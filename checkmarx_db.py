"""Incremental PostgreSQL store for checkmarx_exposure.py (needs psycopg 3; see README.md).

Each run loads only completed scans that are newer than the last one applied for the same
project, branch and engine. Findings are upserted on (project_id, branch, engine,
finding_key). A finding is marked fixed when a newer completed scan of that branch and
engine no longer contains it, and reopened if it comes back. A scan whose engine did not
complete, or whose report had no vulnerability section, never closes findings.
"""
import configparser
import json
from datetime import datetime, timezone
from pathlib import Path

SETTING_KEYS = ('host', 'port', 'dbname', 'user', 'password', 'sslmode', 'sslrootcert', 'connect_timeout')
DEFAULT_SCHEMA = 'checkmarx'
SEVERITY_RANK = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1, 'none': 0}

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS runs (
    run_id bigserial PRIMARY KEY,
    started_at timestamptz NOT NULL,
    finished_at timestamptz,
    summary jsonb
);
CREATE TABLE IF NOT EXISTS projects (
    project_id text PRIMARY KEY,
    name text,
    product text,
    applications text,
    application_ids jsonb,
    tags jsonb,
    groups jsonb,
    main_branch text,
    repo_url text,
    last_seen_at timestamptz,
    last_run_id bigint
);
CREATE TABLE IF NOT EXISTS scans (
    scan_id text PRIMARY KEY,
    project_id text NOT NULL,
    branch text,
    created_at timestamptz,
    status text,
    status_details jsonb,
    engines jsonb,
    tags jsonb,
    last_seen_at timestamptz
);
CREATE TABLE IF NOT EXISTS scan_loads (
    scan_id text NOT NULL,
    engine text NOT NULL,
    project_id text NOT NULL,
    branch text NOT NULL,
    scan_created_at timestamptz,
    vulnerability_section text,
    finding_count integer,
    closed_findings boolean NOT NULL,
    loaded_at timestamptz NOT NULL,
    run_id bigint,
    PRIMARY KEY (scan_id, engine)
);
CREATE TABLE IF NOT EXISTS branch_state (
    project_id text NOT NULL,
    branch text NOT NULL,
    engine text NOT NULL,
    last_scan_id text NOT NULL,
    last_scan_created_at timestamptz,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (project_id, branch, engine)
);
CREATE TABLE IF NOT EXISTS findings (
    project_id text NOT NULL,
    branch text NOT NULL,
    engine text NOT NULL,
    finding_key text NOT NULL,
    vulnerability text,
    aliases text,
    package text,
    versions text,
    ecosystem text,
    purl text,
    image_name text,
    image_tags text,
    severity text,
    cvss_score text,
    triage_state text,
    result_status text,
    recommendation text,
    status text NOT NULL CHECK (status IN ('open', 'fixed')),
    first_seen_at timestamptz,
    first_seen_scan_id text,
    last_seen_at timestamptz,
    last_seen_scan_id text,
    fixed_at timestamptz,
    fixed_in_scan_id text,
    reopened_count integer NOT NULL DEFAULT 0,
    details jsonb,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (project_id, branch, engine, finding_key)
);
CREATE INDEX IF NOT EXISTS findings_status_idx ON findings (status);
CREATE INDEX IF NOT EXISTS findings_vulnerability_idx ON findings (vulnerability);
CREATE TABLE IF NOT EXISTS finding_events (
    event_id bigserial PRIMARY KEY,
    project_id text NOT NULL,
    branch text NOT NULL,
    engine text NOT NULL,
    finding_key text NOT NULL,
    event text NOT NULL CHECK (event IN ('new', 'fixed', 'reopened')),
    scan_id text,
    occurred_at timestamptz,
    run_id bigint
);
CREATE INDEX IF NOT EXISTS finding_events_finding_idx ON finding_events (project_id, branch, engine, finding_key);
CREATE OR REPLACE VIEW open_findings AS
    SELECT p.name AS project, p.product, p.applications, f.*
    FROM findings f LEFT JOIN projects p USING (project_id)
    WHERE f.status = 'open';
"""

FINDING_COLUMNS = ['vulnerability', 'aliases', 'package', 'versions', 'ecosystem', 'purl', 'image_name',
                   'image_tags', 'severity', 'cvss_score', 'triage_state', 'result_status', 'recommendation',
                   'details']


class DatabaseError(Exception):
    """A PostgreSQL problem; the message never includes the password."""


def load_db_settings(path):
    """[postgres] section of an INI file -> (connection keywords, schema). Empty values are left
    out, so libpq's PGPASSWORD / PGHOST environment variables and ~/.pgpass still apply."""
    path = Path(path).expanduser()
    if not path.is_file():
        raise DatabaseError('PostgreSQL config file does not exist')
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with path.open(encoding='utf-8-sig') as f:
            parser.read_file(f)
    except (configparser.Error, OSError, UnicodeError):
        # Parser errors can quote whole lines, including the password.
        raise DatabaseError('Cannot read PostgreSQL config: check file permissions and INI syntax') from None
    if not parser.has_section('postgres'):
        raise DatabaseError('PostgreSQL config must contain a [postgres] section')
    section = parser['postgres']
    unknown = sorted(set(section) - set(SETTING_KEYS) - {'schema'})
    if unknown:
        raise DatabaseError('Unknown PostgreSQL setting(s): ' + ', '.join(unknown))
    settings = {k: section[k].strip() for k in SETTING_KEYS if section.get(k, '').strip()}
    if settings.get('password', '').startswith('YOUR_'):
        raise DatabaseError('Replace the password placeholder in your PostgreSQL config, or leave it empty')
    return settings, section.get('schema', '').strip() or DEFAULT_SCHEMA


def to_time(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def jsonb(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def worst(values):
    values = [v for v in values if v]
    return max(values, key=lambda s: SEVERITY_RANK.get(str(s).lower(), -1), default='unknown')


def joined(values):
    return '; '.join(sorted({str(v) for v in values if v not in (None, '')}))


def finding_key(row, engine):
    """Stable identity of a finding across scans of one project, branch and engine.

    SCA: vulnerability + ecosystem + package name, without the version, so upgrading to a
    version that is still vulnerable keeps the same finding (versions are a column).
    Containers: vulnerability + image name (without tag) + image file + package, so a new
    image tag from the next build does not look like a fix plus a new finding.
    """
    if engine == 'containers':
        parts = [row.get('vulnerability'), row.get('image_name'), row.get('image_file_path'), row.get('package')]
    else:
        package = row.get('package') or 'ref:' + str(row.get('component_ref') or '')
        parts = [row.get('vulnerability'), row.get('ecosystem'), package]
    return '|'.join(str(p or '') for p in parts)


def normalize(rows, engine):
    """Exporter rows of one scan -> {finding_key: record}, merging rows with the same key."""
    groups = {}
    for row in rows:
        groups.setdefault(finding_key(row, engine), []).append(row)
    records = {}
    for key, items in groups.items():
        first = items[0]
        if engine == 'containers':
            purl, ecosystem = '', ''
            versions, triage = joined(r.get('version') for r in items), joined(r.get('state') for r in items)
            result_status = joined(r.get('status') for r in items)
            image_tags = joined(r.get('image_tag') for r in items)
            cvss = joined(r.get('cvss_score') for r in items)
            recommendation = joined(r.get('recommended_version') for r in items)
        else:
            purl, ecosystem = joined(r.get('purl') for r in items), first.get('ecosystem', '')
            versions = joined(r.get('version') for r in items)
            triage, result_status, image_tags, cvss = joined(r.get('analysis_state') for r in items), '', '', ''
            recommendation = joined(r.get('recommendation') for r in items)
        found = [to_time(r.get('first_found_at')) for r in items if r.get('first_found_at')]
        records[key] = {
            'vulnerability': first.get('vulnerability', ''), 'aliases': joined(r.get('aliases') for r in items),
            'package': first.get('package', ''), 'versions': versions, 'ecosystem': ecosystem, 'purl': purl,
            'image_name': first.get('image_name', ''), 'image_tags': image_tags,
            'severity': worst(r.get('severity') for r in items), 'cvss_score': cvss,
            'triage_state': triage, 'result_status': result_status, 'recommendation': recommendation,
            'details': jsonb(items if len(items) > 1 else first),
            'first_found_at': min((t for t in found if t), default=None)}
    return records


class Store:
    def __init__(self, conn, schema):
        self.conn, self.schema = conn, schema
        self.run_id = None
        self.counts = {'scans_loaded': 0, 'new': 0, 'fixed': 0, 'reopened': 0}

    @classmethod
    def connect(cls, config_path):
        settings, schema = load_db_settings(config_path)
        try:
            import psycopg
        except ImportError:
            raise DatabaseError('PostgreSQL loading needs psycopg: pip install -r requirements-db.txt') from None
        settings.setdefault('connect_timeout', '15')
        try:
            conn = psycopg.connect(**settings, application_name='checkmarx_exposure')
        except psycopg.Error as exc:
            raise DatabaseError(describe(exc)) from None
        store = cls(conn, schema)
        store.migrate()
        return store

    def migrate(self):
        from psycopg import sql
        with self.transaction() as cur:
            cur.execute(sql.SQL('CREATE SCHEMA IF NOT EXISTS {}').format(sql.Identifier(self.schema)))
            cur.execute(sql.SQL('SET search_path TO {}').format(sql.Identifier(self.schema)))
            cur.execute(SCHEMA_SQL)
        # search_path set inside a committed transaction stays for the session.

    def transaction(self):
        return _Transaction(self.conn)

    def close(self):
        self.conn.close()

    def start_run(self, now):
        with self.transaction() as cur:
            cur.execute('INSERT INTO runs (started_at) VALUES (%s) RETURNING run_id', (now,))
            self.run_id = cur.fetchone()[0]

    def finish_run(self, summary):
        summary = {**summary, 'database': dict(self.counts)}
        with self.transaction() as cur:
            cur.execute('UPDATE runs SET finished_at = now(), summary = %s::jsonb WHERE run_id = %s',
                        (jsonb(summary), self.run_id))
        return summary['database']

    def save_project(self, project, context):
        with self.transaction() as cur:
            cur.execute("""
                INSERT INTO projects (project_id, name, product, applications, application_ids, tags, groups,
                                      main_branch, repo_url, last_seen_at, last_run_id)
                VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s, now(), %s)
                ON CONFLICT (project_id) DO UPDATE SET name = EXCLUDED.name, product = EXCLUDED.product,
                    applications = EXCLUDED.applications, application_ids = EXCLUDED.application_ids,
                    tags = EXCLUDED.tags, groups = EXCLUDED.groups, main_branch = EXCLUDED.main_branch,
                    repo_url = EXCLUDED.repo_url, last_seen_at = now(), last_run_id = EXCLUDED.last_run_id
                """, (str(project['id']), project.get('name', ''), context.get('product', ''),
                      context.get('applications', ''), context.get('application_ids_json') or '[]',
                      jsonb(project.get('tags')), jsonb(project.get('groups')), project.get('mainBranch', ''),
                      project.get('repoUrl', ''), self.run_id))

    def save_scans(self, project_id, scans):
        if not scans:
            return
        with self.transaction() as cur:
            cur.executemany("""
                INSERT INTO scans (scan_id, project_id, branch, created_at, status, status_details, engines, tags,
                                   last_seen_at)
                VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, now())
                ON CONFLICT (scan_id) DO UPDATE SET status = EXCLUDED.status,
                    status_details = EXCLUDED.status_details, engines = EXCLUDED.engines, tags = EXCLUDED.tags,
                    last_seen_at = now()
                """, [(str(s['id']), str(project_id), s.get('branch') or '(unknown)', to_time(s.get('createdAt')),
                       s.get('status', ''), jsonb(s.get('statusDetails')), jsonb(s.get('engines')),
                       jsonb(s.get('tags'))) for s in scans])

    def branch_state(self, project_id):
        """{(branch, engine): (last_scan_id, last_scan_created_at)} for one project."""
        with self.transaction() as cur:
            cur.execute('SELECT branch, engine, last_scan_id, last_scan_created_at FROM branch_state '
                        'WHERE project_id = %s', (str(project_id),))
            return {(b, e): (sid, created) for b, e, sid, created in cur.fetchall()}

    def pending(self, state, branch, engine, completed):
        """Completed scans (newest first) -> scans to load, oldest first.

        No state yet: only the newest scan, as the baseline (loading the whole history would
        export every retained scan). Otherwise every completed scan newer than the last one
        applied, so fixed dates follow the scan that first showed the fix.
        """
        if not completed:
            return []
        last = state.get((branch, engine))
        if last is None:
            return [completed[0]]
        last_id, last_created = last
        if last_created is None:  # Undated baseline: only move on when the newest scan differs.
            return [] if str(completed[0]['id']) == last_id else [completed[0]]
        newer = [s for s in completed if str(s['id']) != last_id
                 and (to_time(s.get('createdAt')) or last_created) > last_created]
        return list(reversed(newer))

    def load_scan(self, project_id, branch, engine, scan, rows, section):
        """Apply one completed scan's findings in a single transaction.

        Findings are only closed when the scan carried a vulnerability section; otherwise the
        absence of a finding says nothing about whether it was fixed.
        """
        closes = section == 'present'
        created = to_time(scan.get('createdAt')) or datetime.now(timezone.utc)
        scan_id, pid = str(scan['id']), str(project_id)
        records = normalize(rows, engine)
        where = (pid, branch, engine)
        new, reopened, fixed = [], [], []
        with self.transaction() as cur:
            cur.execute('SELECT finding_key, status FROM findings WHERE project_id = %s AND branch = %s '
                        'AND engine = %s FOR UPDATE', where)
            existing = dict(cur.fetchall())
            for key, rec in records.items():
                values = [rec[c] for c in FINDING_COLUMNS]
                if key not in existing:
                    new.append((*where, key, *values, rec['first_found_at'] or created, scan_id, created, scan_id))
                else:
                    if existing[key] == 'fixed':
                        reopened.append(key)
                    cur.execute(f"""
                        UPDATE findings SET {', '.join(f'{c} = %s' for c in FINDING_COLUMNS)},
                            status = 'open', last_seen_at = %s, last_seen_scan_id = %s,
                            fixed_at = NULL, fixed_in_scan_id = NULL,
                            reopened_count = reopened_count + CASE WHEN status = 'fixed' THEN 1 ELSE 0 END,
                            updated_at = now()
                        WHERE project_id = %s AND branch = %s AND engine = %s AND finding_key = %s
                        """, (*values, created, scan_id, *where, key))
            if new:
                cur.executemany(f"""
                    INSERT INTO findings (project_id, branch, engine, finding_key, {', '.join(FINDING_COLUMNS)},
                        status, first_seen_at, first_seen_scan_id, last_seen_at, last_seen_scan_id, updated_at)
                    VALUES ({', '.join(['%s'] * (4 + len(FINDING_COLUMNS)))}, 'open', %s, %s, %s, %s, now())
                    """, new)
            if closes:
                fixed = [k for k, status in existing.items() if status == 'open' and k not in records]
                if fixed:
                    cur.executemany("""
                        UPDATE findings SET status = 'fixed', fixed_at = %s, fixed_in_scan_id = %s, updated_at = now()
                        WHERE project_id = %s AND branch = %s AND engine = %s AND finding_key = %s
                        """, [(created, scan_id, *where, k) for k in fixed])
            events = ([(*where, row[3], 'new') for row in new] + [(*where, k, 'reopened') for k in reopened]
                      + [(*where, k, 'fixed') for k in fixed])
            if events:
                cur.executemany("""
                    INSERT INTO finding_events (project_id, branch, engine, finding_key, event, scan_id,
                                                occurred_at, run_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """, [(*e, scan_id, created, self.run_id) for e in events])
            cur.execute("""
                INSERT INTO scan_loads (scan_id, engine, project_id, branch, scan_created_at, vulnerability_section,
                                        finding_count, closed_findings, loaded_at, run_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now(), %s)
                ON CONFLICT (scan_id, engine) DO UPDATE SET vulnerability_section = EXCLUDED.vulnerability_section,
                    finding_count = EXCLUDED.finding_count, closed_findings = EXCLUDED.closed_findings,
                    loaded_at = now(), run_id = EXCLUDED.run_id
                """, (scan_id, engine, pid, branch, created, section, len(records), closes, self.run_id))
            cur.execute("""
                INSERT INTO branch_state (project_id, branch, engine, last_scan_id, last_scan_created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, now())
                ON CONFLICT (project_id, branch, engine) DO UPDATE SET last_scan_id = EXCLUDED.last_scan_id,
                    last_scan_created_at = EXCLUDED.last_scan_created_at, updated_at = now()
                WHERE branch_state.last_scan_created_at IS NULL
                   OR branch_state.last_scan_created_at <= EXCLUDED.last_scan_created_at
                """, (*where, scan_id, created))
        self.counts['scans_loaded'] += 1
        self.counts['new'] += len(new)
        self.counts['reopened'] += len(reopened)
        self.counts['fixed'] += len(fixed)
        return {'new': len(new), 'reopened': len(reopened), 'fixed': len(fixed)}


def describe(exc):
    """First line of a psycopg error (server messages do not contain the password)."""
    text = str(exc).strip().splitlines()
    return 'PostgreSQL: ' + (text[0][:300] if text else type(exc).__name__)


class _Transaction:
    """Commit on success, roll back on error, and turn psycopg errors into DatabaseError."""

    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        self.cur = self.conn.cursor()
        return self.cur

    def __exit__(self, exc_type, exc, tb):
        import psycopg
        self.cur.close()
        if exc_type is None:
            try:
                self.conn.commit()
            except psycopg.Error as error:
                self.conn.rollback()
                raise DatabaseError(describe(error)) from None
            return False
        self.conn.rollback()
        if isinstance(exc, psycopg.Error):
            raise DatabaseError(describe(exc)) from None
        return False
