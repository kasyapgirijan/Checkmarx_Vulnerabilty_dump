#!/usr/bin/env python3
"""Named-vulnerability exposure report (Log4Shell, Spring4Shell, React2Shell, ...).

Reads the package inventory and findings that checkmarx_exposure.py collected (from
PostgreSQL or from an export folder) and writes a CSV of every project, branch and image
that uses a watched package, with the version and whether that version is affected.

Matching is on package name and version range from report.ini, not on Checkmarx's CVE
list, so a vulnerable version shows up even when Checkmarx has not (yet) reported the CVE
for it; the checkmarx_cves column then says NA. See README.md, "Exposure report".
"""
import argparse
import configparser
import csv
import fnmatch
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import checkmarx_exposure as cx

RESERVED = {'report', 'postgres', 'checkmarx'}
VERDICT_ORDER = {'affected': 0, 'reported_by_checkmarx': 1, 'version_unknown': 2, 'not_affected': 3}
PRE_RELEASE = ('alpha', 'a', 'beta', 'b', 'rc', 'cr', 'm', 'milestone', 'pre', 'preview', 'canary', 'dev',
               'snapshot', 'ea')
RELEASE = ('', 'final', 'release', 'ga')
REPORT_FIELDS = [
    'vulnerability_name', 'verdict', 'project', 'product', 'applications', 'branch', 'scan_type',
    'image_name', 'image_tag', 'ecosystem', 'package', 'version', 'affected_ranges', 'fixed_versions',
    'dependency_type', 'introduced_by', 'target_cves', 'checkmarx_reported_target_cve', 'checkmarx_cves',
    'severity', 'triage_state', 'purl', 'project_id', 'scan_id', 'scan_date', 'rule', 'source']
SUMMARY_FIELDS = ['vulnerability_name', 'project', 'product', 'applications', 'project_id', 'affected_rows',
                  'version_unknown_rows', 'not_affected_rows', 'branches_affected', 'affected_packages',
                  'checkmarx_reported_target_cve']


class ReportError(Exception):
    pass


# ---------------------------------------------------------------- versions

def version_key(value):
    """Sortable key for npm/semver, Maven, PyPI and OS package versions, or None.

    Release numbers compare numerically; a pre-release qualifier (beta, rc, -canary.3,
    SNAPSHOT, ...) sorts before the release and anything else (sp1, -r0, +deb11u3, a
    letter suffix like 1.1.1n) after it. Epochs (1:) and build metadata (+...) are ignored,
    except that OS revisions such as -r0 or -0+deb11u3 still sort after the plain version.
    """
    text = str(value or '').strip().lower()
    text = re.sub(r'^\d+:', '', text)  # Debian/RPM epoch.
    text = text.lstrip('v')
    if re.fullmatch(r'[\d.]+(-[0-9a-z.]+)?\+[0-9a-z.]+', text) and not re.search(r'\+(deb|ubuntu|b\d)', text):
        text = text.split('+', 1)[0]  # Semver build metadata; Debian revisions (+deb11u3) are kept.
    match = re.match(r'(\d+(?:\.\d+)*)(.*)$', text)
    if not match:
        return None
    numbers = [int(n) for n in match.group(1).split('.')]
    numbers += [0] * (6 - len(numbers))
    rest = match.group(2).lstrip('.-_')
    word = re.match(r'[a-z]*', rest).group(0)
    after = rest[len(word):]
    if word in RELEASE and not after.strip('.-_'):
        rank = 1
    elif word in PRE_RELEASE and (len(word) > 1 or after[:1].isdigit()):
        rank = 0  # 1.0a1, 2.0-M1, -rc.1; a lone letter (OpenSSL 1.1.1a, 1.1.1m) is a later release.
    else:
        rank = 2
    tokens = () if rank == 1 else tuple((0, int(t)) if t.isdigit() else (1, t) for t in re.findall(r'\d+|[a-z]+', rest))
    return tuple(numbers[:6]), rank, tokens


def parse_ranges(text, label):
    """'>=2.0,<2.17.1 ; ==1.2.3' -> [[(op, key, raw), ...], ...]; clauses are ORed, conditions ANDed."""
    clauses = []
    for clause in re.split(r'[;|]', text or ''):
        conditions = []
        for part in clause.split(','):
            part = part.strip()
            if not part:
                continue
            match = re.match(r'(>=|<=|==|!=|>|<|=)?\s*(.+)$', part)
            op, raw = match.group(1) or '==', match.group(2).strip()
            key = version_key(raw)
            if key is None:
                raise ReportError(f'[{label}] cannot read version "{raw}" in affected')
            conditions.append(('==' if op == '=' else op, key, raw))
        if conditions:
            clauses.append(conditions)
    if not clauses:
        raise ReportError(f'[{label}] needs affected = version ranges, for example >=2.0,<2.17.1')
    return clauses


def in_ranges(version, clauses):
    """True, False, or None when the version cannot be read."""
    key = version_key(version)
    if key is None:
        return None
    checks = {'>=': lambda a, b: a >= b, '<=': lambda a, b: a <= b, '>': lambda a, b: a > b,
              '<': lambda a, b: a < b, '==': lambda a, b: a == b, '!=': lambda a, b: a != b}
    return any(all(checks[op](key, bound) for op, bound, _ in clause) for clause in clauses)


# ---------------------------------------------------------------- config

def split_list(text):
    return [x.strip() for x in re.split(r'[,\n]', text or '') if x.strip()]


def normalize_name(name):
    return str(name or '').strip().lower().replace(':', '/')


class Rule:
    """One [Name] or [Name/label] section: packages, an ecosystem, and affected ranges."""

    def __init__(self, section_name, section):
        self.section = section_name
        self.name = section_name.split('/', 1)[0].strip()
        self.cves = {c.upper() for c in split_list(section.get('cves'))}
        self.ecosystem = section.get('ecosystem', '').strip().lower()
        self.patterns = [normalize_name(p) for p in split_list(section.get('packages'))]
        if not self.patterns:
            raise ReportError(f'[{section_name}] needs packages = names (globs like *log4j-core allowed)')
        self.affected_text = ' ; '.join(c.strip() for c in re.split(r'[;|]', section.get('affected', '')) if c.strip())
        self.ranges = parse_ranges(section.get('affected'), section_name)
        self.fixed = section.get('fixed', '').strip()
        self.containers = section.get('containers', 'true').strip().lower() not in ('false', 'no', '0', 'off')

    def matches_package(self, package, ecosystem, scan_type):
        name = normalize_name(package)
        if scan_type == 'sca':
            if self.ecosystem and str(ecosystem or '').lower() != self.ecosystem:
                return False
            return any(fnmatch.fnmatchcase(name, p) for p in self.patterns)
        if not self.containers:
            return False
        # Container results name packages inconsistently (log4j-core, group:artifact, ...),
        # so the last path segment is compared too.
        short = name.rsplit('/', 1)[-1]
        return any(fnmatch.fnmatchcase(name, p) or fnmatch.fnmatchcase(short, p.rsplit('/', 1)[-1])
                   for p in self.patterns)


def load_report_config(path, only=None):
    path = Path(path).expanduser()
    if not path.is_file():
        raise ReportError(f'Report config {path} does not exist')
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str.lower
    try:
        with path.open(encoding='utf-8-sig') as f:
            parser.read_file(f)
    except (configparser.Error, OSError, UnicodeError):
        raise ReportError('Cannot read report config: check file permissions and INI syntax') from None
    report = dict(parser['report']) if parser.has_section('report') else {}
    rules = [Rule(name, parser[name]) for name in parser.sections() if name.lower() not in RESERVED]
    if only:
        wanted = {o.lower() for o in only}
        rules = [r for r in rules if r.name.lower() in wanted]
    if not rules:
        raise ReportError('No vulnerability sections to report on' + (' (check --only)' if only else ''))
    return report, rules


# ---------------------------------------------------------------- sources

def unescape(value):
    """Undo the CSV formula guard (a leading ') that checkmarx_exposure.py adds for Excel."""
    if isinstance(value, str) and value[:1] == "'" and value[1:2] in ('=', '+', '-', '@', '\t', '\r'):
        return value[1:]
    return value


def read_csv(path):
    if not path.exists():
        return []
    with path.open(encoding='utf-8-sig', newline='') as f:
        return [{k: unescape(v) for k, v in row.items()} for row in csv.DictReader(f)]


def split_versions(text):
    return [v.strip() for v in str(text or '').split(';') if v.strip()] or ['']


def from_folder(folder):
    """Inventory and findings from a checkmarx_exposure.py output folder."""
    folder = Path(folder).expanduser()
    if not (folder / 'packages.csv').exists() and not (folder / 'container_findings.csv').exists():
        raise ReportError(f'{folder} has no packages.csv or container_findings.csv; '
                          'point source at a checkmarx_exposure.py output folder')
    inventory = [{**r, 'scan_type': 'sca'} for r in read_csv(folder / 'packages.csv')]
    findings = [{**r, 'scan_type': 'sca'} for r in read_csv(folder / 'findings.csv')]
    for r in read_csv(folder / 'container_findings.csv'):
        row = {**r, 'scan_type': 'containers', 'ecosystem': ''}
        inventory.append(row)
        findings.append({**row, 'analysis_state': r.get('state', '')})
    return inventory, findings, f'folder:{folder}'


def from_database(db_config):
    """Current inventory (SCA) and open findings (SCA and containers) from PostgreSQL."""
    import checkmarx_db
    settings, schema = checkmarx_db.load_db_settings(db_config)
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError:
        raise ReportError('Reading from PostgreSQL needs psycopg: pip install -r requirements-db.txt') from None
    try:
        with psycopg.connect(**settings, row_factory=dict_row, application_name='exposure_report') as conn:
            conn.execute(psycopg.sql.SQL('SET search_path TO {}').format(psycopg.sql.Identifier(schema)))
            inventory = [{**r, 'scan_type': 'sca'} for r in conn.execute(
                'SELECT project, product, applications, project_id, branch, ecosystem, package, version, purl, '
                'dependency_type, introduced_by, last_seen_scan_id AS scan_id, last_seen_at AS scan_date '
                'FROM vw_current_packages')]
            findings = []
            for r in conn.execute(
                    'SELECT project, product, applications, project_id, branch, engine, vulnerability, aliases, '
                    'package, versions, ecosystem, purl, image_name, image_tags, severity, triage_state, '
                    'last_seen_scan_id AS scan_id, last_seen_at AS scan_date FROM vw_open_findings'):
                for version in split_versions(r['versions']):
                    row = {**r, 'version': version, 'scan_type': r['engine'], 'analysis_state': r['triage_state'],
                           'image_tag': r['image_tags']}
                    findings.append(row)
                    if r['engine'] == 'containers':
                        inventory.append(row)  # Container results only list packages with findings.
    except psycopg.Error as exc:
        raise ReportError(checkmarx_db.describe(exc)) from None
    return inventory, findings, f'postgres:{schema}'


# ---------------------------------------------------------------- report

def location(row):
    return (str(row.get('project_id')), row.get('branch') or '', row.get('scan_type'), row.get('image_name') or '',
            normalize_name(row.get('package')), str(row.get('version') or ''))


def ids_of(row):
    return {x.strip().upper() for x in [row.get('vulnerability', '')] + str(row.get('aliases') or '').split(';')
            if x and x.strip()}


def build_report(inventory, findings, rules, source):
    by_location = {}
    for f in findings:
        by_location.setdefault(location(f), []).append(f)
    rows, seen = [], set()

    def emit(rule, item, verdict):
        found = by_location.get(location(item), [])
        cves = sorted({c for f in found for c in ids_of(f)})
        target = sorted(rule.cves & set(cves))
        severities = [str(f.get('severity') or '').lower() for f in found]
        rows.append({
            'vulnerability_name': rule.name, 'verdict': verdict, 'project': item.get('project', ''),
            'product': item.get('product', ''), 'applications': item.get('applications', ''),
            'branch': item.get('branch', ''), 'scan_type': item.get('scan_type', ''),
            'image_name': item.get('image_name', '') or '', 'image_tag': item.get('image_tag', '') or '',
            'ecosystem': item.get('ecosystem', '') or '', 'package': item.get('package', ''),
            'version': item.get('version', ''), 'affected_ranges': rule.affected_text, 'fixed_versions': rule.fixed,
            'dependency_type': item.get('dependency_type', '') or '', 'introduced_by': item.get('introduced_by', '') or '',
            'target_cves': '; '.join(sorted(rule.cves)) or 'NA',
            'checkmarx_reported_target_cve': ('yes' if target else 'no') if rule.cves else 'NA',
            'checkmarx_cves': '; '.join(cves) or 'NA',
            'severity': max(severities, key=lambda s: cx.SEVERITY_RANK.get(s, -1), default='') or 'NA',
            'triage_state': '; '.join(sorted({str(f.get('analysis_state') or '') for f in found} - {''})) or 'NA',
            'purl': item.get('purl', '') or '', 'project_id': item.get('project_id', ''),
            'scan_id': item.get('scan_id', ''), 'scan_date': str(item.get('scan_date', '') or ''),
            'rule': rule.section, 'source': source})
        seen.add((rule.name, location(item)))

    for rule in rules:
        for item in inventory:
            if (rule.name, location(item)) in seen:
                continue
            if rule.matches_package(item.get('package'), item.get('ecosystem'), item.get('scan_type')):
                hit = in_ranges(item.get('version'), rule.ranges)
                emit(rule, item, 'version_unknown' if hit is None else 'affected' if hit else 'not_affected')
        # Anything Checkmarx reports under a target CVE that no package rule caught.
        for f in findings:
            if rule.cves & ids_of(f) and (rule.name, location(f)) not in seen:
                emit(rule, f, 'reported_by_checkmarx')
    rows.sort(key=lambda r: (r['vulnerability_name'], VERDICT_ORDER.get(r['verdict'], 9), r['project'],
                             r['branch'], r['package'], r['version']))
    return rows


def summarize(rows):
    groups = {}
    for r in rows:
        g = groups.setdefault((r['vulnerability_name'], r['project_id']), {
            'vulnerability_name': r['vulnerability_name'], 'project': r['project'], 'product': r['product'],
            'applications': r['applications'], 'project_id': r['project_id'], 'affected_rows': 0,
            'version_unknown_rows': 0, 'not_affected_rows': 0, 'branches': set(), 'packages': set(), 'cx': set()})
        if r['verdict'] in ('affected', 'reported_by_checkmarx'):
            g['affected_rows'] += 1
            g['branches'].add(r['branch'])
            g['packages'].add(f"{r['package']}@{r['version']}")
        elif r['verdict'] == 'version_unknown':
            g['version_unknown_rows'] += 1
        else:
            g['not_affected_rows'] += 1
        g['cx'].add(r['checkmarx_reported_target_cve'])
    out = []
    for g in groups.values():
        cx_flag = 'yes' if 'yes' in g['cx'] else 'no' if 'no' in g['cx'] else 'NA'
        out.append({**{k: g[k] for k in ('vulnerability_name', 'project', 'product', 'applications', 'project_id',
                                         'affected_rows', 'version_unknown_rows', 'not_affected_rows')},
                    'branches_affected': '; '.join(sorted(g['branches'])),
                    'affected_packages': '; '.join(sorted(g['packages'])), 'checkmarx_reported_target_cve': cx_flag})
    out.sort(key=lambda g: (g['vulnerability_name'], -g['affected_rows'], g['project']))
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    p.add_argument('--config', type=Path, default=Path('report.ini'), help='Report INI (default report.ini)')
    p.add_argument('--source', help='Override [report] source: db, or a checkmarx_exposure.py output folder')
    p.add_argument('--out', type=Path, help='Override [report] output CSV path')
    p.add_argument('--only', action='append', metavar='NAME', help='Only this vulnerability section; repeatable')
    args = p.parse_args(argv)

    report, rules = load_report_config(args.config, args.only)
    source = (args.source or report.get('source', 'db')).strip()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = args.out or Path(report.get('output', '').strip() or f'vulnerability-report-{stamp}.csv')
    if source.lower() in ('db', 'postgres', 'database'):
        # [postgres] in this file, or in the file named by db_config (for example config.ini).
        inventory, findings, label = from_database(Path(report.get('db_config', '').strip() or args.config))
    else:
        inventory, findings, label = from_folder(source)
    rows = build_report(inventory, findings, rules, label)
    escape = report.get('raw_csv', 'false').strip().lower() not in ('true', 'yes', '1', 'on')
    out.parent.mkdir(parents=True, exist_ok=True)
    cx.write_csv(out, rows, REPORT_FIELDS, escape)
    summary_path = out.with_name(out.stem + '-summary.csv')
    cx.write_csv(summary_path, summarize(rows), SUMMARY_FIELDS, escape)
    for rule_name in dict.fromkeys(r.name for r in rules):
        mine = [r for r in rows if r['vulnerability_name'] == rule_name]
        hit = {r['project_id'] for r in mine if r['verdict'] in ('affected', 'reported_by_checkmarx')}
        unknown = sum(r['verdict'] == 'version_unknown' for r in mine)
        silent = sum(r['verdict'] == 'affected' and r['checkmarx_reported_target_cve'] == 'no' for r in mine)
        print(f'{rule_name}: {len(hit)} project(s) affected, {len(mine)} row(s)'
              + (f', {silent} affected without the CVE in Checkmarx' if silent else '')
              + (f', {unknown} with unreadable versions' if unknown else ''))
    print(f'Saved {out} and {summary_path} (source: {label}).')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except ReportError as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        sys.exit(1)
    except Exception as exc:  # checkmarx_db.DatabaseError and file errors, without tracebacks
        print('ERROR: ' + cx.safe_error(exc), file=sys.stderr)
        sys.exit(1)
