"""Tests for the PostgreSQL store.

Unit tests always run. The end-to-end tests need a disposable PostgreSQL database; set
CX_TEST_PG to libpq keywords, for example:

    CX_TEST_PG="host=localhost port=5432 user=postgres dbname=postgres" python -m unittest test_checkmarx_db.py

Each test creates its own schema and drops it afterwards.
"""
import copy
import csv
import json
import os
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import checkmarx_db as db
import checkmarx_exposure as cx

PG = os.getenv('CX_TEST_PG', '')


def bom(*refs):
    """CycloneDX with npm @scope/thing and pypi django; CVE-A affects the given refs."""
    doc = {'bomFormat': 'CycloneDX', 'components': [
        {'bom-ref': 'npm-a', 'group': '@scope', 'name': 'thing', 'version': '1.2.3', 'purl': 'pkg:npm/%40scope/thing@1.2.3'},
        {'bom-ref': 'py-b', 'name': 'django', 'version': '1.0', 'purl': 'pkg:pypi/django@1.0'}],
        'vulnerabilities': []}
    if refs:
        doc['vulnerabilities'].append({'id': 'CVE-A', 'affects': [{'ref': r} for r in refs],
                                       'ratings': [{'severity': 'high'}], 'analysis': {'state': 'not_affected'}})
    return doc


def scan(i, day, status='Completed', engine='sca', branch='main'):
    return {'id': i, 'branch': branch, 'createdAt': f'2026-10-{day:02d}T00:00:00Z',
            'statusDetails': [{'name': engine, 'status': status}]}


class UnitTests(unittest.TestCase):
    def test_settings_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'pg.ini'
            path.write_text('[postgres]\nhost = db\nport = 5432\npassword =\nsslmode = require\n')
            settings, schema = db.load_db_settings(path)
            self.assertEqual(settings, {'host': 'db', 'port': '5432', 'sslmode': 'require'})  # Empty left out.
            self.assertEqual(schema, 'checkmarx')
            path.write_text('[postgres]\npassword = SECRET\nSECRET\n')
            with self.assertRaises(db.DatabaseError) as result:
                db.load_db_settings(path)
            self.assertNotIn('SECRET', str(result.exception))
            path.write_text('[postgres]\nhots = typo\n')
            with self.assertRaisesRegex(db.DatabaseError, 'hots'):
                db.load_db_settings(path)
            path.write_text('[postgres]\ndatabase = jira_style\n')  # Jira_extract's key name.
            self.assertEqual(db.load_db_settings(path)[0], {'dbname': 'jira_style'})
            path.write_text('[postgres]\ndatabase = a\ndbname = b\n')
            with self.assertRaisesRegex(db.DatabaseError, 'not both'):
                db.load_db_settings(path)
            path.write_text('[checkmarx]\nbase_url = https://x\n')
            with self.assertRaisesRegex(db.DatabaseError, 'no \\[postgres\\] section'):
                db.load_db_settings(path)
            with self.assertRaisesRegex(db.DatabaseError, 'does not exist'):
                db.load_db_settings(Path(tmp) / 'missing.ini')

    def test_finding_keys_ignore_versions_and_image_tags(self):
        sca = [{'vulnerability': 'CVE-1', 'ecosystem': 'npm', 'package': 'a', 'version': '1.0', 'severity': 'low'},
               {'vulnerability': 'CVE-1', 'ecosystem': 'npm', 'package': 'a', 'version': '2.0', 'severity': 'high'}]
        records = db.normalize(sca, 'sca')
        self.assertEqual(list(records), ['CVE-1|npm|a'])
        self.assertEqual((records['CVE-1|npm|a']['versions'], records['CVE-1|npm|a']['severity']), ('1.0; 2.0', 'high'))
        container = {'vulnerability': 'CVE-2', 'image_name': 'nginx', 'image_file_path': 'Dockerfile',
                     'package': 'zlib', 'image_tag': '1.0', 'triage_state': 'NOT_EXPLOITABLE'}
        self.assertEqual(db.finding_key(container, 'containers'),
                         db.finding_key({**container, 'image_tag': '2.0'}, 'containers'))
        self.assertEqual(db.normalize([container], 'containers')['CVE-2|nginx|Dockerfile|zlib']['triage_state'],
                         'NOT_EXPLOITABLE')

    def test_package_inventory_merges_duplicates(self):
        rows = [{'ecosystem': 'npm', 'package': 'a', 'version': '1', 'dependency_type': 'transitive',
                 'introduced_by': 'b@1', 'scope': 'required'},
                {'ecosystem': 'npm', 'package': 'a', 'version': '1', 'dependency_type': 'direct', 'scope': 'optional'}]
        record = db.package_inventory(rows)['npm|a|1']
        self.assertEqual((record['dependency_type'], record['introduced_by'], record['scope']),
                         ('direct', '', 'optional; required'))

    def test_pending_scans(self):
        store = db.Store(None, 'x')
        completed = cx.newest_first([scan('s1', 1), scan('s2', 2), scan('s3', 3)])
        self.assertEqual([s['id'] for s in store.pending({}, 'main', 'sca', completed)], ['s3'])  # Baseline.
        state = {('main', 'sca'): ('s1', db.to_time('2026-10-01T00:00:00Z'))}
        self.assertEqual([s['id'] for s in store.pending(state, 'main', 'sca', completed)], ['s2', 's3'])
        state = {('main', 'sca'): ('s3', db.to_time('2026-10-03T00:00:00Z'))}
        self.assertEqual(store.pending(state, 'main', 'sca', completed), [])

    def test_db_arguments(self):
        with patch('sys.stderr'):
            for bad in (['--db', 'x.ini', '--dump-all'], ['--no-files'], ['--db', 'x.ini', '--no-files', '--out', 'o']):
                with self.assertRaises(SystemExit):
                    cx.parse_args(bad)
        self.assertEqual(cx.parse_args([]).out, 'checkmarx-output')
        self.assertTrue(cx.parse_args(['--db', 'x.ini']).out.startswith('checkmarx-output/20'))
        self.assertEqual(cx.parse_args(['--db']).db, '')  # Alone: [postgres] in the main config.
        self.assertIsNone(cx.parse_args([]).db)
        with patch('sys.stderr'), self.assertRaises(SystemExit):
            cx.parse_args(['--full'])


@unittest.skipUnless(PG, 'set CX_TEST_PG to run the PostgreSQL tests')
class PostgresTests(unittest.TestCase):
    def setUp(self):
        import psycopg
        self.psycopg = psycopg
        self.tmp = tempfile.TemporaryDirectory()
        self.schema = 'cx_test_' + uuid.uuid4().hex[:10]
        keywords = dict(part.split('=', 1) for part in PG.split())
        self.ini = Path(self.tmp.name) / 'postgres.ini'
        self.ini.write_text('[postgres]\n' + ''.join(f'{k} = {v}\n' for k, v in keywords.items())
                            + f'schema = {self.schema}\n')
        self.conn = psycopg.connect(PG, autocommit=True)
        self.scans, self.boms, self.results, self.runs = [], {}, {}, 0
        patcher = patch('checkmarx_exposure.Client')
        self.client = patcher.start().return_value
        self.addCleanup(patcher.stop)
        self.client.verify = True
        self.client.pages.side_effect = lambda path, key, **kw: iter(
            {'projects': [{'id': 'p', 'name': 'Project'}], 'applications': [], 'scans': list(self.scans)}[key])
        self.client.export.side_effect = lambda sid, fmt, timeout: json.dumps(self.boms[sid]).encode()
        self.client.results.side_effect = lambda sid, kind: copy.deepcopy(self.results.get(sid, []))

    def tearDown(self):
        self.conn.execute(f'DROP SCHEMA IF EXISTS {self.schema} CASCADE')
        self.conn.close()
        self.tmp.cleanup()

    def run_export(self, *extra):
        self.runs += 1
        out = Path(self.tmp.name) / f'out{self.runs}'
        with patch('sys.stdout'), patch('sys.stderr'):
            return cx.main(['--db', str(self.ini), '--out', str(out), '--stale-days', '3650', '--keep-states', 'all', *extra]), out

    def findings(self, engine='sca'):
        rows = self.conn.execute(
            f'SELECT finding_key, status, first_seen_scan_id, last_seen_scan_id, fixed_in_scan_id, '
            f'reopened_count, triage_state FROM {self.schema}.findings WHERE engine = %s ORDER BY 1', (engine,))
        return {r[0]: r[1:] for r in rows}

    def events(self):
        return [tuple(r) for r in self.conn.execute(
            f'SELECT scan_id, event, finding_key FROM {self.schema}.finding_events ORDER BY event_id')]

    def test_incremental_fixed_and_reopened(self):
        npm, pypi = 'CVE-A|npm|@scope/thing', 'CVE-A|pypi|django'
        # Run 1: baseline from the newest completed scan only.
        self.scans = [scan('s0', 1), scan('s1', 2)]
        self.boms = {'s1': bom('npm-a', 'py-b')}
        code, out = self.run_export()
        self.assertEqual(code, 0)
        self.assertEqual(self.client.export.call_count, 1)
        self.assertEqual(self.findings(), {npm: ('open', 's1', 's1', None, 0, 'NOT_EXPLOITABLE'),
                                           pypi: ('open', 's1', 's1', None, 0, 'NOT_EXPLOITABLE')})
        self.assertTrue((out / 'findings.csv').exists())  # CSV export still happens.
        self.assertEqual(json.loads((out / 'run.json').read_text())['database']['new'], 2)

        # Run 2: nothing new, so nothing is exported and the run is clean.
        code, out = self.run_export()
        self.assertEqual((code, self.client.export.call_count), (0, 1))
        with (out / 'coverage.csv').open(encoding='utf-8-sig') as f:
            self.assertEqual([r['status'] for r in csv.DictReader(f)], ['already_loaded'])

        # Run 3: two new scans are applied oldest first: django fixed in s2, back in s3.
        self.scans += [scan('s2', 3), scan('s3', 4)]
        self.boms.update(s2=bom('npm-a'), s3=bom('npm-a', 'py-b'))
        code, _ = self.run_export()
        self.assertEqual(code, 0)
        self.assertEqual([c.args[0] for c in self.client.export.call_args_list[1:]], ['s2', 's3'])
        self.assertEqual(self.findings()[pypi], ('open', 's1', 's3', None, 1, 'NOT_EXPLOITABLE'))
        self.assertEqual(self.events()[2:], [('s2', 'fixed', pypi), ('s3', 'reopened', pypi)])

        # Run 4: npm fixed in s4; a newer scan whose SCA failed (s5) never closes anything.
        self.scans += [scan('s4', 5), scan('s5', 6, 'Failed')]
        self.boms['s4'] = bom('py-b')
        code, _ = self.run_export()
        self.assertEqual(code, 2)  # The failed newer scan is flagged for review.
        found = self.findings()
        self.assertEqual(found[npm][:4], ('fixed', 's1', 's3', 's4'))
        self.assertEqual(found[pypi][0], 'open')
        fixed_at = self.conn.execute(f'SELECT fixed_at FROM {self.schema}.findings WHERE finding_key = %s',
                                     (npm,)).fetchone()[0]
        self.assertEqual(fixed_at, datetime(2026, 10, 5, tzinfo=timezone.utc))
        open_rows = self.conn.execute(f'SELECT project, finding_key FROM {self.schema}.vw_open_findings').fetchall()
        self.assertEqual(open_rows, [('Project', pypi)])

    def test_package_inventory(self):
        def sbom(log4j_version):
            return {'bomFormat': 'CycloneDX', 'metadata': {'component': {'bom-ref': 'app'}},
                    'components': [{'bom-ref': 'spring', 'group': 'org.springframework', 'name': 'spring-core',
                                    'version': '6.0', 'purl': 'pkg:maven/org.springframework/spring-core@6.0'},
                                   {'bom-ref': 'log4j', 'group': 'org.apache.logging.log4j', 'name': 'log4j-core',
                                    'version': log4j_version,
                                    'purl': f'pkg:maven/org.apache.logging.log4j/log4j-core@{log4j_version}'}],
                    'dependencies': [{'ref': 'app', 'dependsOn': ['spring']}, {'ref': 'spring', 'dependsOn': ['log4j']}],
                    'vulnerabilities': []}
        self.scans = [scan('s1', 1)]
        self.boms = {'s1': sbom('2.14.1')}
        self.run_export()
        self.scans.append(scan('s2', 2))
        self.boms['s2'] = sbom('2.17.1')  # Upgraded: the old version is removed, the new one present.
        code, _ = self.run_export()
        self.assertEqual(code, 0)
        rows = self.conn.execute(
            f'SELECT package, version, dependency_type, introduced_by, status, first_seen_scan_id, removed_in_scan_id '
            f'FROM {self.schema}.packages ORDER BY package, version').fetchall()
        self.assertEqual(rows, [
            ('org.apache.logging.log4j/log4j-core', '2.14.1', 'transitive', 'org.springframework/spring-core@6.0',
             'removed', 's1', 's2'),
            ('org.apache.logging.log4j/log4j-core', '2.17.1', 'transitive', 'org.springframework/spring-core@6.0',
             'present', 's2', None),
            ('org.springframework/spring-core', '6.0', 'direct', '', 'present', 's1', None)])
        java = self.conn.execute(f"SELECT DISTINCT project FROM {self.schema}.vw_current_packages "
                                 f"WHERE ecosystem = 'maven'").fetchall()
        self.assertEqual(java, [('Project',)])

    def test_postgres_section_in_main_config(self):
        keywords = dict(part.split('=', 1) for part in PG.split())
        main_config = Path(self.tmp.name) / 'config.ini'
        main_config.write_text('[checkmarx]\nbase_url = https://x\n\n[postgres]\n'
                               + ''.join(f'{"database" if k == "dbname" else k} = {v}\n' for k, v in keywords.items())
                               + f'schema = {self.schema}\n')
        self.scans, self.boms = [scan('s1', 1)], {'s1': bom('npm-a')}
        with patch('sys.stdout'), patch('sys.stderr'):
            code = cx.main(['--db', '--config', str(main_config), '--no-files', '--stale-days', '3650', '--keep-states', 'all'])
        self.assertEqual(code, 0)
        self.assertEqual(len(self.findings()), 1)

    def test_run_status_full_reload_and_lock(self):
        self.scans, self.boms = [scan('s1', 1)], {'s1': bom('npm-a')}
        self.run_export()
        self.run_export('--full')  # Reloads s1 although it is already loaded.
        self.assertEqual(self.client.export.call_count, 2)
        self.assertEqual(self.findings()['CVE-A|npm|@scope/thing'][0], 'open')
        # A database failure mid-run marks the run FAILED with the reason.
        with patch.object(db.Store, 'save_scans', side_effect=db.DatabaseError('PostgreSQL: boom')):
            with self.assertRaisesRegex(db.DatabaseError, 'boom'):
                self.run_export()
        runs = self.conn.execute(f'SELECT status, error FROM {self.schema}.runs ORDER BY run_id').fetchall()
        self.assertEqual(runs, [('SUCCESS', None), ('SUCCESS', None), ('FAILED', 'PostgreSQL: boom')])
        # A second load into the same schema while one holds the lock is refused.
        holder = db.Store.connect(self.ini)
        try:
            with self.assertRaisesRegex(db.DatabaseError, 'already running'):
                db.Store.connect(self.ini)
        finally:
            holder.close()
        db.Store.connect(self.ini).close()  # Released when the first connection closes.

    def test_upgrades_a_database_from_the_first_release(self):
        # Schema as PR #6 created it: old index and view names, runs without status/error.
        old = db.SCHEMA_SQL.replace('ALTER INDEX IF EXISTS', '-- ').replace('idx_findings_status', 'findings_status_idx')
        self.conn.execute(f'CREATE SCHEMA {self.schema}')
        self.conn.execute(f'SET search_path TO {self.schema}')
        self.conn.execute(old)
        self.conn.execute('ALTER TABLE runs DROP COLUMN IF EXISTS status')
        self.conn.execute("CREATE VIEW open_findings AS SELECT * FROM findings WHERE status = 'open'")
        # Data as earlier releases stored it: branch_state table, events keyed by four columns, no category.
        self.conn.execute('CREATE TABLE branch_state (project_id text NOT NULL, branch text NOT NULL, '
                          'engine text NOT NULL, last_scan_id text NOT NULL, last_scan_created_at timestamptz, '
                          'updated_at timestamptz NOT NULL, PRIMARY KEY (project_id, branch, engine))')
        self.conn.execute("INSERT INTO branch_state VALUES ('p', 'main', 'containers', 's9', '2026-10-09', now())")
        self.conn.execute("INSERT INTO findings (project_id, branch, engine, finding_key, vulnerability, status, "
                          "details, updated_at) VALUES ('p', 'main', 'containers', 'k', 'CVE-9', 'open', "
                          "'{\"cwe\": \"CWE-502\"}', now())")
        self.conn.execute("INSERT INTO finding_events (project_id, branch, engine, finding_key, event) "
                          "VALUES ('p', 'main', 'containers', 'k', 'new')")
        db.Store.connect(self.ini).close()
        self.assertIsNone(self.conn.execute("SELECT to_regclass('branch_state')").fetchone()[0])
        self.assertEqual(self.conn.execute('SELECT last_scan_id FROM vw_branch_state').fetchall(), [('s9',)])
        finding_id, category, cwe = self.conn.execute('SELECT finding_id, category, cwe FROM findings').fetchone()
        self.assertEqual((category, cwe), ('Deserialization', 'CWE-502'))
        self.assertEqual(self.conn.execute('SELECT finding_id FROM finding_events').fetchall(), [(finding_id,)])
        names = {r[0] for r in self.conn.execute(
            "SELECT indexname FROM pg_indexes WHERE schemaname = %s", (self.schema,))}
        self.assertIn('idx_findings_status', names)
        self.assertNotIn('findings_status_idx', names)
        views = {r[0] for r in self.conn.execute(
            "SELECT table_name FROM information_schema.views WHERE table_schema = %s", (self.schema,))}
        self.assertEqual(views, {'vw_findings', 'vw_open_findings', 'vw_current_packages', 'vw_branch_state',
                                 'vw_category_summary', 'vw_unique_open_findings', 'vw_sca', 'vw_containers', 'vw_sast', 'vw_iac', 'vw_secrets'})
        columns = {r[0] for r in self.conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = %s AND table_name = 'runs'",
            (self.schema,))}
        self.assertTrue({'status', 'error'} <= columns)

    def test_project_name_on_every_table(self):
        self.scans, self.boms = [scan('s1', 1)], {'s1': bom('npm-a')}
        self.run_export()
        for table in ('findings', 'packages', 'finding_events'):
            names = self.conn.execute(f'SELECT DISTINCT project_name FROM {self.schema}.{table}').fetchall()
            self.assertEqual(names, [('Project',)], table)
        # A renamed project is updated on the next run.
        self.client.pages.side_effect = lambda path, key, **kw: iter(
            {'projects': [{'id': 'p', 'name': 'Renamed'}], 'applications': [], 'scans': list(self.scans)}[key])
        self.run_export()
        self.assertEqual(self.conn.execute(f'SELECT DISTINCT project_name FROM {self.schema}.findings').fetchall(),
                         [('Renamed',)])
        rows = self.conn.execute(f'SELECT project, status FROM {self.schema}.vw_findings').fetchall()
        self.assertEqual(rows, [('Renamed', 'open')])

    def test_missing_vulnerability_section_never_closes(self):
        self.scans = [scan('s1', 1)]
        self.boms = {'s1': bom('npm-a')}
        self.run_export()
        self.scans.append(scan('s2', 2))
        self.boms['s2'] = {k: v for k, v in bom().items() if k != 'vulnerabilities'}
        code, _ = self.run_export()
        self.assertEqual(code, 2)  # Unknown coverage is flagged.
        self.assertEqual(self.findings()['CVE-A|npm|@scope/thing'][0], 'open')
        closed = self.conn.execute(f'SELECT closed_findings FROM {self.schema}.scan_loads WHERE scan_id = %s',
                                   ('s2',)).fetchone()[0]
        self.assertFalse(closed)

    def test_export_error_is_retried_next_run(self):
        self.scans = [scan('s1', 1)]
        self.boms = {}  # The export fails (KeyError in the mock), so nothing is recorded.
        code, _ = self.run_export()
        self.assertEqual((code, self.findings()), (2, {}))
        self.boms = {'s1': bom('npm-a')}
        code, _ = self.run_export()
        self.assertEqual(code, 0)
        self.assertEqual(self.client.export.call_count, 2)
        self.assertEqual(len(self.findings()), 1)

    def test_containers_and_no_files(self):
        def result(tag, state='TO_VERIFY'):
            return {'type': 'containers', 'id': 'r-' + tag, 'state': state, 'status': 'NEW', 'severity': 'HIGH',
                    'firstFoundAt': '2026-09-01T00:00:00Z',
                    'data': {'imageName': 'nginx', 'imageTag': tag, 'imageFilePath': 'Dockerfile',
                             'packageName': 'zlib', 'packageVersion': '1.2'},
                    'vulnerabilityDetails': {'cveName': 'CVE-C'}}
        self.scans = [scan('c1', 1, engine='containers')]
        self.results = {'c1': [result('1.0')]}
        with patch('sys.stdout'), patch('sys.stderr'):
            self.assertEqual(cx.main(['--db', str(self.ini), '--no-files', '--keep-states', 'all', '--scan-types', 'containers',
                                      '--stale-days', '3650']), 0)
        self.scans.append(scan('c2', 2, engine='containers'))
        self.results['c2'] = [result('2.0', 'NOT_EXPLOITABLE')]  # New image tag, same finding, triaged.
        self.run_export('--scan-types', 'containers')
        key = 'CVE-C|nginx|Dockerfile|zlib'
        self.assertEqual(self.findings('containers'), {key: ('open', 'c1', 'c2', None, 0, 'NOT_EXPLOITABLE')})
        first = self.conn.execute(f'SELECT first_seen_at, image_tags FROM {self.schema}.findings').fetchone()
        self.assertEqual(first, (datetime(2026, 9, 1, tzinfo=timezone.utc), '2.0'))
        self.scans.append(scan('c3', 3, engine='containers'))
        self.results['c3'] = []
        self.run_export('--scan-types', 'containers')
        self.assertEqual(self.findings('containers')[key][0], 'fixed')

    def test_sast_iac_and_secrets_share_the_findings_table(self):
        sast = {'type': 'sast', 'id': 'r1', 'similarityId': '77', 'severity': 'HIGH', 'state': 'TO_VERIFY',
                'vulnerabilityDetails': {'cweId': 89},
                'data': {'queryName': 'SQL_Injection', 'languageName': 'Java',
                         'nodes': [{'fileName': 'Dao.java', 'line': 10}]}}
        kics = {'type': 'kics', 'id': 'r2', 'similarityId': '88', 'severity': 'MEDIUM',
                'data': {'queryName': 'Privileged Container', 'group': 'Insecure Configurations',
                         'platform': 'Kubernetes', 'fileName': 'deploy.yaml', 'line': 3}}
        secret = {'type': 'sscs-secret-detection', 'id': 'r3', 'similarityId': '99', 'severity': 'HIGH',
                  'data': {'ruleName': 'github-pat', 'fileName': '.env', 'line': 1}}
        status = [{'name': n, 'status': 'Completed'} for n in ('sast', 'kics', 'microengines')]
        self.scans = [{**scan('x1', 1), 'statusDetails': status}]
        self.results = {'x1': [sast, kics, secret]}
        _, out = self.run_export('--scan-types', 'sast,iac,secrets')
        self.client.results.assert_called_once()  # One /api/results fetch serves all three engines.
        with (out / 'findings.csv').open(encoding='utf-8-sig') as f:
            self.assertEqual(sorted(r['engine'] for r in csv.DictReader(f)), ['kics', 'sast', 'secrets'])
        rows = self.conn.execute(f'SELECT engine, finding_key, category, cwe, file_path, line FROM {self.schema}.findings '
                                 'ORDER BY engine').fetchall()
        self.assertEqual(rows, [('kics', 'sim:88', 'IaC: Insecure Configurations', '', 'deploy.yaml', '3'),
                                ('sast', 'sim:77', 'SQL/NoSQL Injection', 'CWE-89', 'Dao.java', '10'),
                                ('secrets', 'sim:99', 'Hardcoded Credentials / Secrets', '', '.env', '1')])
        self.assertEqual(self.conn.execute(f'SELECT language FROM {self.schema}.vw_sast').fetchall(), [('Java',)])
        # The SQL injection moved to another line (same similarity id); the secret was removed.
        moved = {**sast, 'data': {**sast['data'], 'nodes': [{'fileName': 'Dao.java', 'line': 25}]}}
        self.scans.append({**scan('x2', 2), 'statusDetails': status})
        self.results['x2'] = [moved, kics]
        self.run_export('--scan-types', 'sast,iac,secrets')
        self.assertEqual(self.findings('sast')['sim:77'][:3], ('open', 'x1', 'x2'))
        self.assertEqual(self.findings('secrets')['sim:99'][0], 'fixed')
        summary = self.conn.execute(f'SELECT engine, open_findings, fixed_findings FROM {self.schema}.vw_category_summary '
                                    'ORDER BY engine').fetchall()
        self.assertEqual(summary, [('kics', 1, 0), ('sast', 1, 0), ('secrets', 0, 1)])
        events = self.conn.execute(f'SELECT count(*) FROM {self.schema}.finding_events WHERE finding_id IS NULL')
        self.assertEqual(events.fetchone(), (0,))

    def test_only_true_positives_are_loaded(self):
        def sast(sim, state):
            return {'type': 'sast', 'id': 'r' + sim, 'similarityId': sim, 'severity': 'HIGH', 'state': state,
                    'data': {'queryName': 'SQL_Injection', 'nodes': [{'fileName': 'a.java', 'line': 1}]}}
        status = [{'name': 'sast', 'status': 'Completed'}]
        self.scans = [{**scan('t1', 1), 'statusDetails': status}]
        self.results = {'t1': [sast('1', 'CONFIRMED'), sast('2', 'TO_VERIFY'), sast('3', 'NOT_EXPLOITABLE'),
                               sast('4', 'PROPOSED_NOT_EXPLOITABLE')]}
        _, out = self.run_export('--scan-types', 'sast', '--keep-states', 'CONFIRMED,URGENT')
        self.assertEqual(list(self.findings('sast')), ['sim:1'])
        with (out / 'findings.csv').open(encoding='utf-8-sig') as f:
            self.assertEqual([r['similarity_id'] for r in csv.DictReader(f)], ['1'])
        with (out / 'coverage.csv').open(encoding='utf-8-sig') as f:
            self.assertEqual([(r['finding_count'], r['excluded_findings']) for r in csv.DictReader(f)], [('1', '3')])
        # Scan 2: 1 is re-triaged as not exploitable (excluded, not fixed); 2 becomes Urgent (new).
        self.scans.append({**scan('t2', 2), 'statusDetails': status})
        self.results['t2'] = [sast('1', 'NotExploitable'), sast('2', 'URGENT')]
        self.run_export('--scan-types', 'sast', '--keep-states', 'CONFIRMED,URGENT')
        self.assertEqual({k: v[0] for k, v in self.findings('sast').items()}, {'sim:1': 'excluded', 'sim:2': 'open'})
        # Scan 3: 1 is confirmed again (open); 2 is gone (fixed).
        self.scans.append({**scan('t3', 3), 'statusDetails': status})
        self.results['t3'] = [sast('1', 'CONFIRMED')]
        self.run_export('--scan-types', 'sast', '--keep-states', 'CONFIRMED,URGENT')
        self.assertEqual({k: v[0] for k, v in self.findings('sast').items()}, {'sim:1': 'open', 'sim:2': 'fixed'})
        events = self.conn.execute(f"SELECT finding_key, event FROM {self.schema}.finding_events ORDER BY event_id")
        self.assertEqual(events.fetchall(), [('sim:1', 'new'), ('sim:2', 'new'), ('sim:1', 'excluded'),
                                             ('sim:2', 'fixed'), ('sim:1', 'included')])

    def test_sca_states_come_from_the_results_api(self):
        self.scans = [scan('s1', 1)]
        self.boms = {'s1': bom('npm-a', 'py-b')}
        self.results = {'s1': [  # Checkmarx triage: the npm one is confirmed, django was never triaged.
            {'type': 'sca', 'id': 'CVE-A', 'state': 'CONFIRMED', 'data': {'packageIdentifier': 'Npm-@scope/thing-1.2.3'}},
            {'type': 'sca', 'id': 'CVE-A', 'state': 'TO_VERIFY', 'data': {'scaPackageData': {
                'dependencyPaths': [[{'name': 'django', 'version': '1.0'}]]}}}]}
        self.run_export('--keep-states', 'CONFIRMED,URGENT')
        self.assertEqual(self.findings(), {'CVE-A|npm|@scope/thing': ('open', 's1', 's1', None, 0, 'CONFIRMED')})

    def test_unique_open_findings_across_branches(self):
        self.scans = [scan('m1', 1), scan('d1', 1, branch='dev')]
        self.boms = {'m1': bom('npm-a'), 'd1': bom('npm-a')}
        self.run_export()
        rows = self.conn.execute(f'SELECT vulnerability, package, branches, branch_count '
                                 f'FROM {self.schema}.vw_unique_open_findings').fetchall()
        self.assertEqual(rows, [('CVE-A', '@scope/thing', 'dev; main', 2)])

    def test_bad_connection_is_a_clean_error(self):
        self.ini.write_text('[postgres]\nhost = 127.0.0.1\nport = 1\nconnect_timeout = 2\npassword = hunter2\n')
        with self.assertRaises(db.DatabaseError) as result:
            db.Store.connect(self.ini)
        self.assertIn('PostgreSQL', str(result.exception))
        self.assertNotIn('hunter2', str(result.exception))


if __name__ == '__main__':
    unittest.main()
