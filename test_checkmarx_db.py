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
            with self.assertRaisesRegex(db.DatabaseError, 'does not exist'):
                db.load_db_settings(Path(tmp) / 'missing.ini')

    def test_finding_keys_ignore_versions_and_image_tags(self):
        sca = [{'vulnerability': 'CVE-1', 'ecosystem': 'npm', 'package': 'a', 'version': '1.0', 'severity': 'low'},
               {'vulnerability': 'CVE-1', 'ecosystem': 'npm', 'package': 'a', 'version': '2.0', 'severity': 'high'}]
        records = db.normalize(sca, 'sca')
        self.assertEqual(list(records), ['CVE-1|npm|a'])
        self.assertEqual((records['CVE-1|npm|a']['versions'], records['CVE-1|npm|a']['severity']), ('1.0; 2.0', 'high'))
        container = {'vulnerability': 'CVE-2', 'image_name': 'nginx', 'image_file_path': 'Dockerfile',
                     'package': 'zlib', 'image_tag': '1.0', 'state': 'NOT_EXPLOITABLE'}
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
        self.client.results.side_effect = lambda sid, kind: copy.deepcopy(self.results[sid])

    def tearDown(self):
        self.conn.execute(f'DROP SCHEMA IF EXISTS {self.schema} CASCADE')
        self.conn.close()
        self.tmp.cleanup()

    def run_export(self, *extra):
        self.runs += 1
        out = Path(self.tmp.name) / f'out{self.runs}'
        with patch('sys.stdout'), patch('sys.stderr'):
            return cx.main(['--db', str(self.ini), '--out', str(out), '--stale-days', '3650', *extra]), out

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
        self.assertEqual(self.findings(), {npm: ('open', 's1', 's1', None, 0, 'not_affected'),
                                           pypi: ('open', 's1', 's1', None, 0, 'not_affected')})
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
        self.assertEqual(self.findings()[pypi], ('open', 's1', 's3', None, 1, 'not_affected'))
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
        open_rows = self.conn.execute(f'SELECT project, finding_key FROM {self.schema}.open_findings').fetchall()
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
        java = self.conn.execute(f"SELECT DISTINCT project FROM {self.schema}.current_packages "
                                 f"WHERE ecosystem = 'maven'").fetchall()
        self.assertEqual(java, [('Project',)])

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
            self.assertEqual(cx.main(['--db', str(self.ini), '--no-files', '--scan-types', 'containers',
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

    def test_bad_connection_is_a_clean_error(self):
        self.ini.write_text('[postgres]\nhost = 127.0.0.1\nport = 1\nconnect_timeout = 2\npassword = hunter2\n')
        with self.assertRaises(db.DatabaseError) as result:
            db.Store.connect(self.ini)
        self.assertIn('PostgreSQL', str(result.exception))
        self.assertNotIn('hunter2', str(result.exception))


if __name__ == '__main__':
    unittest.main()
