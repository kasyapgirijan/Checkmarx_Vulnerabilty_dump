"""Tests for exposure_report.py. The PostgreSQL test needs CX_TEST_PG (see test_checkmarx_db.py)."""
import csv
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import checkmarx_exposure as cx
import exposure_report as er

PG = os.getenv('CX_TEST_PG', '')
INI = """
[report]
output = {out}
source = {source}

[Log4Shell]
cves = CVE-2021-44228
ecosystem = maven
packages = org.apache.logging.log4j/log4j-core
affected = >=2.0-beta9,<2.3.2 ; >=2.4,<2.12.4 ; >=2.13.0,<2.17.1
fixed = 2.17.1

[React2Shell/react]
cves = CVE-2025-55182
ecosystem = npm
packages = react-server-dom-*
affected = >=19.0.0,<19.0.1 ; >=19.1.0,<19.1.2
"""


def write(path, fields, rows):
    cx.write_csv(path, rows, fields)


def read(path):
    with path.open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


class VersionTests(unittest.TestCase):
    def test_ranges(self):
        ranges = er.parse_ranges('>=2.0-beta9,<2.3.2 ; >=2.4,<2.12.4 ; >=2.13.0,<2.17.1', 'x')
        expected = {'2.0-beta9': True, '2.0-rc1': True, '2.3.2': False, '2.12.4': False, '2.14.1': True,
                    '2.16.0': True, '2.17.1': False, '2.20.0': False, '1.2.17': False, 'latest': None}
        self.assertEqual({v: er.in_ranges(v, ranges) for v in expected}, expected)
        self.assertTrue(er.in_ranges('5.3.17.RELEASE', er.parse_ranges('<5.2.20 ; >=5.3.0,<5.3.18', 'x')))
        self.assertTrue(er.in_ranges('19.0.0', er.parse_ranges('19.0.0', 'x')))  # Bare version = exact.
        with self.assertRaises(er.ReportError):
            er.parse_ranges('', 'x')

    def test_container_names_match_on_last_segment(self):
        rule = er.Rule('X', {'packages': 'org.apache.logging.log4j/log4j-core', 'affected': '<2.17.1',
                             'ecosystem': 'maven'})
        self.assertTrue(rule.matches_package('log4j-core', '', 'containers'))
        self.assertTrue(rule.matches_package('org.apache.logging.log4j:log4j-core', '', 'containers'))
        self.assertFalse(rule.matches_package('log4j-core', 'npm', 'sca'))  # Wrong ecosystem for SCA.
        self.assertFalse(rule.matches_package('log4j-api', '', 'containers'))


class FolderReportTests(unittest.TestCase):
    def test_report_from_export_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / 'export'
            folder.mkdir()
            base = {'project': 'Payments', 'project_id': 'p1', 'branch': 'main', 'scan_id': 's1',
                    'applications': 'Bank'}
            write(folder / 'packages.csv', cx.PKG, [
                {**base, 'package': 'org.apache.logging.log4j/log4j-core', 'version': '2.14.1', 'ecosystem': 'maven',
                 'dependency_type': 'transitive', 'introduced_by': 'org.springframework/spring-core@5.3.0'},
                {**base, 'branch': 'release', 'package': 'org.apache.logging.log4j/log4j-core', 'version': '2.17.1',
                 'ecosystem': 'maven'},
                {**base, 'project': 'Web', 'project_id': 'p2', 'package': 'react-server-dom-webpack',
                 'version': '19.1.1', 'ecosystem': 'npm'},
                {**base, 'package': 'org.apache.logging.log4j/log4j-api', 'version': '2.14.1', 'ecosystem': 'maven'}])
            # Checkmarx reported the CVE on the Payments log4j-core, but not React2Shell on Web.
            write(folder / 'findings.csv', cx.FIND, [
                {**base, 'package': 'org.apache.logging.log4j/log4j-core', 'version': '2.14.1',
                 'vulnerability': 'CVE-2021-44228', 'severity': 'critical', 'triage_state': 'exploitable', 'engine': 'sca'},
                {**base, 'project': 'Api', 'project_id': 'p3', 'image_name': 'api', 'image_tag': '1.0', 'engine': 'containers',
                 'package': 'log4j-core', 'version': '2.15.0', 'vulnerability': 'CVE-2021-45046', 'triage_state': 'TO_VERIFY'},
                {**base, 'project': 'Old', 'project_id': 'p4', 'image_name': 'legacy', 'package': 'log4j',
                 'version': '1.2.17', 'vulnerability': 'CVE-2021-44228', 'engine': 'containers'},  # Name not in rule, CVE is.
                {**base, 'engine': 'sast', 'vulnerability': 'SQL_Injection', 'file_path': 'a.java'}])  # Ignored.
            ini = Path(tmp) / 'report.ini'
            out = Path(tmp) / 'out' / 'report.csv'
            ini.write_text(INI.format(out=out, source=folder))
            with patch('sys.stdout'):
                self.assertEqual(er.main(['--config', str(ini)]), 0)
            rows = read(out)
            got = [(r['vulnerability_name'], r['verdict'], r['project'], r['branch'], r['scan_type'], r['package'],
                    r['version'], r['checkmarx_reported_target_cve'], r['checkmarx_cves']) for r in rows]
            self.assertEqual(got, [
                ('Log4Shell', 'affected', 'Api', 'main', 'containers', 'log4j-core', '2.15.0', 'no', 'CVE-2021-45046'),
                ('Log4Shell', 'affected', 'Payments', 'main', 'sca', 'org.apache.logging.log4j/log4j-core', '2.14.1',
                 'yes', 'CVE-2021-44228'),
                ('Log4Shell', 'reported_by_checkmarx', 'Old', 'main', 'containers', 'log4j', '1.2.17', 'yes',
                 'CVE-2021-44228'),
                ('Log4Shell', 'not_affected', 'Payments', 'release', 'sca', 'org.apache.logging.log4j/log4j-core',
                 '2.17.1', 'no', 'NA'),
                ('React2Shell', 'affected', 'Web', 'main', 'sca', 'react-server-dom-webpack', '19.1.1', 'no', 'NA')])
            self.assertEqual(rows[1]['dependency_type'], 'transitive')
            self.assertEqual(rows[1]['triage_state'], 'exploitable')
            summary = read(out.with_name('report-summary.csv'))
            self.assertEqual([(s['vulnerability_name'], s['project'], s['affected_rows'], s['branches_affected'])
                              for s in summary][:2], [('Log4Shell', 'Api', '1', 'main'),
                                                      ('Log4Shell', 'Old', '1', 'main')])

    def test_example_config_parses(self):
        report, rules = er.load_report_config(Path(__file__).with_name('report.example.ini'))
        self.assertEqual(report['source'], 'db')
        self.assertEqual(sorted({r.name for r in rules}), ['Log4Shell', 'React2Shell', 'Spring4Shell'])
        next_rule = next(r for r in rules if r.section == 'React2Shell/next')
        self.assertTrue(er.in_ranges('15.4.7', next_rule.ranges))
        self.assertFalse(er.in_ranges('15.4.8', next_rule.ranges))


@unittest.skipUnless(PG, 'set CX_TEST_PG to run the PostgreSQL tests')
class DatabaseReportTests(unittest.TestCase):
    def test_report_from_database(self):
        import psycopg
        schema = 'cx_test_' + uuid.uuid4().hex[:10]
        keywords = dict(part.split('=', 1) for part in PG.split())
        with tempfile.TemporaryDirectory() as tmp, patch('checkmarx_exposure.Client') as constructor:
            config = Path(tmp) / 'config.ini'
            config.write_text('[postgres]\n' + ''.join(f'{k} = {v}\n' for k, v in keywords.items())
                              + f'schema = {schema}\n')
            client = constructor.return_value
            client.verify = True
            scans = [{'id': 's1', 'branch': 'main', 'createdAt': '2026-10-01T00:00:00Z',
                      'statusDetails': [{'name': 'sca', 'status': 'Completed'}]}]
            bom = {'bomFormat': 'CycloneDX', 'components': [
                {'bom-ref': 'l', 'group': 'org.apache.logging.log4j', 'name': 'log4j-core', 'version': '2.14.1',
                 'purl': 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'}], 'vulnerabilities': []}
            client.pages.side_effect = lambda path, key, **kw: iter(
                {'projects': [{'id': 'p', 'name': 'Payments'}], 'applications': [], 'scans': scans}[key])
            client.export.side_effect = lambda sid, fmt, timeout: json.dumps(bom).encode()
            try:
                with patch('sys.stdout'), patch('sys.stderr'):
                    cx.main(['--db', '--config', str(config), '--no-files', '--exclude-states', 'none'])
                ini = Path(tmp) / 'report.ini'
                out = Path(tmp) / 'report.csv'
                ini.write_text(INI.format(out=out, source='db').replace('[report]\n',
                                                                       f'[report]\ndb_config = {config}\n'))
                with patch('sys.stdout'):
                    er.main(['--config', str(ini), '--only', 'Log4Shell'])
                rows = read(out)
                # No CVE in Checkmarx (empty vulnerabilities), but the version is in range.
                self.assertEqual([(r['verdict'], r['project'], r['version'], r['checkmarx_cves']) for r in rows],
                                 [('affected', 'Payments', '2.14.1', 'NA')])
                self.assertTrue(rows[0]['source'].startswith('postgres:'))
            finally:
                with psycopg.connect(PG, autocommit=True) as conn:
                    conn.execute(f'DROP SCHEMA IF EXISTS {schema} CASCADE')


if __name__ == '__main__':
    unittest.main()
