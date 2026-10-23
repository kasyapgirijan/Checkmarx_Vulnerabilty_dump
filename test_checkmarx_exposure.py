import argparse
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import checkmarx_exposure as cx


def bom():
    return {'bomFormat': 'CycloneDX', 'components': [
        {'bom-ref': 'npm-a', 'group': '@scope', 'name': 'thing', 'version': '1.2.3', 'purl': 'pkg:npm/%40scope/thing@1.2.3'},
        {'bom-ref': 'py-b', 'name': 'django', 'version': '1.0', 'purl': 'pkg:pypi/django@1.0'}],
        'vulnerabilities': [{'id': 'CVE-TEST-1', 'affects': [{'ref': 'npm-a'}, {'ref': 'py-b'}],
        'ratings': [{'severity': 'medium'}, {'severity': 'high'}], 'analysis': {'state': 'not_affected'}}]}


class Tests(unittest.TestCase):
    def test_join_and_scope(self):
        packages, findings, status, unresolved = cx.flatten(bom(), {'project': 'A'})
        self.assertEqual(len(packages), 2)
        self.assertEqual([f['package'] for f in findings], ['@scope/thing', 'django'])
        self.assertEqual(findings[0]['severity'], 'high')
        self.assertEqual(findings[0]['analysis_state'], 'not_affected')
        self.assertEqual((status, unresolved), ('present', 0))
        args = argparse.Namespace(ecosystems='python', package='django', cve='cve-test-1')
        self.assertFalse(cx.matches(findings[0], args))
        self.assertTrue(cx.matches(findings[1], args))

    def test_unknown_is_not_clean(self):
        b = bom()
        del b['vulnerabilities']
        self.assertEqual(cx.flatten(b, {})[2], 'not_provided')
        b['vulnerabilities'] = [{'id': 'CVE-X', 'affects': [{'ref': 'missing'}]}]
        result = cx.flatten(b, {})
        self.assertEqual(result[3], 1)
        self.assertEqual(result[1][0]['package_link_status'], 'unresolved')
        with self.assertRaises(cx.ExportError):
            cx.flatten({'Packages': []}, {})

    def test_latest_successful_sca_per_branch(self):
        def scan(i, branch, status, date):
            return dict(id=i, branch=branch, createdAt=date, statusDetails=[{'name': 'sca', 'status': status}])
        scans = [scan('old', 'main', 'Completed', '2026-01-01T00:00:00Z'),
                 scan('new', 'main', 'Failed', '2026-02-01T00:00:00Z'),
                 scan('feature', 'feature', 'Completed', '2026-03-01T00:00:00Z')]
        chosen = cx.choose_scans(scans, 'main')
        self.assertEqual(chosen[0][1]['id'], 'new')
        self.assertEqual(chosen[0][2]['id'], 'old')
        self.assertEqual(len(cx.choose_scans(scans)), 2)
        self.assertFalse(cx.sca_completed({'status': 'Completed', 'engines': ['sast']}))

    def test_pagination_with_server_cap(self):
        client = cx.Client.__new__(cx.Client)
        client.api = Mock(side_effect=[{'projects': [{'id': '1'}]}, {'projects': [{'id': '2'}]}, {'projects': []}])
        self.assertEqual(len(list(client.pages('/api/projects', 'projects'))), 2)
        self.assertEqual(client.api.call_args_list[1].kwargs['params']['offset'], 1)
        client.api = Mock(side_effect=[{'projects': [{'id': '1'}]}, {'projects': [{'id': '1'}]}])
        with self.assertRaises(cx.ExportError):
            list(client.pages('/api/projects', 'projects'))

    @patch('checkmarx_exposure.time.sleep')
    def test_export_polling_and_download_without_credentials(self, sleep):
        client = cx.Client.__new__(cx.Client)
        client.api = Mock(side_effect=[{'exportId': 'x'}, {'exportStatus': 'Pending'},
            {'exportStatus': 'Completed', 'fileUrl': 'https://example.com/report?signature=secret'}])
        client.download = Mock()
        client.download.get.return_value = Mock(status_code=200)
        client.download.get.return_value.json.return_value = bom()
        self.assertEqual(client.export('scan', 'CycloneDxJson', 10), bom())
        self.assertNotIn('headers', client.download.get.call_args.kwargs)
        self.assertFalse(client.download.get.call_args.kwargs['allow_redirects'])

    def test_csv_formula_safety(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / 'x.csv'
            cx.write_csv(target, [{'package': '=1+1'}], ['package'])
            self.assertIn("'=1+1", target.read_text(encoding='utf-8-sig'))

    def test_application_links_and_tags(self):
        apps = [{'id': 'a', 'name': 'Alpha', 'projectIds': ['p'], 'tags': {'owner': 'team'}},
                {'id': 'b', 'name': 'Beta', 'projectIds': ['p'], 'tags': {}}]
        result = cx.application_context({'id': 'p', 'tags': {'release': '1'}}, apps, True)
        self.assertEqual(cx.json.loads(result['application_ids_json']), ['a', 'b'])
        self.assertEqual(result['application_mapping_status'], 'resolved')
        result = cx.application_context({'id': 'p', 'applicationIds': ['missing']}, [], False)
        self.assertEqual(result['application_mapping_status'], 'partial_or_unknown')

    @patch('checkmarx_exposure.Client')
    def test_dump_all_end_to_end(self, constructor):
        import csv
        client = constructor.return_value
        scans = [{'id': 's1', 'branch': 'main', 'createdAt': '2026-10-01T00:00:00Z',
                  'statusDetails': [{'name': 'sca', 'status': 'Completed'}], 'tags': {'build': '1'}},
                 {'id': 's2', 'branch': 'main', 'createdAt': '2026-10-02T00:00:00Z',
                  'statusDetails': [{'name': 'sca', 'status': 'Failed'}]},
                 {'id': 's3', 'branch': 'main', 'createdAt': '2026-10-03T00:00:00Z',
                  'statusDetails': [{'name': 'sca', 'status': 'Completed'}]}]
        def pages(path, key, **kwargs):
            return iter({'projects': [{'id': 'p', 'name': 'Project', 'tags': {'owner': 'X'}}],
                         'applications': [{'id': 'a', 'name': 'App', 'projectIds': ['p'], 'tags': {'tier': '1'}}],
                         'scans': scans}[key])
        client.pages.side_effect = pages
        client.export.side_effect = lambda sid, fmt, timeout: bom() if fmt == 'CycloneDxJson' else {'Packages': []}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'dump'
            with patch('sys.argv', ['script', '--dump-all', '--out', str(out)]):
                self.assertEqual(cx.main(), 2)  # Failed SCA is explicit coverage gap.
            self.assertEqual(client.export.call_count, 4)
            with (out / 'packages.csv').open(encoding='utf-8-sig') as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 4)
            self.assertEqual(cx.json.loads(rows[0]['application_names_json']), {'a': 'App'})
            self.assertTrue((out / 'applications.csv').exists())
            self.assertEqual(len((out / 'raw' / 'scans-p.jsonl').read_text().splitlines()), 3)

    @patch.dict('os.environ', {}, clear=True)
    def test_ini_config_and_precedence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.ini'
            path.write_text('[checkmarx]\nbase_url = https://example.com\ntoken_url = https://iam.example.com/token\napi_key = test%literal#token\n')
            settings = cx.load_settings(path)
            self.assertEqual(settings['api_key'], 'test%literal#token')
            with patch.dict('os.environ', {'CX_API_KEY': 'env-token'}):
                self.assertEqual(cx.load_settings(path)['api_key'], 'env-token')
            with patch.object(cx, 'DEFAULT_CONFIG', path):
                self.assertEqual(cx.load_settings()['base_url'], 'https://example.com')

    @patch.dict('os.environ', {}, clear=True)
    def test_config_errors_redact_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.ini'
            with self.assertRaisesRegex(cx.ExportError, 'does not exist'):
                cx.load_settings(path)
            path.write_text('[checkmarx]\napi_key = PRIVATE_VALUE\nPRIVATE_VALUE\n')
            with self.assertRaises(cx.ExportError) as result:
                cx.load_settings(path)
            self.assertNotIn('PRIVATE_VALUE', str(result.exception))
            path.write_text('[checkmarx]\napi_key = test\n')
            with self.assertRaisesRegex(cx.ExportError, 'Missing base_url'):
                cx.load_settings(path)

    @patch.dict('os.environ', {'CX_BASE_URL': 'https://example.com',
        'CX_TOKEN_URL': 'https://iam.example.com/token', 'CX_API_KEY': 'test'}, clear=True)
    def test_environment_only_compatibility(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cx, 'DEFAULT_CONFIG', Path(tmp) / 'missing.ini'):
                self.assertEqual(cx.load_settings()['api_key'], 'test')

    def test_https(self):
        for url in ['http://example.com', 'https://user:password@example.com']:
            with self.assertRaises(cx.ExportError):
                cx.https_url(url)


if __name__ == '__main__':
    unittest.main()
