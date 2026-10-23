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
        matches = cx.finding_filter(argparse.Namespace(ecosystems='python', package='django', cve='cve-test-1'))
        self.assertFalse(matches(findings[0]))
        self.assertTrue(matches(findings[1]))
        everything = cx.finding_filter(argparse.Namespace(ecosystems='', package=None, cve=None))
        self.assertTrue(all(everything(f) for f in findings))

    def test_null_optional_fields(self):
        b = bom()
        b['vulnerabilities'][0].update(analysis=None, source=None, references=None, ratings=None)
        finding = cx.flatten(b, {})[1][0]
        self.assertEqual((finding['analysis_state'], finding['severity']), ('', 'unknown'))

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
        # A record inserted during paging shifts the next page; repeats are skipped.
        client.api = Mock(side_effect=[{'scans': [{'id': '1'}, {'id': '2'}]},
                                       {'scans': [{'id': '2'}, {'id': '3'}], 'filteredTotalCount': 4}])
        self.assertEqual([s['id'] for s in client.pages('/api/scans', 'scans')], ['1', '2', '3'])
        self.assertEqual(client.api.call_count, 2)  # Stops at filteredTotalCount.

    @staticmethod
    def response(status, body=None, headers=None):
        content = body if isinstance(body, bytes) else cx.json.dumps(body).encode()
        return Mock(status_code=status, content=content, headers=headers or {})

    def export_client(self, responses):
        client = cx.Client.__new__(cx.Client)
        client.base = 'https://eu.ast.checkmarx.net'
        client.verify = True
        client.send = Mock(side_effect=responses)
        client.download = Mock()
        return client

    @patch('checkmarx_exposure.time.sleep')
    def test_export_polling_and_authenticated_download(self, sleep):
        r = self.response
        report = b'\xef\xbb\xbf' + cx.json.dumps(bom()).encode()
        client = self.export_client([r(400, {}), r(202, {'exportId': 'x/1'}), r(404, {}),
            r(200, {'exportStatus': 'Exporting'}), r(200, {'exportStatus': 'Completed', 'fileUrl': 'ignored'}),
            r(200, report)])
        content = client.export('scan', 'CycloneDxJson', 60)
        self.assertEqual(cx.decode_json(content, 'x'), bom())  # BOM is tolerated.
        self.assertEqual(client.send.call_args_list[0].args, ('POST', '/api/sca/export/requests'))
        self.assertEqual(client.send.call_args_list[0].kwargs['json']['ScanID'], 'scan')
        self.assertEqual(client.send.call_args.args, ('GET', '/api/sca/export/requests/x%2F1/download'))
        client.download.get.assert_not_called()

    @patch('checkmarx_exposure.time.sleep')
    def test_export_failure_and_offhost_redirect(self, sleep):
        r = self.response
        client = self.export_client([r(202, {'exportId': 'x'}),
                                     r(200, {'exportStatus': 'Failed', 'errorMessage': 'no results'})])
        with self.assertRaisesRegex(cx.ExportError, 'no results'):
            client.export('scan', 'CycloneDxJson', 60)
        client = self.export_client([r(202, {'exportId': 'x'}), r(200, {'exportStatus': 'Completed'}),
                                     r(302, b'', {'Location': 'https://storage.example.com/r?sig=secret'})])
        client.download.get.return_value = r(200, b'{}')
        self.assertEqual(client.export('scan', 'CycloneDxJson', 60), b'{}')
        self.assertNotIn('headers', client.download.get.call_args.kwargs)
        self.assertFalse(client.download.get.call_args.kwargs['allow_redirects'])

    def test_api_key_client_id(self):
        claims = cx.base64.urlsafe_b64encode(b'{"azp":"custom-app"}').decode().rstrip('=')
        self.assertEqual(cx.token_client_id('h.' + claims + '.s'), 'custom-app')
        self.assertEqual(cx.token_client_id('not-a-jwt'), 'ast-app')

    def test_csv_formula_safety(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / 'x.csv'
            cx.write_csv(target, [{'package': '=1+1'}], ['package'])
            self.assertIn("'=1+1", target.read_text(encoding='utf-8-sig'))

    def test_application_links_and_tags(self):
        apps = [{'id': 'a', 'name': 'Alpha', 'projectIds': ['p'], 'tags': {'owner': 'team'}},
                {'id': 'b', 'name': 'Beta', 'projectIds': ['p'], 'tags': {}}]
        result = cx.application_context({'id': 'p', 'tags': {'release': '1'}}, cx.ApplicationIndex(apps))
        self.assertEqual(cx.json.loads(result['application_ids_json']), ['a', 'b'])
        self.assertEqual(result['application_mapping_status'], 'resolved')
        self.assertEqual(result['applications'], 'Alpha; Beta')
        result = cx.application_context({'id': 'p', 'applicationIds': ['missing']}, cx.ApplicationIndex([], False))
        self.assertEqual(result['application_mapping_status'], 'partial_or_unknown')

    @patch('checkmarx_exposure.Client')
    def test_dump_all_end_to_end(self, constructor):
        import csv
        client = constructor.return_value
        client.verify = True
        scans = [{'id': 's1', 'branch': 'main', 'createdAt': '2026-10-01T00:00:00Z',
                  'statusDetails': [{'name': 'sca', 'status': 'Completed'}], 'tags': {'build': '1'}},
                 {'id': 's2', 'branch': 'main', 'createdAt': '2026-10-02T00:00:00Z',
                  'statusDetails': [{'name': 'sca', 'status': 'Failed'}]},
                 {'id': 's3', 'branch': 'main', 'createdAt': '2026-10-03T00:00:00Z',
                  'statusDetails': [{'name': 'sca', 'status': 'Completed'}]},
                 {'id': 's4', 'branch': 'main', 'createdAt': '2026-10-04T00:00:00Z',
                  'statusDetails': [{'name': 'sca', 'status': 'Failed'}]}]
        def pages(path, key, **kwargs):
            return iter({'projects': [{'id': 'p', 'name': 'Project', 'tags': {'owner': 'X'}}],
                         'applications': [{'id': 'a', 'name': 'App', 'projectIds': ['p'], 'tags': {'tier': '1'}}],
                         'scans': scans}[key])
        client.pages.side_effect = pages
        client.export.side_effect = lambda sid, fmt, timeout: (
            cx.json.dumps(bom()).encode() if fmt == 'CycloneDxJson' else b'{"Packages": []}')
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'dump'
            # Newest scan (s4) failed SCA, so the current evidence is flagged for review.
            self.assertEqual(cx.main(['--dump-all', '--out', str(out)]), 2)
            self.assertEqual(client.export.call_count, 4)
            with (out / 'packages.csv').open(encoding='utf-8-sig') as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 4)
            self.assertEqual(cx.json.loads(rows[0]['application_names_json']), {'a': 'App'})
            self.assertEqual((rows[0]['project'], rows[0]['applications']), ('Project', 'App'))
            self.assertTrue((out / 'applications.csv').exists())
            self.assertEqual(len((out / 'raw' / 'scans-p.jsonl').read_text().splitlines()), 4)
            with (out / 'coverage.csv').open(encoding='utf-8-sig') as f:
                roles = {r['scan_id']: r['scan_role'] for r in csv.DictReader(f)}
            self.assertEqual(roles, {'s4': 'historical', 's3': 'current', 's2': 'historical', 's1': 'historical'})

    def test_project_filters(self):
        apps = cx.ApplicationIndex([{'id': 'a1', 'name': 'Payments', 'projectIds': ['p1']}])
        projects = [{'id': 'p1', 'name': 'pay-api', 'tags': {'Team': 'Blue', 'pci': ''}, 'groups': ['g-eu']},
                    {'id': 'p2', 'name': 'web', 'tags': {'team': 'red'}, 'applicationIds': ['a2'], 'groups': []},
                    {'id': 'p3', 'name': 'tool', 'tags': None}]
        def pick(**kw):
            args = argparse.Namespace(**{'project': None, 'tag': None, 'application': None, 'group': None,
                                         'project_id': None, **kw})
            return [p['id'] for p in projects if cx.project_filter(args, apps)(p)]
        self.assertEqual(pick(), ['p1', 'p2', 'p3'])
        self.assertEqual(pick(tag=['team=blue']), ['p1'])
        self.assertEqual(pick(tag=['TEAM']), ['p1', 'p2'])  # Key only, any value.
        self.assertEqual(pick(tag=['pci']), ['p1'])  # Key-only tag with empty value.
        self.assertEqual(pick(tag=['team=blue', 'team=red']), ['p1', 'p2'])  # Repeats are OR.
        self.assertEqual(pick(tag=['team'], application=['payments']), ['p1'])  # Types are AND.
        self.assertEqual(pick(application=['a2']), ['p2'])  # By ID from project applicationIds.
        self.assertEqual(pick(group=['G-EU']), ['p1'])
        self.assertEqual(pick(project='WEB', tag=['team=blue']), [])
        self.assertEqual(pick(project_id=['P2,p3']), ['p2', 'p3'])  # Exact IDs, case-insensitive.

    def test_results_paging_like_ast_cli(self):
        client = cx.Client.__new__(cx.Client)
        with patch.object(cx, 'RESULTS_PAGE_SIZE', 2):
            client.api = Mock(side_effect=[
                {'results': [{'id': 'a'}, {'id': 'b'}], 'totalCount': 3}, {'results': [{'id': 'c'}], 'totalCount': 3}])
            self.assertEqual([r['id'] for r in client.results('s')], ['a', 'b', 'c'])
            params = client.api.call_args_list[1].kwargs['params']
            self.assertEqual((params['scan-id'], params['offset'], params['limit']), ('s', 1, 2))  # Page number.
            client.api = Mock(side_effect=[{'results': [{'id': 'a'}, {'id': 'b'}], 'totalCount': 9},
                                           {'results': [{'id': 'a'}, {'id': 'b'}], 'totalCount': 9}])
            with self.assertRaises(cx.ExportError):
                client.results('s')
        client.api = Mock(return_value={'totalCount': 0})
        self.assertEqual(client.results('s'), [])

    def test_container_findings(self):
        results = [{'type': 'sast', 'id': 'x'},
                   {'type': 'containers', 'id': 'r1', 'severity': 'HIGH', 'state': 'TO_VERIFY', 'status': 'NEW',
                    'data': {'packageName': 'openssl', 'packageVersion': '1.1', 'imageName': 'nginx',
                             'imageTag': '1.25', 'imageFilePath': 'Dockerfile', 'queryName': 'CVE-1'},
                    'vulnerabilityDetails': {'cveName': 'CVE-1', 'cvssScore': 7.5, 'cweId': 'CWE-1'}}]
        rows = cx.container_findings(results, {'project': 'P'})
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]['image_name'], rows[0]['package'], rows[0]['vulnerability'], rows[0]['severity']),
                         ('nginx', 'openssl', 'CVE-1', 'high'))

    @patch('checkmarx_exposure.Client')
    def test_containers_only_end_to_end(self, constructor):
        import csv
        client = constructor.return_value
        client.verify = True
        scans = [{'id': 's1', 'branch': 'main', 'createdAt': '2026-10-01T00:00:00Z',
                  'statusDetails': [{'name': 'sca', 'status': 'Completed'}, {'name': 'containers', 'status': 'Completed'}]},
                 {'id': 's2', 'branch': 'main', 'createdAt': '2026-10-02T00:00:00Z',
                  'statusDetails': [{'name': 'containers', 'status': 'Failed'}]}]
        def pages(path, key, **kwargs):
            return iter({'projects': [{'id': 'P1', 'name': 'One'}, {'id': 'p2', 'name': 'Two'}],
                         'applications': [], 'scans': scans}[key])
        client.pages.side_effect = pages
        client.results.return_value = [{'type': 'containers', 'id': 'r', 'data': {'packageName': 'zlib'},
                                        'vulnerabilityDetails': {'cveName': 'CVE-2'}}, {'type': 'sca', 'id': 'q'}]
        with tempfile.TemporaryDirectory() as tmp:
            ids = Path(tmp) / 'ids.csv'
            ids.write_text('Project ID,name\n\np1,One\nmissing,Gone\n', encoding='utf-8')
            out = Path(tmp) / 'out'
            self.assertEqual(cx.main(['--scan-types', 'container-security', '--project-ids-file', str(ids),
                                      '--out', str(out)]), 2)  # Unknown ID and newer failed scan are flagged.
            client.export.assert_not_called()
            client.results.assert_called_once_with('s1')
            with (out / 'container_findings.csv').open(encoding='utf-8-sig') as f:
                rows = list(csv.DictReader(f))
            self.assertEqual([(r['project_id'], r['package']) for r in rows], [('P1', 'zlib')])
            with (out / 'coverage.csv').open(encoding='utf-8-sig') as f:
                cover = list(csv.DictReader(f))
            self.assertEqual([(r['scan_type'], r['scan_id'], r['newer_scan_than_selected']) for r in cover],
                             [('containers', 's1', 'True')])
            self.assertTrue((out / 'raw' / 's1.containers.json').exists())
            summary = cx.json.loads((out / 'run.json').read_text())
            self.assertEqual(summary['metadata_errors'][0]['project_ids'], ['missing'])

    def test_scan_types_and_project_ids_args(self):
        self.assertEqual(cx.parse_args([]).engines, ['sca'])
        self.assertEqual(cx.parse_args(['--scan-types', 'SCA,containers,container']).engines, ['sca', 'containers'])
        with self.assertRaises(SystemExit), patch('sys.stderr'):
            cx.parse_args(['--scan-types', 'sast'])
        with tempfile.TemporaryDirectory() as tmp:
            plain = Path(tmp) / 'plain.csv'
            plain.write_text('\ufeffaaa\n\n bbb ,x\n', encoding='utf-8')
            self.assertEqual(cx.load_project_ids(plain), ['aaa', 'bbb'])
            args = cx.parse_args(['--project-id', 'c,d', '--project-ids-file', str(plain)])
            self.assertEqual(cx.project_ids(args), ['c', 'd', 'aaa', 'bbb'])

    def test_coverage_gap(self):
        current = {'scan_role': 'current', 'status': 'exported', 'vulnerability_section': 'present',
                   'unresolved_links': 0, 'newer_scan_than_selected': False}
        self.assertFalse(cx.coverage_gap(current))
        self.assertTrue(cx.coverage_gap({**current, 'newer_scan_than_selected': True}))
        self.assertFalse(cx.coverage_gap({**current, 'scan_role': 'historical', 'status': 'stale_or_unknown_date'}))
        self.assertTrue(cx.coverage_gap({**current, 'scan_role': 'historical', 'status': 'export_error'}))

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

    @patch.dict('os.environ', {'CX_BASE_URL': 'https://example.com', 'CX_TOKEN_URL': 'https://iam.example.com/token',
        'CX_API_KEY': 'test', 'REQUESTS_CA_BUNDLE': '/etc/ssl/certs/ca-certificates.crt'}, clear=True)
    def test_tls_verification_setting(self):
        self.assertIs(cx.tls_verify(''), True)
        self.assertIs(cx.tls_verify('False'), False)
        with self.assertRaises(cx.ExportError):
            cx.tls_verify('/no/such/ca.pem')
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / 'ca.pem'
            bundle.write_text('placeholder')
            self.assertEqual(cx.tls_verify(str(bundle)), str(bundle))
            with patch.object(cx, 'DEFAULT_CONFIG', Path(tmp) / 'missing.ini'):
                with patch.dict('os.environ', {'CX_VERIFY_SSL': 'false'}), patch('sys.stderr'):
                    client = cx.Client()
                self.assertIs(client.verify, False)
                self.assertIs(cx.Client(insecure=False).verify, True)
                with patch('sys.stderr'):
                    self.assertIs(cx.Client(insecure=True).verify, False)
        # verify=False must be sent per request: REQUESTS_CA_BUNDLE overrides a session-level False.
        client.http = Mock()
        client.http.post.return_value = self.response(200, {'access_token': 't', 'expires_in': 300})
        client.http.request.return_value = self.response(200, {'ok': True})
        client.api('GET', '/api/projects')
        self.assertIs(client.http.post.call_args.kwargs['verify'], False)
        self.assertIs(client.http.request.call_args.kwargs['verify'], False)

    def test_relaxed_tls_session(self):
        adapter = cx.session(False).get_adapter('https://eu.ast.checkmarx.net')
        self.assertIsInstance(adapter, cx.RelaxedTLSAdapter)
        ctx = adapter.poolmanager.connection_pool_kw['ssl_context']
        self.assertEqual((ctx.check_hostname, ctx.verify_mode), (False, cx.ssl.CERT_NONE))
        self.assertTrue(ctx.options & getattr(cx.ssl, 'OP_LEGACY_SERVER_CONNECT', 0x4))
        self.assertNotIsInstance(cx.session(True).get_adapter('https://x.example'), cx.RelaxedTLSAdapter)

    def test_connection_errors_are_diagnosable_but_redacted(self):
        exc = cx.requests.exceptions.SSLError(
            "HTTPSConnectionPool(host='eu.ast.checkmarx.net', port=443): Max retries exceeded with url: "
            "/r?sig=SECRET (Caused by SSLError(SSLCertVerificationError('certificate verify failed')))")
        text = cx.safe_error(exc)
        self.assertIn('certificate verify failed', text)
        self.assertIn('eu.ast.checkmarx.net', text)
        self.assertNotIn('SECRET', text)
        proxy = cx.safe_error(cx.requests.exceptions.ProxyError('Cannot connect to proxy http://bob:pw@proxy:8080'))
        self.assertNotIn('pw', proxy)
        self.assertEqual(cx.safe_error(KeyError('x')), 'KeyError')

    def test_https(self):
        for url in ['http://example.com', 'https://user:password@example.com']:
            with self.assertRaises(cx.ExportError):
                cx.https_url(url)


if __name__ == '__main__':
    unittest.main()
