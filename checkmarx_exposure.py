#!/usr/bin/env python3
"""Export Checkmarx One SCA evidence. Python 3.10+, requests. See README.md."""
import argparse
import base64
import configparser
import csv
import json
import os
from pathlib import Path
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class ExportError(Exception):
    pass


def https_url(value):
    u = urlsplit(value)
    if u.scheme != 'https' or not u.netloc or u.username or u.password or u.fragment:
        raise ExportError('Expected an HTTPS URL without embedded credentials or fragment')
    return value.rstrip('/')


def session():
    s = requests.Session()
    # POSTs are deliberately not retried: they can create duplicate export jobs.
    s.mount('https://', HTTPAdapter(max_retries=Retry(
        total=4, backoff_factor=1, status_forcelist=[429, 502, 503, 504],
        allowed_methods=['GET'], respect_retry_after_header=True)))
    return s


def checked_json(response, label):
    if not 200 <= response.status_code < 300:
        raise ExportError(f'{label}: HTTP {response.status_code}')
    try:
        return response.json()
    except ValueError:
        raise ExportError(f'{label}: invalid JSON') from None


DEFAULT_CONFIG = Path(__file__).resolve().with_name('config.ini')


def load_settings(config_path=None):
    """Read local INI settings; non-empty environment values override file values."""
    path = Path(config_path).expanduser() if config_path is not None else DEFAULT_CONFIG
    values = {}
    if path.exists():
        parser = configparser.ConfigParser(interpolation=None)
        try:
            with path.open(encoding='utf-8-sig') as config_file:
                parser.read_file(config_file)
            if not parser.has_section('checkmarx'):
                raise ExportError('Config must contain a [checkmarx] section')
            values = dict(parser['checkmarx'])
        except (configparser.Error, OSError, UnicodeError):
            # Parser errors can include full lines containing secrets.
            raise ExportError('Cannot read config: check file permissions and INI syntax') from None
    elif config_path is not None:
        raise ExportError('Specified config file does not exist')
    keys = {'base_url': 'CX_BASE_URL', 'token_url': 'CX_TOKEN_URL',
            'api_key': 'CX_API_KEY', 'client_id': 'CX_CLIENT_ID',
            'client_secret': 'CX_CLIENT_SECRET'}
    result = {key: (os.getenv(env) or values.get(key, '')).strip() for key, env in keys.items()}
    for key in ('base_url', 'token_url'):
        if not result[key]:
            raise ExportError('Missing ' + key + ': set it in config.ini or ' + keys[key])
    if not result['api_key'] and not (result['client_id'] and result['client_secret']):
        raise ExportError('Set api_key in config.ini (or CX_API_KEY), or provide client_id and client_secret')
    if result['api_key'].startswith('YOUR_'):
        raise ExportError('Replace the api_key placeholder in your local config.ini')
    return result


class Client:
    def __init__(self, config_path=None):
        settings = load_settings(config_path)
        self.base = https_url(settings['base_url'])
        self.token_url = https_url(settings['token_url'])
        self.api_key = settings['api_key']
        self.client_id = settings['client_id']
        self.secret = settings['client_secret']
        self.http = session()
        self.download = session()  # Never receives a Checkmarx Authorization header.
        self.token = ''
        self.expires = 0

    def authenticate(self):
        if self.api_key:
            client_id = self.client_id or 'ast-app'
            if not self.client_id:
                try:
                    payload = self.api_key.split('.')[1]
                    client_id = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))).get('azp') or client_id
                except (ValueError, IndexError, TypeError):
                    pass
            data = dict(grant_type='refresh_token', client_id=client_id, refresh_token=self.api_key)
        else:
            data = dict(grant_type='client_credentials', client_id=self.client_id, client_secret=self.secret)
        result = checked_json(self.http.post(self.token_url, data=data, timeout=(15, 90), allow_redirects=False), 'Authentication')
        self.token = result['access_token']
        self.expires = time.monotonic() + max(1, float(result.get('expires_in', 300)) - 30)
        if self.api_key and result.get('refresh_token'):
            self.api_key = result['refresh_token']

    def api(self, method, path, **kwargs):
        for attempt in range(2):
            if time.monotonic() >= self.expires:
                self.authenticate()
            response = self.http.request(method, self.base + path,
                headers={'Authorization': 'Bearer ' + self.token}, timeout=(15, 90),
                allow_redirects=False, **kwargs)
            if response.status_code == 401 and attempt == 0:
                self.expires = 0
                continue
            return checked_json(response, path)
        raise ExportError('Authentication failed')

    def pages(self, path, key, **params):
        offset, seen = 0, set()
        while True:
            result = self.api('GET', path, params={**params, 'limit': 100, 'offset': offset})
            batch = result.get(key)
            if not isinstance(batch, list):
                raise ExportError(f'{path}: missing {key} array')
            if not batch:
                break
            for item in batch:
                ident = item['id']
                if ident in seen:
                    raise ExportError(f'{path}: repeated ID during pagination; rerun when scans are stable')
                seen.add(ident)
                yield item
            offset += len(batch)
            # Request until empty, allowing server-side page-size caps.

    def export(self, scan_id, fmt, timeout):
        endpoint = '/api/sca/export/requests'
        job = self.api('POST', endpoint, json={
            'ScanId': scan_id, 'FileFormat': fmt,
            'ExportParameters': {'hideDevAndTestDependencies': False,
                                 'excludeVulnerabilities': False}})
        export_id = job['exportId']
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.api('GET', endpoint, params={'exportId': export_id, 'returnUrl': 'true'})
            state = str(result.get('exportStatus', '')).lower()
            if state == 'completed':
                url = https_url(result['fileUrl'])
                # Signed URL has its own authorization. No API credentials are sent.
                response = self.download.get(url, timeout=(15, 120), allow_redirects=False)
                return checked_json(response, 'Report download')
            if state == 'failed':
                raise ExportError('Report generation failed')
            if state not in ('pending', 'exporting'):
                raise ExportError('Unexpected export status')
            time.sleep(3)
        raise ExportError('Report generation timed out')


def field(obj, name, default=''):
    return next((v for k, v in obj.items() if k.lower() == name.lower()), default)


def sca_completed(scan):
    return any(str(field(d, 'name')).lower() == 'sca' and
               str(field(d, 'status')).lower() == 'completed'
               for d in scan.get('statusDetails', []))


def parse_date(value):
    try:
        date = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return date if date.tzinfo else date.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError, AttributeError):
        return datetime.min.replace(tzinfo=timezone.utc)


def choose_scans(scans, branch=None):
    groups = {}
    for scan in scans:
        name = scan.get('branch') or '(unknown)'
        if branch is None or name == branch:
            groups.setdefault(name, []).append(scan)
    chosen = []
    for name, items in sorted(groups.items()):
        items.sort(key=lambda s: parse_date(s.get('createdAt')), reverse=True)
        selected = next((s for s in items if sca_completed(s)), None)
        chosen.append((name, items[0], selected))
    return chosen


def components(items):
    for c in items:
        yield c
        yield from components(c.get('components', []))


def flatten(bom, context):
    if bom.get('bomFormat') != 'CycloneDX' or not isinstance(bom.get('components'), list):
        raise ExportError('Unexpected SBOM schema: expected CycloneDX components array')
    packages, findings, by_ref = [], [], {}
    for c in components(bom['components']):
        purl = c.get('purl', '')
        ecosystem = purl[4:].split('/', 1)[0] if purl.startswith('pkg:') else 'unknown'
        name = '/'.join(filter(None, [c.get('group'), c.get('name')]))
        ref = c.get('bom-ref', '')
        row = {**context, 'component_ref': ref, 'package': name, 'version': c.get('version', ''),
               'ecosystem': ecosystem, 'purl': purl, 'scope': c.get('scope', ''),
               'component_type': c.get('type', ''), 'runtime_verified': 'not_assessed'}
        packages.append(row)
        if ref:
            by_ref[ref] = row
    vulnerabilities = bom.get('vulnerabilities', [])
    if not isinstance(vulnerabilities, list):
        raise ExportError('Unexpected vulnerabilities schema')
    unresolved = 0
    for v in vulnerabilities:
        ratings = v.get('ratings', [])
        ranks = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1, 'none': 0}
        severity = max((r.get('severity', 'unknown').lower() for r in ratings),
                       key=lambda s: ranks.get(s, -1), default='unknown')
        aliases = [r.get('id', '') for r in v.get('references', [])]
        for affected in v.get('affects') or [{'ref': ''}]:
            ref = affected.get('ref', '')
            package = by_ref.get(ref)
            if package is None:
                unresolved += 1
                package = {**context, 'component_ref': ref, 'ecosystem': 'unknown',
                           'runtime_verified': 'not_assessed'}
            findings.append({**package, 'vulnerability': v.get('id', ''),
                'aliases': ';'.join(aliases), 'severity': severity,
                'ratings_json': json.dumps(ratings, ensure_ascii=False),
                'analysis_state': v.get('analysis', {}).get('state', ''),
                'recommendation': v.get('recommendation', ''),
                'affected_versions_json': json.dumps(affected.get('versions', [])),
                'source_url': v.get('source', {}).get('url', ''),
                'package_link_status': 'matched' if ref in by_ref else 'unresolved'})
    status = 'present' if 'vulnerabilities' in bom else 'not_provided'
    return packages, findings, status, unresolved


META = ['application_ids_json', 'application_names_json', 'application_tags_json', 'application_mapping_status', 'project_tags_json', 'scan_tags_json']
BASE = META + ['product', 'product_mapping', 'project', 'project_id', 'branch', 'scan_id', 'scan_date', 'scan_age_days']
PKG = BASE + ['component_ref', 'package', 'version', 'ecosystem', 'purl', 'scope', 'component_type', 'runtime_verified']
FIND = PKG + ['vulnerability', 'aliases', 'severity', 'ratings_json', 'analysis_state', 'recommendation', 'affected_versions_json', 'source_url', 'package_link_status']
COVER = BASE + ['status', 'latest_scan_id', 'latest_scan_status', 'newer_scan_than_selected', 'vulnerability_section', 'package_count', 'finding_count', 'unresolved_links', 'runtime_verified', 'error']


def write_csv(path, rows, fields):
    def safe(value):
        # Prevent spreadsheet formula execution when imported into Excel.
        if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@', '\t', '\r')):
            return "'" + value
        return value
    with path.open('w', encoding='utf-8-sig', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows({k: safe(v) for k, v in row.items()} for row in rows)


def matches(row, args):
    ecosystems = {x.strip().lower() for x in args.ecosystems.split(',') if x.strip()}
    ecosystems = {'npm' if x in ('node', 'nodejs') else 'pypi' if x == 'python' else x for x in ecosystems}
    return ((not ecosystems or row.get('ecosystem') in ecosystems) and
            (not args.package or args.package.lower() in row.get('package', '').lower()) and
            (not args.cve or args.cve.lower() in [x.lower() for x in [row.get('vulnerability', '')] + row.get('aliases', '').split(';')]))


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def application_context(project, applications, lookup_ok):
    by_id = {a['id']: a for a in applications}
    ids = set(project.get('applicationIds') or [])
    ids.update(a['id'] for a in applications if project['id'] in (a.get('projectIds') or []))
    ids = sorted(ids)
    complete = lookup_ok and all(i in by_id for i in ids)
    # Absence of association fields is a schema gap, not proof of no association.
    schema_known = 'applicationIds' in project or (lookup_ok and all('projectIds' in a for a in applications))
    status = ('resolved' if ids else 'unassigned') if complete and schema_known else 'partial_or_unknown'
    return {'application_ids_json': encoded(ids),
            'application_names_json': encoded({i: by_id[i].get('name', '') for i in ids if i in by_id}),
            'application_tags_json': encoded({i: by_id[i].get('tags') for i in ids if i in by_id}),
            'application_mapping_status': status,
            'project_tags_json': encoded(project.get('tags'))}


def all_scan_selections(scans):
    latest = {branch: newest for branch, newest, _ in choose_scans(scans)}
    return [(s.get('branch') or '(unknown)', latest[s.get('branch') or '(unknown)'], s)
            for s in sorted(scans, key=lambda x: parse_date(x.get('createdAt')), reverse=True)]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', default='checkmarx-output')
    p.add_argument('--config', type=Path, help='INI path; default config.ini beside this script, then environment fallback')
    p.add_argument('--project', help='Case-insensitive project name substring')
    p.add_argument('--branch', help='Exact branch; default: latest completed SCA for each observed branch')
    p.add_argument('--ecosystems', default='', help='Comma-separated purl ecosystems; npm,pypi (or nodejs,python). Default all')
    p.add_argument('--package', help='Package name substring')
    p.add_argument('--cve', help='Exact vulnerability ID or alias')
    p.add_argument('--stale-days', type=int, default=30)
    p.add_argument('--export-timeout', type=int, default=600)
    p.add_argument('--product-map', type=Path, help='CSV with project_id,product columns')
    p.add_argument('--raw-scan-report', action='store_true', help='Also download original ScanReportJson for review')
    p.add_argument('--dump-all', action='store_true', help='All visible projects, retained scans and completed SCA reports; no filters')
    args = p.parse_args()
    if args.dump_all:
        if any([args.project, args.branch, args.ecosystems, args.package, args.cve]):
            p.error('--dump-all cannot be combined with scope or finding filters')
        args.raw_scan_report = True
    if args.stale_days < 0 or args.export_timeout <= 0:
        p.error('stale-days must be >= 0 and export-timeout > 0')
    client = Client(args.config)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=False)  # Separate evidence per run; do not mix old/new exports.
    (out / 'raw').mkdir()
    product_map = {}
    if args.product_map:
        with args.product_map.open(encoding='utf-8-sig', newline='') as f:
            product_map = {r['project_id']: r['product'] for r in csv.DictReader(f)}
    projects = list(client.pages('/api/projects', 'projects'))
    projects = [x for x in projects if not args.project or args.project.lower() in x['name'].lower()]
    if not projects:
        raise ExportError('No visible projects matched; check filter and account permissions')
    metadata_errors = []
    applications = []
    apps_ok = True
    try:
        for application in client.pages('/api/applications', 'applications'):
            applications.append(application)
    except (ExportError, requests.RequestException, KeyError, ValueError) as exc:
        apps_ok = False
        metadata_errors.append({'stage': 'applications', 'error': safe_error(exc)})
    (out / 'raw' / 'applications.json').write_text(encoded(applications), encoding='utf-8')
    (out / 'raw' / 'projects.json').write_text(encoded(projects), encoding='utf-8')
    write_csv(out / 'applications.csv', [dict(application_id=a['id'], application=a.get('name', ''),
        tags_json=encoded(a.get('tags')), project_ids_json=encoded(a.get('projectIds')),
        description=a.get('description', ''), criticality=a.get('criticality', '')) for a in applications],
        ['application_id', 'application', 'tags_json', 'project_ids_json', 'description', 'criticality'])
    project_rows, links, scan_rows = [], [], []
    packages, findings, coverage = [], [], []
    now = datetime.now(timezone.utc)
    for index, project in enumerate(projects, 1):
        pid = project['id']
        print(f'Project {index}/{len(projects)}: {project["name"]}', flush=True)
        context = {'product': product_map.get(pid, project['name']),
                   'product_mapping': 'explicit' if pid in product_map else 'project_name_fallback',
                   'project': project['name'], 'project_id': pid,
                   **application_context(project, applications, apps_ok)}
        project_rows.append({**context, 'main_branch': project.get('mainBranch', ''), 'repo_url': project.get('repoUrl', '')})
        for aid in json.loads(context['application_ids_json']):
            app = next((a for a in applications if a['id'] == aid), {})
            links.append({'project_id': pid, 'project': project['name'], 'application_id': aid,
                          'application': app.get('name', ''), 'application_tags_json': encoded(app.get('tags')),
                          'project_tags_json': context['project_tags_json']})
        try:
            scans = []
            scan_path = out / 'raw' / ('scans-' + quote(str(pid), safe='') + '.jsonl')
            with scan_path.open('w', encoding='utf-8') as scan_file:
                for record in client.pages('/api/scans', 'scans', **{'project-id': pid}):
                    scans.append(record)
                    scan_file.write(encoded(record) + '\n')
                    scan_rows.append({**context, 'scan_id': record['id'], 'branch': record.get('branch', ''),
                        'scan_date': record.get('createdAt', ''), 'status': record.get('status', ''),
                        'scan_tags_json': encoded(record.get('tags')),
                        'status_details_json': encoded(record.get('statusDetails')),
                        'engines_json': encoded(record.get('engines'))})
            selections = all_scan_selections(scans) if args.dump_all else choose_scans(scans, args.branch)
        except (ExportError, requests.RequestException, KeyError, ValueError) as exc:
            coverage.append({**context, 'status': 'scan_list_error', 'error': safe_error(exc)})
            continue
        if not selections:
            coverage.append({**context, 'branch': args.branch or '', 'status': 'no_scans_in_scope'})
        for branch, latest, scan in selections:
            c = {**context, 'branch': branch, 'latest_scan_id': latest['id'],
                 'latest_scan_status': latest.get('status', ''), 'runtime_verified': 'not_assessed'}
            if not scan or not sca_completed(scan):
                coverage.append({**c, 'scan_id': scan.get('id', '') if scan else '',
                                 'scan_date': scan.get('createdAt', '') if scan else '',
                                 'scan_tags_json': encoded(scan.get('tags')) if scan else '',
                                 'status': 'no_confirmed_completed_sca'})
                continue
            age = (now - parse_date(scan.get('createdAt'))).total_seconds() / 86400
            age_valid = scan.get('createdAt') and 0 <= age < 365000
            c.update(scan_tags_json=encoded(scan.get('tags')), scan_id=scan['id'], scan_date=scan.get('createdAt', ''),
                     scan_age_days=round(age, 1) if age_valid else '',
                     newer_scan_than_selected=latest['id'] != scan['id'])
            try:
                bom = client.export(scan['id'], 'CycloneDxJson', args.export_timeout)
                # Sanitize IDs for local filenames; actual ID is preserved in context.
                stem = ''.join(ch if ch.isalnum() or ch in '-_' else '_' for ch in str(scan['id']))
                (out / 'raw' / (stem + '.cdx.json')).write_text(json.dumps(bom, indent=2), encoding='utf-8')
                pkgs, vulns, section, unresolved = flatten(bom, {k: c.get(k, '') for k in BASE})
                packages.extend(pkgs)
                findings.extend(vulns)
                c.update(status='exported' if age_valid and age <= args.stale_days else 'stale_or_unknown_date',
                         vulnerability_section=section, package_count=len(pkgs), finding_count=len(vulns), unresolved_links=unresolved)
            except (ExportError, requests.RequestException, KeyError, ValueError, TypeError) as exc:
                c.update(status='export_error', error=safe_error(exc))
            if args.raw_scan_report:
                try:
                    stem = ''.join(ch if ch.isalnum() or ch in '-_' else '_' for ch in str(scan['id']))
                    report = client.export(scan['id'], 'ScanReportJson', args.export_timeout)
                    (out / 'raw' / (stem + '.scan-report.json')).write_text(json.dumps(report, indent=2), encoding='utf-8')
                except (ExportError, requests.RequestException, KeyError, ValueError, TypeError) as exc:
                    c.update(status='export_error', error=c.get('error', '') + ' ScanReportJson: ' + safe_error(exc))
            coverage.append(c)
    write_csv(out / 'projects.csv', project_rows, ['project_id', 'project', 'product', 'product_mapping', 'main_branch', 'repo_url'] + META)
    write_csv(out / 'application_projects.csv', links, ['application_id', 'application', 'project_id', 'project', 'application_tags_json', 'project_tags_json'])
    write_csv(out / 'scans.csv', scan_rows, BASE + ['status', 'status_details_json', 'engines_json'])
    write_csv(out / 'packages.csv', packages, PKG)
    write_csv(out / 'findings.csv', findings, FIND)
    write_csv(out / 'matches.csv', [r for r in findings if matches(r, args)], FIND)
    write_csv(out / 'coverage.csv', coverage, COVER)
    summary = {'generated_at': now.isoformat(), 'visible_projects_in_scope': len(projects),
               'packages': len(packages), 'finding_rows': len(findings),
               'filters': {'ecosystems': args.ecosystems, 'package': args.package, 'cve': args.cve},
               'scope': 'All retained scans; completed SCA reports' if args.dump_all else 'Latest confirmed completed SCA scan per observed branch',
               'metadata_errors': metadata_errors, 'visible_applications': len(applications), 'scan_records': len(scan_rows),
               'metadata_time_basis': 'Application associations and project/application tags are current at export, not historical',
               'runtime_assessment': 'Not performed; npm/pypi presence does not identify deployed runtimes',
               'limitations': ['Not a production deployment inventory', 'No new scans or vulnerability recalculation are triggered',
                               'No matches does not establish absence of exposure', 'Missing vulnerability section is unknown coverage']}
    (out / 'run.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    incomplete = bool(metadata_errors) or any(r['application_mapping_status'] == 'partial_or_unknown' for r in project_rows) or any(r.get('status') != 'exported' or r.get('vulnerability_section') != 'present'
                     or r.get('unresolved_links', 0) or r.get('newer_scan_than_selected') for r in coverage)
    print(f'Saved {len(packages)} packages, {len(findings)} finding rows. Review coverage.csv. Output: {out.resolve()}')
    return 2 if incomplete else 0


def safe_error(exc):
    # requests exception text can contain a signed URL; never include it in logs/CSV.
    return str(exc) if isinstance(exc, ExportError) else type(exc).__name__


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ExportError, requests.RequestException, KeyError, ValueError, OSError) as exc:
        print('ERROR: ' + safe_error(exc), file=sys.stderr)
        sys.exit(1)
