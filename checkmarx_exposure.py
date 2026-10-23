#!/usr/bin/env python3
"""Export Checkmarx One SCA and Container Security evidence. Python 3.10+, requests. See README.md."""
import argparse
import base64
import configparser
import contextlib
import csv
import json
import os
import re
import ssl
import sys
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry

DEFAULT_CONFIG = Path(__file__).resolve().with_name('config.ini')
CONNECT_TIMEOUT, READ_TIMEOUT = 15, 120
PAGE_SIZE = 100
POLL_INTERVAL = 5  # Seconds; matches Checkmarx ast-cli export polling.
EXPORT_ENDPOINT = '/api/sca/export/requests'
RESULTS_ENDPOINT = '/api/results'  # All engines' results; ast-cli reads container findings here.
RESULTS_PAGE_SIZE = 10000  # ast-cli's page length for /api/results.
# --scan-types values -> engine names in scan statusDetails (ast-cli maps container-security too).
SCAN_TYPES = {'sca': 'sca', 'containers': 'containers', 'container': 'containers',
              'container-security': 'containers'}
REDIRECTS = (301, 302, 303, 307, 308)
SEVERITY_RANK = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1, 'none': 0}
ECOSYSTEM_ALIASES = {'node': 'npm', 'nodejs': 'npm', 'python': 'pypi'}
# Expected, recoverable failures for a single project/scan; anything else is a bug.
RECOVERABLE = (requests.RequestException, KeyError, ValueError, TypeError)
ENV_KEYS = {'base_url': 'CX_BASE_URL', 'token_url': 'CX_TOKEN_URL', 'api_key': 'CX_API_KEY',
            'client_id': 'CX_CLIENT_ID', 'client_secret': 'CX_CLIENT_SECRET',
            'verify_ssl': 'CX_VERIFY_SSL'}


class ExportError(Exception):
    pass


def safe_error(exc):
    # requests exception text can contain signed URLs or tokens; never log/CSV it.
    if isinstance(exc, ExportError):
        return str(exc)
    if isinstance(exc, requests.ConnectionError):  # Includes SSLError and ProxyError.
        # Keep host and the underlying reason (needed to diagnose TLS/proxy problems),
        # but drop request paths, query strings and proxy credentials.
        text = re.sub(r'url: \S+', 'url: <redacted>', str(exc))
        text = re.sub(r'\?[^\s\'"]*', '', text)
        text = re.sub(r'//[^/\s@]+@', '//', text)
        return f'{type(exc).__name__}: {text[:400]}'
    return type(exc).__name__


def https_url(value):
    u = urlsplit(value)
    if u.scheme != 'https' or not u.netloc or u.username or u.password or u.fragment:
        raise ExportError('Expected an HTTPS URL without embedded credentials or fragment')
    return value.rstrip('/')


def relaxed_tls_context():
    """No certificate/hostname checks and tolerant handshakes, for TLS-inspecting proxies."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.options |= getattr(ssl, 'OP_LEGACY_SERVER_CONNECT', 0x4)  # Older proxies.
    with contextlib.suppress(ValueError, ssl.SSLError):
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    with contextlib.suppress(ssl.SSLError):
        ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
    return ctx


class RelaxedTLSAdapter(HTTPAdapter):
    def __init__(self, **kwargs):
        self.ssl_context = relaxed_tls_context()
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, proxy, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        return super().proxy_manager_for(proxy, **kwargs)


def session(verify=True):
    s = requests.Session()
    # POSTs are deliberately not retried here: they can create duplicate export jobs.
    retry = Retry(total=4, backoff_factor=1, status_forcelist=[429, 502, 503, 504],
                  allowed_methods=['GET'], respect_retry_after_header=True)
    s.mount('https://', RelaxedTLSAdapter(max_retries=retry) if verify is False
            else HTTPAdapter(max_retries=retry))
    return s


def tls_verify(value):
    """verify_ssl setting -> requests verify value: True, False or a CA bundle path."""
    value = (value or '').strip()
    if value.lower() in ('', 'true', 'yes', 'on', '1'):
        return True
    if value.lower() in ('false', 'no', 'off', '0'):
        return False
    path = Path(value).expanduser()
    if not path.is_file():
        raise ExportError('verify_ssl must be true, false or the path to a CA bundle (PEM) file')
    return str(path)


def tls_mode(verify):
    return 'enabled' if verify is True else 'disabled' if verify is False else 'custom_ca_bundle'


def decode_json(content, label):
    # Checkmarx export files may start with a UTF-8 BOM (ast-cli strips it too).
    try:
        return json.loads(content.decode('utf-8-sig') if isinstance(content, bytes) else content)
    except (ValueError, UnicodeError):
        raise ExportError(f'{label}: invalid JSON') from None


def checked_json(response, label):
    if not 200 <= response.status_code < 300:
        raise ExportError(f'{label}: HTTP {response.status_code}')
    return decode_json(response.content, label)


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
    result = {key: (os.getenv(env) or values.get(key, '')).strip() for key, env in ENV_KEYS.items()}
    for key in ('base_url', 'token_url'):
        if not result[key]:
            raise ExportError(f'Missing {key}: set it in config.ini or {ENV_KEYS[key]}')
    if not result['api_key'] and not (result['client_id'] and result['client_secret']):
        raise ExportError('Set api_key in config.ini (or CX_API_KEY), or provide client_id and client_secret')
    if result['api_key'].startswith('YOUR_'):
        raise ExportError('Replace the api_key placeholder in your local config.ini')
    result['verify_ssl'] = tls_verify(result['verify_ssl'])
    return result


def token_client_id(api_key):
    """ast-cli uses the API key's azp claim as client_id, falling back to ast-app."""
    try:
        payload = api_key.split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        return claims.get('azp') or 'ast-app'
    except (ValueError, IndexError, TypeError, AttributeError):
        return 'ast-app'


class Client:
    def __init__(self, config_path=None, insecure=False):
        settings = load_settings(config_path)
        # Passed on every request: a session-level verify=False is silently
        # overridden by REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE in requests.
        self.verify = False if insecure else settings['verify_ssl']
        if self.verify is False:
            warnings.simplefilter('ignore', InsecureRequestWarning)
            print('WARNING: SSL checks are disabled (verify_ssl = false); the API key and results '
                  'are exposed to anyone able to intercept this network traffic.', file=sys.stderr)
        self.base = https_url(settings['base_url'])
        self.token_url = https_url(settings['token_url'])
        self.api_key = settings['api_key']
        self.client_id = settings['client_id']
        self.secret = settings['client_secret']
        self.http = session(self.verify)
        self.download = session(self.verify)  # Never receives a Checkmarx Authorization header.
        self.token = ''
        self.expires = 0

    def authenticate(self):
        if self.api_key:
            # The API key is a long-lived offline refresh token; it is reused for every
            # renewal, as ast-cli does, rather than replaced by a session-bound token.
            data = dict(grant_type='refresh_token', refresh_token=self.api_key,
                        client_id=self.client_id or token_client_id(self.api_key))
        else:
            data = dict(grant_type='client_credentials', client_id=self.client_id, client_secret=self.secret)
        response = self.http.post(self.token_url, data=data, allow_redirects=False, verify=self.verify,
                                  timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
        result = checked_json(response, 'Authentication')
        if not result.get('access_token'):
            raise ExportError('Authentication: no access token returned')
        self.token = result['access_token']
        self.expires = time.monotonic() + max(1, float(result.get('expires_in', 300)) - 30)

    def send(self, method, path, **kwargs):
        """Authenticated request to the configured Checkmarx origin; returns the raw response."""
        for attempt in range(2):
            if time.monotonic() >= self.expires:
                self.authenticate()
            response = self.http.request(method, self.base + path, allow_redirects=False, verify=self.verify,
                                         headers={'Authorization': 'Bearer ' + self.token},
                                         timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), **kwargs)
            if response.status_code != 401 or attempt:
                return response
            self.expires = 0  # Token revoked or expired early: renew once and retry.
        raise AssertionError('unreachable')

    def api(self, method, path, **kwargs):
        return checked_json(self.send(method, path, **kwargs), path)

    def pages(self, path, key, **params):
        offset, seen = 0, set()
        while True:
            result = self.api('GET', path, params={**params, 'limit': PAGE_SIZE, 'offset': offset})
            batch = result.get(key)
            if not isinstance(batch, list):
                raise ExportError(f'{path}: missing {key} array')
            if not batch:
                return
            fresh = [item for item in batch if item['id'] not in seen]
            if not fresh:
                # Server ignored the offset; stop instead of looping forever.
                raise ExportError(f'{path}: pagination returned only repeated IDs')
            # Records created during paging shift later pages; skip the repeats.
            for item in fresh:
                seen.add(item['id'])
                yield item
            offset += len(batch)
            total = result.get('filteredTotalCount', result.get('totalCount'))
            if isinstance(total, int) and offset >= total:
                return

    def export(self, scan_id, fmt, timeout):
        """Generate an SCA export and return the original file bytes."""
        deadline = time.monotonic() + timeout
        export_id = self._request_export(scan_id, fmt, deadline)
        while True:
            response = self.send('GET', EXPORT_ENDPOINT, params={'exportId': export_id})
            # A freshly created export can briefly be unknown (404) to the status endpoint.
            if response.status_code != 404:
                result = checked_json(response, 'Export status')
                state = str(result.get('exportStatus', '')).lower()
                if state == 'completed':
                    return self._download(export_id)
                if state == 'failed':
                    detail = str(result.get('errorMessage') or '')[:200]
                    raise ExportError('Report generation failed' + (': ' + detail if detail else ''))
                if state not in ('pending', 'exporting'):
                    raise ExportError('Unexpected export status')
            if time.monotonic() >= deadline:
                raise ExportError('Report generation timed out')
            time.sleep(POLL_INTERVAL)

    def results(self, scan_id):
        """All results of a scan from /api/results, paged the way ast-cli does (offset = page number)."""
        page, seen, results = 0, set(), []
        while True:
            body = self.api('GET', RESULTS_ENDPOINT, params={
                'scan-id': scan_id, 'limit': RESULTS_PAGE_SIZE, 'sort': '-severity', 'offset': page})
            batch = body.get('results')
            if batch is None:
                batch = []  # Checkmarx omits the array when a scan has no results.
            if not isinstance(batch, list):
                raise ExportError(f'{RESULTS_ENDPOINT}: unexpected results schema')
            if not batch:
                return results
            fresh = [r for r in batch if r.get('id') not in seen or not r.get('id')]
            if not fresh:
                raise ExportError(f'{RESULTS_ENDPOINT}: pagination returned only repeated IDs')
            for r in fresh:
                seen.add(r.get('id'))
                results.append(r)
            total = body.get('totalCount')
            if not isinstance(total, int) or len(results) >= total or len(batch) < RESULTS_PAGE_SIZE:
                return results
            page += 1

    def _request_export(self, scan_id, fmt, deadline):
        payload = {'ScanID': scan_id, 'FileFormat': fmt, 'ExportParameters': {
            'hideDevAndTestDependencies': False, 'showOnlyEffectiveLicenses': False,
            'excludePackages': False, 'excludeLicenses': False,
            'excludeVulnerabilities': False, 'excludePolicies': False}}
        while True:
            response = self.send('POST', EXPORT_ENDPOINT, json=payload)
            # 400 is returned while SCA results are not yet exportable; no job is created,
            # so retrying cannot duplicate work (ast-cli does the same).
            if response.status_code != 400 or time.monotonic() >= deadline:
                job = checked_json(response, 'Export request')
                if not job.get('exportId'):
                    raise ExportError('Export request: no exportId returned')
                return job['exportId']
            time.sleep(POLL_INTERVAL)

    def _download(self, export_id):
        path = f'{EXPORT_ENDPOINT}/{quote(str(export_id), safe="")}/download'
        response = self.send('GET', path)
        if response.status_code in REDIRECTS:
            location = urljoin(self.base + path, response.headers.get('Location', ''))
            if location.startswith(self.base + '/'):
                response = self.send('GET', location[len(self.base):])
            else:
                # Other hosts (e.g. signed storage URLs) never receive API credentials.
                response = self.download.get(https_url(location), allow_redirects=False, verify=self.verify,
                                             timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
        if response.status_code != 200:
            raise ExportError(f'Report download: HTTP {response.status_code}')
        return response.content


def field(obj, name, default=''):
    return next((v for k, v in obj.items() if k.lower() == name.lower()), default)


def engine_completed(scan, engine):
    return any(str(field(d, 'name')).lower() == engine and
               str(field(d, 'status')).lower() == 'completed'
               for d in scan.get('statusDetails') or [])


def sca_completed(scan):
    return engine_completed(scan, 'sca')


def parse_date(value):
    try:
        date = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return date if date.tzinfo else date.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError, AttributeError):
        return datetime.min.replace(tzinfo=timezone.utc)


def branch_of(scan):
    return scan.get('branch') or '(unknown)'


def newest_first(scans):
    return sorted(scans, key=lambda s: parse_date(s.get('createdAt')), reverse=True)


def choose_scans(scans, branch=None, engine='sca'):
    """Per branch: (branch, newest scan, newest scan whose engine completed, or None)."""
    groups = {}
    for scan in scans:
        if branch is None or branch_of(scan) == branch:
            groups.setdefault(branch_of(scan), []).append(scan)
    chosen = []
    for name, items in sorted(groups.items()):
        items = newest_first(items)
        chosen.append((name, items[0], next((s for s in items if engine_completed(s, engine)), None)))
    return chosen


def all_scan_selections(scans):
    """Every scan, newest first, with its branch's newest scan for comparison."""
    latest = {name: newest for name, newest, _ in choose_scans(scans)}
    return [(branch_of(s), latest[branch_of(s)], s) for s in newest_first(scans)]


def components(items):
    for c in items:
        yield c
        yield from components(c.get('components') or [])


def flatten(bom, context):
    if bom.get('bomFormat') != 'CycloneDX' or not isinstance(bom.get('components'), list):
        raise ExportError('Unexpected SBOM schema: expected CycloneDX components array')
    packages, findings, by_ref = [], [], {}
    for c in components(bom['components']):
        purl = c.get('purl', '')
        ref = c.get('bom-ref', '')
        row = {**context, 'component_ref': ref, 'version': c.get('version', ''),
               'package': '/'.join(filter(None, [c.get('group'), c.get('name')])),
               'ecosystem': purl[4:].split('/', 1)[0] if purl.startswith('pkg:') else 'unknown',
               'purl': purl, 'scope': c.get('scope', ''), 'component_type': c.get('type', ''),
               'runtime_verified': 'not_assessed'}
        packages.append(row)
        if ref:
            by_ref[ref] = row
    vulnerabilities = bom.get('vulnerabilities', [])
    if not isinstance(vulnerabilities, list):
        raise ExportError('Unexpected vulnerabilities schema')
    unresolved = 0
    for v in vulnerabilities:
        ratings = v.get('ratings') or []
        severity = max((str(r.get('severity') or 'unknown').lower() for r in ratings),
                       key=lambda s: SEVERITY_RANK.get(s, -1), default='unknown')
        details = {'vulnerability': v.get('id', ''),
                   'aliases': ';'.join(r.get('id', '') for r in v.get('references') or []),
                   'severity': severity, 'ratings_json': json.dumps(ratings, ensure_ascii=False),
                   'analysis_state': (v.get('analysis') or {}).get('state', ''),
                   'recommendation': v.get('recommendation', ''),
                   'source_url': (v.get('source') or {}).get('url', '')}
        for affected in v.get('affects') or [{'ref': ''}]:
            ref = affected.get('ref', '')
            package = by_ref.get(ref)
            if package is None:
                unresolved += 1
                package = {**context, 'component_ref': ref, 'ecosystem': 'unknown',
                           'runtime_verified': 'not_assessed'}
            findings.append({**package, **details,
                             'affected_versions_json': json.dumps(affected.get('versions', [])),
                             'package_link_status': 'matched' if ref in by_ref else 'unresolved'})
    status = 'present' if 'vulnerabilities' in bom else 'not_provided'
    return packages, findings, status, unresolved


def container_findings(results, context):
    """Container Security rows (result type "containers") from /api/results, one per finding."""
    rows = []
    for r in results:
        if str(r.get('type', '')).lower() != 'containers':
            continue
        data = r.get('data') or {}
        details = r.get('vulnerabilityDetails') or {}
        recommended = data.get('recommendedVersion')
        rows.append({**context, 'result_id': r.get('id', ''), 'similarity_id': r.get('similarityId', ''),
                     'image_name': data.get('imageName', ''), 'image_tag': data.get('imageTag', ''),
                     'image_file_path': data.get('imageFilePath', ''), 'image_origin': data.get('imageOrigin', ''),
                     'package': data.get('packageName', ''), 'version': data.get('packageVersion', ''),
                     'package_identifier': data.get('packageIdentifier', ''),
                     'vulnerability': details.get('cveName') or data.get('queryName') or '',
                     'aliases': data.get('queryName', '') if details.get('cveName') else '',
                     'cwe': details.get('cweId') or '', 'cvss_score': details.get('cvssScore', ''),
                     'severity': str(r.get('severity') or 'unknown').lower(),
                     'state': r.get('state', ''), 'status': r.get('status', ''),
                     'first_found_at': r.get('firstFoundAt', ''), 'found_at': r.get('foundAt', ''),
                     'recommended_version': recommended if isinstance(recommended, str) else
                     (encoded(recommended) if recommended else ''),
                     'description': r.get('description', ''), 'runtime_verified': 'not_assessed'})
    return rows


META = ['application_ids_json', 'application_names_json', 'application_tags_json', 'application_mapping_status', 'project_tags_json', 'scan_tags_json']
BASE = META + ['product', 'product_mapping', 'project', 'applications', 'project_id', 'branch', 'scan_id', 'scan_date', 'scan_age_days']
PKG = BASE + ['component_ref', 'package', 'version', 'ecosystem', 'purl', 'scope', 'component_type', 'runtime_verified']
FIND = PKG + ['vulnerability', 'aliases', 'severity', 'ratings_json', 'analysis_state', 'recommendation', 'affected_versions_json', 'source_url', 'package_link_status']
CONTAINER = BASE + ['result_id', 'similarity_id', 'image_name', 'image_tag', 'image_file_path', 'image_origin', 'package', 'version', 'package_identifier', 'vulnerability', 'aliases', 'cwe', 'cvss_score', 'severity', 'state', 'status', 'first_found_at', 'found_at', 'recommended_version', 'description', 'runtime_verified']
COVER = BASE + ['scan_type', 'scan_role', 'status', 'latest_scan_id', 'latest_scan_status', 'newer_scan_than_selected', 'vulnerability_section', 'package_count', 'finding_count', 'unresolved_links', 'runtime_verified', 'error']
PROJECT_FIELDS = ['project_id', 'project', 'applications', 'product', 'product_mapping', 'main_branch', 'repo_url', 'groups_json'] + META
LINK_FIELDS = ['application_id', 'application', 'project_id', 'project', 'application_tags_json', 'project_tags_json']
SCAN_FIELDS = BASE + ['status', 'status_details_json', 'engines_json']
APP_FIELDS = ['application_id', 'application', 'tags_json', 'project_ids_json', 'description', 'criticality']


def spreadsheet_safe(value):
    # Prevent spreadsheet formula execution when imported into Excel.
    if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@', '\t', '\r')):
        return "'" + value
    return value


class CsvWriter:
    """Streams rows to disk so large tenants are not held in memory."""

    def __init__(self, path, fields):
        self.file = path.open('w', encoding='utf-8-sig', newline='')
        self.writer = csv.DictWriter(self.file, fieldnames=fields, extrasaction='ignore')
        self.writer.writeheader()
        self.count = 0

    def write(self, rows):
        for row in rows:
            self.writer.writerow({k: spreadsheet_safe(v) for k, v in row.items()})
            self.count += 1

    def close(self):
        self.file.close()


def write_csv(path, rows, fields):
    writer = CsvWriter(path, fields)
    try:
        writer.write(rows)
    finally:
        writer.close()


def finding_filter(args):
    """Build the matches.csv predicate once (ecosystem AND package AND CVE)."""
    ecosystems = {x.strip().lower() for x in (args.ecosystems or '').split(',') if x.strip()}
    ecosystems = {ECOSYSTEM_ALIASES.get(x, x) for x in ecosystems}
    package = (args.package or '').lower()
    cve = (args.cve or '').lower()

    def matches(row):
        ids = [row.get('vulnerability', '')] + row.get('aliases', '').split(';')
        return ((not ecosystems or row.get('ecosystem') in ecosystems) and
                (not package or package in row.get('package', '').lower()) and
                (not cve or cve in (x.lower() for x in ids)))
    return matches


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


class ApplicationIndex:
    def __init__(self, applications, complete=True):
        self.complete = complete
        self.by_id = {a['id']: a for a in applications}
        self.by_project = {}
        for a in applications:
            for pid in a.get('projectIds') or []:
                self.by_project.setdefault(pid, set()).add(a['id'])
        self.all_have_project_ids = all('projectIds' in a for a in applications)


def application_context(project, index):
    ids = sorted(set(project.get('applicationIds') or []) | index.by_project.get(project['id'], set()))
    apps = {i: index.by_id[i] for i in ids if i in index.by_id}
    complete = index.complete and len(apps) == len(ids)
    # Absence of association fields is a schema gap, not proof of no association.
    schema_known = 'applicationIds' in project or (index.complete and index.all_have_project_ids)
    status = ('resolved' if ids else 'unassigned') if complete and schema_known else 'partial_or_unknown'
    # Readable names for spreadsheets; the *_json columns stay authoritative (names can repeat).
    names = sorted(str(a.get('name') or i) for i, a in apps.items())
    return {'applications': '; '.join(names),
            'application_ids_json': encoded(ids),
            'application_names_json': encoded({i: a.get('name', '') for i, a in apps.items()}),
            'application_tags_json': encoded({i: a.get('tags') for i, a in apps.items()}),
            'application_mapping_status': status,
            'project_tags_json': encoded(project.get('tags'))}


def project_filter(args, apps):
    """Project selection: each option type must match (AND); repeats of one option are alternatives (OR)."""
    def fold(values):
        return [v.strip().lower() for v in values or [] if v.strip()]
    tags = [tuple(t.split('=', 1)) if '=' in t else (t, None) for t in fold(args.tag)]
    wanted_apps, groups = fold(args.application), fold(args.group)
    ids = set(project_ids(args))

    def tag_match(project):
        have = {str(k).lower(): str(v or '').lower() for k, v in (project.get('tags') or {}).items()}
        return any(k in have and (v is None or have[k] == v) for k, v in tags)

    def app_match(project):
        ids = set(project.get('applicationIds') or []) | apps.by_project.get(project['id'], set())
        names = {str(i).lower() for i in ids} | {str(apps.by_id[i].get('name', '')).lower() for i in ids if i in apps.by_id}
        return bool(names & set(wanted_apps))

    def matches(project):
        return ((not ids or str(project['id']).lower() in ids) and
                (not args.project or args.project.lower() in project['name'].lower()) and
                (not tags or tag_match(project)) and
                (not wanted_apps or app_match(project)) and
                (not groups or bool({str(g).lower() for g in project.get('groups') or []} & set(groups))))
    return matches


def project_ids(args):
    """--project-id values (repeatable, comma-separated), lower-cased."""
    return [x.strip().lower() for v in getattr(args, 'project_id', None) or [] for x in v.split(',') if x.strip()]


def load_project_ids(path):
    """Project IDs from a CSV: the project_id (or id) column if there is a header, else the first column."""
    with path.open(encoding='utf-8-sig', newline='') as f:
        rows = [[cell.strip() for cell in row] for row in csv.reader(f)]
    rows = [r for r in rows if any(r)]
    column = 0
    if rows:
        names = [c.lower().replace(' ', '_') for c in rows[0]]
        header = next((n for n in ('project_id', 'projectid', 'id') if n in names), None)
        if header:
            column, rows = names.index(header), rows[1:]
    return [r[column] for r in rows if len(r) > column and r[column]]


def file_stem(identifier):
    # Sanitize IDs for local filenames; the actual ID is preserved in CSV context.
    return ''.join(ch if ch.isalnum() or ch in '-_' else '_' for ch in str(identifier))


def load_product_map(path):
    if not path:
        return {}
    with path.open(encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        if not {'project_id', 'product'} <= set(reader.fieldnames or []):
            raise ExportError('Product map must have project_id and product columns')
        return {r['project_id'].strip(): r['product'].strip() for r in reader if r['project_id']}


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', default='checkmarx-output')
    p.add_argument('--config', type=Path, help='INI path; default config.ini beside this script, then environment fallback')
    p.add_argument('--insecure', action='store_true',
                   help='Turn off all SSL checks for this run (same as verify_ssl = false)')
    p.add_argument('--project', help='Case-insensitive project name substring')
    p.add_argument('--project-id', action='append', metavar='ID[,ID...]',
                   help='Exact Checkmarx project ID; repeat or comma-separate for several')
    p.add_argument('--project-ids-file', type=Path, metavar='FILE.csv',
                   help='CSV of project IDs (project_id/id column, or first column without a header)')
    p.add_argument('--scan-types', default='sca', metavar='TYPES',
                   help='Comma-separated results to export: sca, containers (or container-security). Default sca')
    p.add_argument('--tag', action='append', metavar='KEY[=VALUE]',
                   help='Project tag key, or exact key=value; repeat for alternatives (case-insensitive)')
    p.add_argument('--application', action='append', metavar='NAME_OR_ID',
                   help='Exact application name or ID; repeat for alternatives (case-insensitive)')
    p.add_argument('--group', action='append', metavar='GROUP',
                   help='Project group as returned by the API; repeat for alternatives (case-insensitive)')
    p.add_argument('--branch', help='Exact branch; default: latest completed scan of each type for each observed branch')
    p.add_argument('--ecosystems', default='', help='Comma-separated purl ecosystems; npm,pypi (or nodejs,python). Default all')
    p.add_argument('--package', help='Package name substring')
    p.add_argument('--cve', help='Exact vulnerability ID or alias')
    p.add_argument('--stale-days', type=int, default=30)
    p.add_argument('--export-timeout', type=int, default=600, help='Seconds allowed per report export')
    p.add_argument('--product-map', type=Path, help='CSV with project_id,product columns')
    p.add_argument('--raw-scan-report', action='store_true', help='Also download original ScanReportJson for review')
    p.add_argument('--dump-all', action='store_true',
                   help='All retained scans and their completed reports; project filters allowed, branch/finding filters not')
    args = p.parse_args(argv)
    requested = [x.strip().lower() for x in args.scan_types.split(',') if x.strip()]
    unknown = [x for x in requested if x not in SCAN_TYPES]
    if not requested or unknown:
        p.error('--scan-types takes sca and/or containers (container-security)')
    args.engines = list(dict.fromkeys(SCAN_TYPES[x] for x in requested))
    if args.project_ids_file:
        try:
            from_file = load_project_ids(args.project_ids_file)
        except (OSError, UnicodeError, csv.Error):
            p.error('--project-ids-file cannot be read; check the path and that it is a UTF-8 CSV')
        if not from_file:
            p.error('--project-ids-file contains no project IDs')
        args.project_id = (args.project_id or []) + from_file
    if args.dump_all:
        if any([args.branch, args.ecosystems, args.package, args.cve]):
            p.error('--dump-all cannot be combined with --branch or finding filters')
        args.raw_scan_report = True
    if args.stale_days < 0 or args.export_timeout <= 0:
        p.error('stale-days must be >= 0 and export-timeout > 0')
    return args


class Exporter:
    def __init__(self, client, args, out, csvs):
        self.client, self.args, self.out, self.csv = client, args, out, csvs
        self.raw = out / 'raw'
        self.now = datetime.now(timezone.utc)
        self.matches = finding_filter(args)
        # --ecosystems describes purl ecosystems, which container results do not carry.
        self.container_matches = finding_filter(argparse.Namespace(ecosystems='', package=args.package, cve=args.cve))
        self.coverage, self.project_rows = [], []

    def run_project(self, project, product_map, apps):
        pid = project['id']
        context = {'product': product_map.get(pid, project['name']),
                   'product_mapping': 'explicit' if pid in product_map else 'project_name_fallback',
                   'project': project['name'], 'project_id': pid, **application_context(project, apps)}
        self.project_rows.append({**context, 'main_branch': project.get('mainBranch', ''),
                                  'groups_json': encoded(project.get('groups')),
                                  'repo_url': project.get('repoUrl', '')})
        self.csv['application_projects'].write(
            {'project_id': pid, 'project': project['name'], 'application_id': aid,
             'application': apps.by_id.get(aid, {}).get('name', ''),
             'application_tags_json': encoded(apps.by_id.get(aid, {}).get('tags')),
             'project_tags_json': context['project_tags_json']}
            for aid in json.loads(context['application_ids_json']))
        try:
            scans = self.fetch_scans(pid, context)
        except (ExportError, *RECOVERABLE) as exc:
            self.coverage.append({**context, 'status': 'scan_list_error', 'error': safe_error(exc)})
            return
        for engine in self.args.engines:
            current = {name: chosen['id'] for name, _, chosen in choose_scans(scans, engine=engine) if chosen}
            selections = (all_scan_selections(scans) if self.args.dump_all
                          else choose_scans(scans, self.args.branch, engine))
            if not selections:
                self.coverage.append({**context, 'scan_type': engine, 'branch': self.args.branch or '',
                                      'status': 'no_scans_in_scope'})
            for branch, latest, scan in selections:
                role = 'current' if scan and current.get(branch) == scan['id'] else 'historical'
                self.coverage.append(self.export_scan({**context, 'scan_type': engine, 'branch': branch,
                    'scan_role': role, 'latest_scan_id': latest['id'], 'latest_scan_status': latest.get('status', ''),
                    'runtime_verified': 'not_assessed'}, latest, scan, engine))

    def fetch_scans(self, pid, context):
        scans = []
        with (self.raw / f'scans-{quote(str(pid), safe="")}.jsonl').open('w', encoding='utf-8') as raw:
            for record in self.client.pages('/api/scans', 'scans', **{'project-id': pid}):
                scans.append(record)
                raw.write(encoded(record) + '\n')
                self.csv['scans'].write([{**context, 'scan_id': record['id'], 'branch': record.get('branch', ''),
                    'scan_date': record.get('createdAt', ''), 'status': record.get('status', ''),
                    'scan_tags_json': encoded(record.get('tags')),
                    'status_details_json': encoded(record.get('statusDetails')),
                    'engines_json': encoded(record.get('engines'))}])
        return scans

    def export_scan(self, c, latest, scan, engine='sca'):
        if not scan or not engine_completed(scan, engine):
            return {**c, 'scan_id': scan.get('id', '') if scan else '',
                    'scan_date': scan.get('createdAt', '') if scan else '',
                    'scan_tags_json': encoded(scan.get('tags')) if scan else '',
                    'status': f'no_confirmed_completed_{engine}'}
        age = (self.now - parse_date(scan.get('createdAt'))).total_seconds() / 86400
        age_valid = bool(scan.get('createdAt')) and 0 <= age < 365000
        c.update(scan_tags_json=encoded(scan.get('tags')), scan_id=scan['id'], scan_date=scan.get('createdAt', ''),
                 scan_age_days=round(age, 1) if age_valid else '',
                 newer_scan_than_selected=latest['id'] != scan['id'])
        fresh = 'exported' if age_valid and age <= self.args.stale_days else 'stale_or_unknown_date'
        if engine == 'containers':
            return self.export_containers(c, scan, fresh)
        stem = file_stem(scan['id'])
        errors = []
        try:
            content = self.client.export(scan['id'], 'CycloneDxJson', self.args.export_timeout)
            (self.raw / f'{stem}.cdx.json').write_bytes(content)  # Original evidence, unmodified.
            pkgs, vulns, section, unresolved = flatten(decode_json(content, 'CycloneDX'),
                                                       {k: c.get(k, '') for k in BASE})
            self.csv['packages'].write(pkgs)
            self.csv['findings'].write(vulns)
            self.csv['matches'].write(r for r in vulns if self.matches(r))
            c.update(status=fresh, vulnerability_section=section, package_count=len(pkgs), finding_count=len(vulns),
                     unresolved_links=unresolved)
        except (ExportError, *RECOVERABLE) as exc:
            errors.append('CycloneDxJson: ' + safe_error(exc))
        if self.args.raw_scan_report:
            try:
                content = self.client.export(scan['id'], 'ScanReportJson', self.args.export_timeout)
                (self.raw / f'{stem}.scan-report.json').write_bytes(content)
            except (ExportError, *RECOVERABLE) as exc:
                errors.append('ScanReportJson: ' + safe_error(exc))
        if errors:
            c.update(status='export_error', error='; '.join(errors))
        return c

    def export_containers(self, c, scan, fresh):
        try:
            results = self.client.results(scan['id'])
            containers = [r for r in results if str(r.get('type', '')).lower() == 'containers']
            # Original container result records, unmodified; other engines' results are left out.
            (self.raw / f'{file_stem(scan["id"])}.containers.json').write_text(
                encoded({'scanId': scan['id'], 'results': containers}), encoding='utf-8')
            rows = container_findings(containers, {k: c.get(k, '') for k in BASE})
            self.csv['container_findings'].write(rows)
            self.csv['container_matches'].write(r for r in rows if self.container_matches(r))
            c.update(status=fresh, vulnerability_section='present', finding_count=len(rows),
                     package_count=len({(r['image_name'], r['image_tag'], r['package'], r['version']) for r in rows}),
                     unresolved_links=0)
        except (ExportError, *RECOVERABLE) as exc:
            c.update(status='export_error', error='Containers results: ' + safe_error(exc))
        return c


def coverage_gap(row):
    """Whether a coverage row should make the run exit 2 (needs review)."""
    if row.get('status') == 'export_error' or row.get('status') == 'scan_list_error':
        return True
    if row.get('scan_role') == 'historical':
        return False  # Older scans in --dump-all are evidence, not current exposure.
    return (row.get('status') != 'exported' or row.get('vulnerability_section') != 'present'
            or bool(row.get('unresolved_links')) or bool(row.get('newer_scan_than_selected')))


def main(argv=None):
    args = parse_args(argv)
    client = Client(args.config, insecure=args.insecure)
    product_map = load_product_map(args.product_map)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=False)  # Separate evidence per run; do not mix old/new exports.
    (out / 'raw').mkdir()
    metadata_errors, applications = [], []
    try:
        applications.extend(client.pages('/api/applications', 'applications'))
        apps = ApplicationIndex(applications)
    except (ExportError, *RECOVERABLE) as exc:
        if args.application:
            raise ExportError('Cannot filter by --application: application list unavailable '
                              f'({safe_error(exc)})') from None
        # Project export continues; mappings are then flagged partial_or_unknown.
        metadata_errors.append({'stage': 'applications', 'error': safe_error(exc)})
        apps = ApplicationIndex([a for a in applications if 'id' in a], complete=False)
    selected = project_filter(args, apps)
    projects = [x for x in client.pages('/api/projects', 'projects') if selected(x)]
    if not projects:
        raise ExportError('No visible projects matched; check filters and account permissions')
    missing = sorted(set(project_ids(args)) - {str(x['id']).lower() for x in projects})
    if missing:
        # Mistyped, deleted, outside the API identity's permissions, or excluded by other filters.
        print(f'WARNING: {len(missing)} --project-id value(s) not exported: {", ".join(missing)}', file=sys.stderr)
        metadata_errors.append({'stage': 'project_ids', 'error': 'Not visible or excluded by other filters',
                                'project_ids': missing})
    (out / 'raw' / 'applications.json').write_text(encoded(applications), encoding='utf-8')
    (out / 'raw' / 'projects.json').write_text(encoded(projects), encoding='utf-8')
    write_csv(out / 'applications.csv', (dict(application_id=a['id'], application=a.get('name', ''),
        tags_json=encoded(a.get('tags')), project_ids_json=encoded(a.get('projectIds')),
        description=a.get('description', ''), criticality=a.get('criticality', ''))
        for a in apps.by_id.values()), APP_FIELDS)

    with contextlib.ExitStack() as stack:
        csvs = {}
        for name, fields in [('application_projects', LINK_FIELDS), ('scans', SCAN_FIELDS),
                             ('packages', PKG), ('findings', FIND), ('matches', FIND),
                             ('container_findings', CONTAINER), ('container_matches', CONTAINER)]:
            csvs[name] = CsvWriter(out / f'{name}.csv', fields)
            stack.callback(csvs[name].close)
        exporter = Exporter(client, args, out, csvs)
        for index, project in enumerate(projects, 1):
            print(f'Project {index}/{len(projects)}: {project["name"]}', flush=True)
            exporter.run_project(project, product_map, apps)
    write_csv(out / 'projects.csv', exporter.project_rows, PROJECT_FIELDS)
    write_csv(out / 'coverage.csv', exporter.coverage, COVER)

    summary = {'generated_at': exporter.now.isoformat(), 'visible_projects_in_scope': len(projects),
               'scan_types': args.engines,
               'packages': csvs['packages'].count, 'finding_rows': csvs['findings'].count,
               'container_finding_rows': csvs['container_findings'].count,
               'filters': {'ecosystems': args.ecosystems, 'package': args.package, 'cve': args.cve},
               'project_filters': {'project_id': project_ids(args) or None, 'project': args.project, 'tag': args.tag, 'application': args.application,
                                   'group': args.group, 'branch': args.branch},
               'scope': ('All retained scans; completed reports per scan type' if args.dump_all
                         else 'Latest confirmed completed scan per scan type and observed branch'),
               'metadata_errors': metadata_errors, 'visible_applications': len(applications),
               'scan_records': csvs['scans'].count,
               'metadata_time_basis': 'Application associations and project/application tags are current at export, not historical',
               'tls_verification': tls_mode(client.verify),
               'runtime_assessment': 'Not performed; npm/pypi presence does not identify deployed runtimes',
               'limitations': ['Not a production deployment inventory', 'No new scans or vulnerability recalculation are triggered',
                               'No matches does not establish absence of exposure', 'Missing vulnerability section is unknown coverage']}
    (out / 'run.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    incomplete = (bool(metadata_errors) or any(coverage_gap(r) for r in exporter.coverage)
                  or any(r['application_mapping_status'] == 'partial_or_unknown' for r in exporter.project_rows))
    print(f'Saved {csvs["packages"].count} packages, {csvs["findings"].count} SCA finding rows, '
          f'{csvs["container_findings"].count} container finding rows. '
          f'Review coverage.csv. Output: {out.resolve()}')
    return 2 if incomplete else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ExportError, requests.RequestException, KeyError, ValueError, OSError) as exc:
        print('ERROR: ' + safe_error(exc), file=sys.stderr)
        sys.exit(1)
