# Checkmarx One product exposure exporter — v2

## Full dump with applications and tags

After configuring credentials below, run:

```powershell
python checkmarx_exposure.py --dump-all --out checkmarx-full-dump
```

This includes all visible projects and applications, all retained scan metadata,
and both CycloneDX and original SCA JSON reports for every scan with a confirmed
completed SCA engine. All package ecosystems, severities and dependency scopes are
included. Failed/incomplete/non-SCA scans remain in scans.csv and coverage.csv;
they cannot supply completed SCA reports. Project selection filters (--project, --tag,
--application, --group) can be combined with --dump-all; --branch and finding filters cannot.

This is a full **SCA exposure dump plus application/project/scan metadata**, not a
backup of source code or SAST/DAST/container finding details. Deleted or expired
records and data outside the API identity's permissions are unavailable.
Historical scans can make this substantially slower than the default latest-scan
mode and create repeated package/finding rows across scan IDs. In coverage.csv,
`scan_role` is `current` for each branch's newest completed SCA scan and
`historical` for older scans; historical rows only affect the exit code when their
export fails, so a full dump is not flagged merely because old scans are stale. No resume mode is
implemented; retain completed raw files if a run is interrupted.

New exports:

| File | Contents |
| --- | --- |
| applications.csv | Application IDs, names, tags, descriptions, criticality and project IDs |
| projects.csv | Project inventory, project tags and associated applications |
| application_projects.csv | One row per application/project association |
| scans.csv | All retrieved scan metadata, statuses, engine statuses and scan tags |
| raw/applications.json | Original application list records |
| raw/projects.json | Original project list records |
| raw/scans-PROJECT_ID.jsonl | Original scan records, saved as retrieved |

Every scans, packages, findings, matches, coverage and projects row carries the
project name (`project`) and its application names (`applications`, plain text
separated by `; `, empty when unassigned) for easy filtering in Excel/Power BI.
Application IDs/names/tags and project/scan tags also accompany package and finding
rows. Tags stay as JSON to preserve keys, empty values and differing tags at each
level. Application name/tag objects are keyed by application ID; memberships do
not duplicate findings. Use application_projects.csv as a bridge in Power BI.
Associations are joined from application projectIds and project applicationIds,
not guessed from names or locally re-evaluated rules. Missing schemas, inaccessible
applications and unresolved IDs are flagged, and application retrieval errors are
recorded in run.json. Project export continues when application retrieval fails.

Application memberships and project/application tags reflect the **current export
snapshot**, not their historical state at scan time. Scan tags are the values
returned on the scan record. An explicit product-map still determines product;
applications are separate fields because one project may belong to multiple apps.

The default mode still exports only the latest completed SCA scan per branch;
application and tag enrichment is enabled in both modes.


Identify projects containing dependencies that Checkmarx reports as vulnerable.
Python 3.10 or newer; Windows, Linux or macOS.

## What it does

- Enumerates all projects visible to your API identity (or a name filter).
- Paginates scan history and selects the newest scan whose SCA engine explicitly
  completed, separately for every observed branch, or one exact branch you select.
- Generates CycloneDX JSON through the SCA Export Service and joins vulnerability
  `affects.ref` values to component `bom-ref` values. It does not guess affected
  versions or infer CVEs from language names.
- Includes development/test dependencies; preserves available scope and analysis state.
- Writes the original SBOM, packages.csv, findings.csv, matches.csv, coverage.csv,
  and run.json. Optionally exports the vendor's ScanReportJson as additional evidence.
- Does not start scans, modify findings, or change project settings. POST requests
  authenticate and generate exports only.

**This identifies reported dependency exposure, not verified production exposure.**
An npm dependency is not evidence of a particular deployed Node.js version, nor is
an installed Python package evidence of a particular Python interpreter version.
For Node.js/Python interpreter advisories, separately collect exact runtime versions
from deployed hosts or container image inventories and evaluate the advisory's
version ranges. This exporter does not perform that runtime assessment.

## Config file (recommended)

Copy the template and edit the local file:

```powershell
Copy-Item config.example.ini config.ini
notepad config.ini
```

Set `base_url`, `token_url` (including your tenant), and `api_key` under
`[checkmarx]`. Use the full API key token, not its portal Key ID. Values must be
on one line without quotes. The URLs in the example are EU examples; use your
actual region. No credentials need to be entered in the source code.

```powershell
python -m pip install -r requirements.txt
python checkmarx_exposure.py --dump-all --out checkmarx-full-dump
```

The script automatically reads `config.ini` beside `checkmarx_exposure.py`,
regardless of your terminal's working directory. For another path:

```powershell
python checkmarx_exposure.py --config "C:\Secure\checkmarx.ini" --dump-all --out checkmarx-full-dump
```

**Non-empty CX_* environment variables override corresponding config values.**
If settings seem stale, clear those environment variables or update them.
Without the default file, the previous environment-only setup still works.
An explicitly requested missing/malformed config file produces an error.
For OAuth client credentials, leave `api_key` empty and populate `client_id` and
`client_secret`; also clear CX_API_KEY if it was previously set.

The local file stores your key in plaintext. Restrict access to your account.
All `*.ini` files are ignored by Git except `config.example.ini`, which must
contain placeholders only. Do not force-add a real config to this public repo.
The config and key are never copied into exported reports or error messages.

## Environment variables (alternative)

Install the dependency:

```powershell
python -m pip install -r requirements.txt
```

Set your actual regional Checkmarx API origin and full token endpoint. Copy them
from your Checkmarx integration configuration; the examples below are EU examples,
not a determination of your tenant's location. The token URL includes the tenant.
Do not append `/api` to CX_BASE_URL.

```powershell
$env:CX_BASE_URL = "https://eu.ast.checkmarx.net"
$env:CX_TOKEN_URL = "https://eu.iam.checkmarx.net/auth/realms/YOUR_TENANT/protocol/openid-connect/token"
$env:CX_API_KEY = Read-Host "Checkmarx API key" -MaskInput
```

`-MaskInput` requires PowerShell 7.1+. On Windows PowerShell 5.1, use:

```powershell
$secret = Read-Host "Checkmarx API key" -AsSecureString
$env:CX_API_KEY = [System.Net.NetworkCredential]::new("", $secret).Password
```

Alternatively, omit CX_API_KEY and supply CX_CLIENT_ID and CX_CLIENT_SECRET for an
OAuth service client. If both methods are configured, CX_API_KEY takes precedence.
For API key authentication, CX_CLIENT_ID can override the key's azp/default ast-app.
Access tokens renew during a run. Credentials are not written into outputs.
Use an identity authorized to read the required projects/scans and generate SCA
exports. SCA must be licensed/enabled and scans must have usable SCA results.

Linux/macOS:

```bash
export CX_BASE_URL='https://eu.ast.checkmarx.net'
export CX_TOKEN_URL='https://eu.iam.checkmarx.net/auth/realms/YOUR_TENANT/protocol/openid-connect/token'
read -rsp 'Checkmarx API key: ' CX_API_KEY
export CX_API_KEY
```

TLS verification is enabled by default. SSL errors such as
`CERTIFICATE_VERIFY_FAILED` usually mean a corporate proxy or firewall re-signs
HTTPS traffic with your organization's own CA. Preferred fix: export that root CA
as a PEM file (ask IT, or export it from your browser's certificate viewer) and set

```ini
verify_ssl = C:\Secure\corporate-root-ca.pem
```

in `config.ini` (or CX_VERIFY_SSL). Configure HTTPS_PROXY if a proxy is required.

**Simplest option on a trusted PC: turn SSL checks off.** Add this one line under
`[checkmarx]` in your local `config.ini`:

```ini
verify_ssl = false
```

(or set it once for your Windows user with `setx CX_VERIFY_SSL false` and open a new
terminal, or pass `--insecure` for a single run). This skips certificate and
hostname checks and also accepts older TLS handshakes used by some corporate
proxies. A warning is printed and `run.json` records `tls_verification: disabled`.
Anyone able to intercept the traffic could capture your API key and exported data,
so rotate the key if the network later turns out to be untrusted. The setting only
affects machines whose config/environment sets it; the default stays verified.

If an SSL error persists with `verify_ssl = false`:
- No `WARNING: TLS certificate verification is disabled` line at startup means the
  setting was not applied: check you are running this version of the script, that
  the line is under `[checkmarx]` in the config actually used, and that
  CX_VERIFY_SSL is not set to another value (environment values win).
- Errors print the underlying reason (paths and secrets redacted). `WRONG_VERSION_NUMBER`
  or a `ProxyError` usually means a wrong HTTPS_PROXY value (for example `https://`
  where the proxy expects `http://`); check HTTPS_PROXY/NO_PROXY with your network team.

## Run

Start with one product to validate access and output:

```powershell
python checkmarx_exposure.py --project "Product A" --ecosystems npm,pypi --raw-scan-report --out pilot
```

Then export all visible projects:

```powershell
python checkmarx_exposure.py --ecosystems npm,pypi --out all-products
```

Search an exact CVE (replace the illustrative ID):

```powershell
python checkmarx_exposure.py --cve CVE-YYYY-NNNNN --out cve-review
```

Search vulnerable instances of a package:

```powershell
python checkmarx_exposure.py --package django --ecosystems pypi --out django-review
```

Select projects by tag, application or group:

```powershell
# Projects tagged team=payments (exact key=value) or having a "pci" tag (any value)
python checkmarx_exposure.py --tag team=payments --tag pci --out tagged
# Projects in the "Mobile Banking" application (name or ID), npm findings only
python checkmarx_exposure.py --application "Mobile Banking" --ecosystems npm --out mobile-npm
# Full history for one group
python checkmarx_exposure.py --dump-all --group "GROUP_FROM_PROJECTS_CSV" --out group-dump
```

Matching is case-insensitive. Repeating the same option means *any of* (OR); different
options must all match (AND), together with --project. `--application` matches the
exact application name or ID; it stops with an error if applications cannot be read,
rather than silently exporting the wrong set. `--group` matches the values in the
project's `groups` field as returned by the API (often group IDs); see the
`groups_json` column of projects.csv from an earlier run for the exact values. Filtering
is done locally after listing all visible projects, so it uses exactly these rules.

Restrict to a known release branch if appropriate:

```powershell
python checkmarx_exposure.py --branch release/2026.1 --out release-review
```

Each --out directory must be new. This prevents old exports mixing with a later run.
No branch is implicitly assumed to be production. Without --branch, every observed
branch is included, so old feature branches can legitimately be marked stale.
Fetching full scan history can take time on large tenants; --project is useful
for a pilot. Deleted/retained-out scans cannot be recovered by this script.

## Map technical projects to business products

Provide a CSV with exact project UUIDs (multiple projects may map to one product):

```csv
project_id,product
REPLACE_WITH_PROJECT_UUID,Product A
```

Use `--product-map products.csv`. Without a mapping, the project name is used and
`product_mapping` is explicitly `project_name_fallback`. The script does not assume
that a Checkmarx project or application necessarily equals a commercial product.

## Read the outputs

| File | Purpose |
| --- | --- |
| packages.csv | Full package inventory; use this to find usage even without a reported CVE |
| findings.csv | All exported vulnerability/component associations; includes triage state |
| matches.csv | Finding rows matching --ecosystems, --package and --cve (AND logic) |
| coverage.csv | One record per project/branch (per scan with --dump-all), plus project-level retrieval errors |
| raw/*.cdx.json | Original CycloneDX evidence for each selected scan |
| raw/*.scan-report.json | Optional original Checkmarx scan report |
| run.json | Run timestamp, scope, filters and limitations |

Filters affect matches.csv only. Full inventory and findings remain available.
Ecosystems use package URL types: npm = JavaScript/Node ecosystem; pypi = Python.
Other ecosystems are included when --ecosystems is omitted. Packages lacking a
purl are `unknown`; inspect them rather than assuming they are irrelevant.
An unresolved vulnerability reference is retained in findings.csv with unknown
package fields and flagged in coverage.csv. Ecosystem/package filters may exclude
these unresolved rows; always review the unfiltered findings and coverage.

Severity is the highest available reported rating. Ratings are preserved as JSON.
The recommendation is copied when present, not converted into an invented fixed
version. Analysis state (for example, not_affected) is preserved; matching rows are
reported associations, not automatically confirmed exploitable vulnerabilities.
Rows can repeat across branches. Do not treat row counts as unique CVE counts.

No findings is not proof of safety. A missing vulnerabilities section is explicitly
`not_provided`, not zero confirmed vulnerabilities. Review the raw scan report/UI
when this happens. The script does not silently substitute a different JSON schema.
Stale threshold defaults to 30 days (`--stale-days`). Scan dates represent when the
source was scanned; no recalculation against newer intelligence is triggered.
`newer_scan_than_selected` means a newer scan exists than the completed SCA evidence
used and warrants review (it may have failed, be in progress, or lack SCA).

Exit codes: 0 = exports completed with fresh, linked evidence and no flagged gaps;
2 = files produced with coverage warnings/errors; 1 = fatal setup/request error.
Even exit 0 does not mean the product is safe or runtimes have been assessed.
API visibility limits mean undisclosed/inaccessible projects cannot be enumerated.

CSV cells beginning with spreadsheet formula characters receive a leading apostrophe.
Raw JSON retains the original values. Treat outputs as internal security information.
Reports are downloaded from the documented, authenticated
`/api/sca/export/requests/{exportId}/download` endpoint on your configured
`base_url` (as ast-cli does); the `fileUrl` returned by the status endpoint is not
followed. If the download redirects to another host (for example signed storage),
that request is sent without API credentials. Report files are saved byte-for-byte
as downloaded. If your tenant returns a different export format, retain the raw
report and adapt the parser against a sanitized sample.

## Validation and sources

Validated locally with mocked API responses and synthetic CycloneDX fixtures:
pagination, failed-SCA fallback per branch, scoped package/CVE matching, unresolved
references, missing vulnerability data, report polling (including transient 400/404
responses while an export is being prepared), authenticated download, off-host
redirects without credentials and UTF-8 BOM handling.
No live tenant credentials were used, so live integration remains to be validated.

Run tests: `python -m unittest -v test_checkmarx_exposure.py`.

API behavior checked against:
- https://docs.checkmarx.com/en/34965-145615-checkmarx-sca--rest--api---export-service.html
- https://github.com/Checkmarx/ast-cli/blob/main/internal/wrappers/scans.go
- https://github.com/Checkmarx/ast-cli/blob/main/internal/wrappers/projects.go
- https://github.com/Checkmarx/ast-cli/blob/main/internal/wrappers/export-http.go
- https://github.com/Checkmarx/ast-cli/blob/main/internal/wrappers/client.go
- https://docs.checkmarx.com/en/34965-68618-generating-an-api-key.html
