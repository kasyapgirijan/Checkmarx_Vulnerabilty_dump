# Checkmarx One SCA and Container Security exporter

Exports the open-source dependency (SCA) and, optionally, the Container Security results
of your Checkmarx One projects into CSV and JSON files for review in Excel or Power BI:
every package, every reported vulnerability, and which project, application and branch
(and, for containers, which image) it belongs to.

- Python 3.10+ on Windows, Linux or macOS; one dependency (`requests`).
- **Read-only.** It never starts scans, changes findings or edits projects. Its only
  POST requests log in and ask Checkmarx to generate SCA reports.
- Works with Checkmarx One cloud (any region) using an API key or OAuth client.

> **Reported exposure, not verified production exposure.** A vulnerable npm or PyPI
> package in a scan is not proof that it is deployed, nor evidence of a particular
> Node.js or Python runtime version. For runtime advisories, collect the exact
> versions from your hosts or container images separately.

## Contents

- [Quick start](#quick-start)
- [Common tasks](#common-tasks)
- [Configuration](#configuration)
- [SSL errors on a company network](#ssl-errors-on-a-company-network)
- [Usage](#usage)
  - [Choose scan types (SCA, Container Security)](#choose-scan-types)
  - [Choose projects (including a CSV of project IDs)](#choose-projects)
  - [All options](#all-options)
- [Output files](#output-files)
- [Reading the results](#reading-the-results)
- [Security notes](#security-notes)
- [Development](#development)

## Quick start

1. Install the one dependency and create your local config:

   ```powershell
   python -m pip install -r requirements.txt
   Copy-Item config.example.ini config.ini
   notepad config.ini          # set base_url, token_url and api_key
   ```

   On a company network that inspects HTTPS, also set `verify_ssl = false` in
   `config.ini` (see [SSL errors](#ssl-errors-on-a-company-network)).

2. Try one project first:

   ```powershell
   python checkmarx_exposure.py --project "Product A" --out pilot
   ```

3. Open `pilot\coverage.csv` (did every branch export?) and `pilot\findings.csv` (the
   vulnerabilities). Then pick a command from [Common tasks](#common-tasks).

Each `--out` folder must be new, so results from different runs never mix.

## Common tasks

| I want... | Command |
| --- | --- |
| SCA for every project (latest scan per branch) | `python checkmarx_exposure.py --out all-sca` |
| SCA and Container Security for every project | `python checkmarx_exposure.py --scan-types sca,containers --out all` |
| Container Security only | `python checkmarx_exposure.py --scan-types containers --out containers` |
| Only the projects in my CSV of project IDs, SCA and containers | `python checkmarx_exposure.py --project-ids-file my-projects.csv --scan-types sca,containers --out selected` |
| One or two specific projects by ID | `python checkmarx_exposure.py --project-id ID1,ID2 --out two-projects` |
| One application's projects | `python checkmarx_exposure.py --application "Mobile Banking" --out mobile` |
| Projects with a tag | `python checkmarx_exposure.py --tag team=payments --out payments` |
| npm packages only (in `matches.csv`) | `python checkmarx_exposure.py --ecosystems npm --out npm-review` |
| Where a package is used (in `matches.csv`) | `python checkmarx_exposure.py --package lodash --out lodash` |
| Where a CVE is reported (in `matches.csv`) | `python checkmarx_exposure.py --cve CVE-YYYY-NNNNN --out cve-review` |
| Only the `main` branch | `python checkmarx_exposure.py --branch main --out main-only` |
| Every retained scan, not just the latest | `python checkmarx_exposure.py --dump-all --scan-types sca,containers --out full-dump` |
| One run with SSL checks off | add `--insecure` to any command |

Options combine: for example `--project-ids-file my-projects.csv --scan-types
sca,containers --ecosystems npm --insecure --out selected` exports SCA and containers
for the listed projects, puts npm SCA findings in `matches.csv`, and skips SSL checks.

A project ID file is a CSV with one ID per row; see
[`project-ids.example.csv`](project-ids.example.csv) and
[A CSV of project IDs](#a-csv-of-project-ids).

## Configuration

### config.ini (recommended)

The script reads `config.ini` next to `checkmarx_exposure.py`, whatever folder you run
it from. Use `--config "C:\Secure\checkmarx.ini"` for a different file.

```ini
[checkmarx]
base_url = https://eu.ast.checkmarx.net
token_url = https://eu.iam.checkmarx.net/auth/realms/YOUR_TENANT/protocol/openid-connect/token
api_key = YOUR_API_KEY
client_id =
client_secret =
verify_ssl = true
```

| Setting | Environment variable | Meaning |
| --- | --- | --- |
| `base_url` | `CX_BASE_URL` | Your regional Checkmarx One address, without `/api` |
| `token_url` | `CX_TOKEN_URL` | Token endpoint including your tenant name |
| `api_key` | `CX_API_KEY` | The full API key token (not the Key ID shown in the portal) |
| `client_id`, `client_secret` | `CX_CLIENT_ID`, `CX_CLIENT_SECRET` | OAuth client instead of an API key; leave `api_key` empty |
| `verify_ssl` | `CX_VERIFY_SSL` | `true` (default), `false`, or the path to a CA bundle; see [SSL errors](#ssl-errors-on-a-company-network) |

- The URLs above are EU examples; use your own region and tenant.
- Values go on one line, without quotes.
- **Environment variables override the file** when they are set and not empty. If a
  setting seems to be ignored, check for an old `CX_*` variable.
- With an API key, `client_id` is optional (the key's own client, or `ast-app`, is used).
  If both an API key and OAuth client are configured, the API key wins.
- The API identity needs read access to the projects and scans you want, and permission
  to generate SCA exports. SCA must be licensed and the scans must include SCA results.
- For `--scan-types containers`, Container Security must be licensed, the scans must
  include the containers engine, and the identity needs permission to view scan results.

### Environment variables only

Without a `config.ini`, set the variables instead. PowerShell 7.1+:

```powershell
$env:CX_BASE_URL  = "https://eu.ast.checkmarx.net"
$env:CX_TOKEN_URL = "https://eu.iam.checkmarx.net/auth/realms/YOUR_TENANT/protocol/openid-connect/token"
$env:CX_API_KEY   = Read-Host "Checkmarx API key" -MaskInput
```

Windows PowerShell 5.1 (no `-MaskInput`):

```powershell
$secret = Read-Host "Checkmarx API key" -AsSecureString
$env:CX_API_KEY = [System.Net.NetworkCredential]::new("", $secret).Password
```

Linux/macOS:

```bash
export CX_BASE_URL='https://eu.ast.checkmarx.net'
export CX_TOKEN_URL='https://eu.iam.checkmarx.net/auth/realms/YOUR_TENANT/protocol/openid-connect/token'
read -rsp 'Checkmarx API key: ' CX_API_KEY && export CX_API_KEY
```

## SSL errors on a company network

Errors such as `CERTIFICATE_VERIFY_FAILED` usually mean a company proxy or firewall
inspects HTTPS traffic and re-signs it with its own certificate.

**Simplest fix on a trusted PC: turn SSL checks off.** In your local `config.ini`:

```ini
verify_ssl = false
```

Or set it once for your Windows user (then open a new terminal):
`setx CX_VERIFY_SSL false`. Or add `--insecure` to a single run.

This skips certificate and hostname checks and also accepts the older handshakes some
proxies use. The run starts with `WARNING: SSL checks are disabled ...`, and `run.json`
records `"tls_verification": "disabled"`. It only affects machines that set it; the
default stays verified. Anyone able to intercept the traffic could read your API key
and the results, so rotate the key if the network later turns out to be untrusted.

**Safer alternative:** get your company's root certificate as a PEM file (from IT, or
exported from your browser) and point to it, which keeps verification on:

```ini
verify_ssl = C:\Secure\company-root-ca.pem
```

**Still failing?**
- No `WARNING: SSL checks are disabled` line means the setting was not picked up. Check
  that you run the latest script, that the line is under `[checkmarx]` in the config
  file actually used, and that `CX_VERIFY_SSL` is not set to something else.
- The `ERROR:` line shows the underlying reason (paths and secrets removed).
  `WRONG_VERSION_NUMBER` or `ProxyError` usually points to a wrong `HTTPS_PROXY` value
  (for example `https://` where the proxy expects `http://`). Check `HTTPS_PROXY` and
  `NO_PROXY` with your network team.

## Usage

### Two modes

| Mode | Command | Which scans are exported |
| --- | --- | --- |
| Latest (default) | `python checkmarx_exposure.py --out DIR` | Per branch and scan type, the newest scan whose engine (SCA or containers) completed |
| Full dump | `python checkmarx_exposure.py --dump-all --out DIR` | Every retained scan with a completed engine of each chosen type, plus the original Checkmarx SCA scan report for each |

Each scan type is chosen separately, so the SCA and container rows for a branch can
come from different scans if one engine failed in the latest scan. Full dumps are slower
and repeat the same packages and findings across scans. Failed, incomplete or skipped
engines are still listed in `scans.csv` and `coverage.csv`, but have nothing to export.
There is no resume: if a run stops, start again in a new folder.

### Choose scan types

| Option | Exports |
| --- | --- |
| `--scan-types sca` (default) | SCA only, exactly as before: `packages.csv`, `findings.csv`, `matches.csv` |
| `--scan-types containers` | Container Security only: `container_findings.csv`, `container_matches.csv` |
| `--scan-types sca,containers` | Both |

- `container-security` and `container` are accepted for `containers` (as in the
  Checkmarx CLI's `--scan-types`). Case is ignored.
- All output files are always created; the ones for a type you did not choose only
  have a header row.
- `coverage.csv` has one row per project, branch **and scan type**; see `scan_type`.
- Container findings are read the way the official Checkmarx CLI (`cx results show`)
  reads them: `GET /api/results?scan-id=...` for the scan, keeping results of type
  `containers`. A scan counts only when its `containers` engine completed.
- Works with every project filter, `--branch` and `--dump-all`.

```powershell
python checkmarx_exposure.py --scan-types containers --out containers-only
python checkmarx_exposure.py --scan-types sca,containers --application "Mobile Banking" --out mobile
python checkmarx_exposure.py --dump-all --scan-types sca,containers --out full-dump
```

### Choose projects

| Option | Matches |
| --- | --- |
| `--project-id ID` | Exactly this project ID; repeat or comma-separate for several (`--project-id ID1,ID2`) |
| `--project-ids-file FILE.csv` | Exactly the project IDs listed in a CSV file (see below) |
| `--project TEXT` | Project names containing this text |
| `--tag KEY` | Projects with this tag, any value |
| `--tag KEY=VALUE` | Projects with exactly this tag and value |
| `--application NAME_OR_ID` | Projects in this application (exact name or ID) |
| `--group GROUP` | Projects in this group, as listed in the `groups_json` column of `projects.csv` (often group IDs) |

- Matching ignores upper/lower case.
- Repeating an option means *any of*: `--tag team=blue --tag team=red` gets both teams.
- Different options must all match: `--tag team=blue --application Payments` gets only
  blue-team projects that are in Payments.
- `--application` stops with an error if the application list cannot be read, rather
  than export the wrong set of projects.
- `--project-id` and `--project-ids-file` together count as one option: projects in
  either are included.
- These options work in both modes, including `--dump-all`.

```powershell
python checkmarx_exposure.py --project-ids-file my-projects.csv --scan-types sca,containers --out selected
python checkmarx_exposure.py --project-id 1b2c3d4e-0000-0000-0000-000000000000 --out one-project
python checkmarx_exposure.py --tag team=payments --tag pci --out tagged
python checkmarx_exposure.py --application "Mobile Banking" --out mobile
python checkmarx_exposure.py --dump-all --group "GROUP_FROM_PROJECTS_CSV" --out group-dump
```

#### A CSV of project IDs

Put one project ID per row. With a header row, the IDs are read from the column named
`project_id` (or `Project ID`, `projectId`, `id`) and other columns are ignored, so a
`projects.csv` from an earlier run works as is. Without one of those headers, the first
column is used. Blank lines and spaces around IDs are ignored.

```csv
project_id,note
1b2c3d4e-0000-0000-0000-000000000000,Payments API
5f6a7b8c-0000-0000-0000-000000000000,Web shop
```

A file with just the IDs works too:

```csv
1b2c3d4e-0000-0000-0000-000000000000
5f6a7b8c-0000-0000-0000-000000000000
```

[`project-ids.example.csv`](project-ids.example.csv) is a template to copy. Save the
file as CSV (Excel's "CSV UTF-8" is fine).

IDs that are not exported (mistyped, deleted, not visible to the API identity, or
excluded by another filter) are listed in a `WARNING:` line and under `metadata_errors`
in `run.json`, and the run exits with code 2. Find project IDs in `projects.csv` or in
the project's page in Checkmarx One.

### Choose findings

These narrow `matches.csv` and `container_matches.csv` only; the other files always
keep everything. They cannot be combined with `--dump-all` (filter the findings files in
Excel or Power BI instead).

| Option | Matches |
| --- | --- |
| `--ecosystems npm,pypi` | Package types (`node`/`nodejs` = npm, `python` = pypi; also maven, nuget, ...) |
| `--package TEXT` | Package names containing this text |
| `--cve ID` | Exact vulnerability ID or alias |

A finding must match every option given. `--ecosystems` applies to SCA only, since
container results describe image (OS) packages without a package-URL ecosystem; for
`container_matches.csv` only `--package` and `--cve` are used.

```powershell
python checkmarx_exposure.py --ecosystems npm --out npm-review
python checkmarx_exposure.py --package lodash --ecosystems npm --out lodash-review
python checkmarx_exposure.py --cve CVE-YYYY-NNNNN --out cve-review
```

### All options

Every option in one place. Run `python checkmarx_exposure.py --help` for the same list.

| Option | Default | Meaning |
| --- | --- | --- |
| **Output and settings** | | |
| `--out DIR` | `checkmarx-output` | New folder for this run's files; must not exist yet |
| `--config FILE` | `config.ini` beside the script | Settings file |
| `--insecure` | off | Turn SSL checks off for this run (same as `verify_ssl = false`) |
| **What to export** | | |
| `--scan-types TYPES` | `sca` | `sca`, `containers` (or `container-security`), or both comma-separated |
| `--dump-all` | off | Every retained scan instead of the latest per branch; implies `--raw-scan-report` |
| `--branch NAME` | every branch | Only this exact branch (latest mode only). No branch is assumed to be production. |
| `--raw-scan-report` | off | Also save Checkmarx's original SCA scan report JSON |
| **Which projects** ([details](#choose-projects)) | | |
| `--project-id ID[,ID...]` | all | Exact project IDs; repeatable |
| `--project-ids-file FILE.csv` | all | Project IDs from a CSV file |
| `--project TEXT` | all | Project names containing this text |
| `--tag KEY[=VALUE]` | all | Project tag; repeatable |
| `--application NAME_OR_ID` | all | Application name or ID; repeatable |
| `--group GROUP` | all | Project group; repeatable |
| **Which findings go in the matches files** ([details](#choose-findings)) | | |
| `--ecosystems LIST` | all | Package types such as `npm,pypi` (SCA only) |
| `--package TEXT` | all | Package names containing this text |
| `--cve ID` | all | Exact vulnerability ID or alias |
| **Tuning** | | |
| `--stale-days N` | 30 | Scans older than this are marked `stale_or_unknown_date` |
| `--export-timeout SECONDS` | 600 | Time allowed for Checkmarx to produce each SCA report |
| `--product-map FILE.csv` | project name | Map projects to business products (see below) |

`--dump-all` cannot be combined with `--branch`, `--ecosystems`, `--package` or `--cve`.

### Map projects to products

By default the `product` column is the project name (`product_mapping =
project_name_fallback`). To group projects into products, create a CSV with exact
project IDs (from `projects.csv`) and pass `--product-map products.csv`:

```csv
project_id,product
REPLACE_WITH_PROJECT_UUID,Product A
```

## Output files

| File | Contents |
| --- | --- |
| `packages.csv` | Every package in every exported scan, vulnerable or not |
| `findings.csv` | Every vulnerability/package pair, with severity and triage state |
| `matches.csv` | The `findings.csv` rows that match `--ecosystems`, `--package` and `--cve` |
| `container_findings.csv` | Every Container Security finding: image, package, vulnerability, severity, state (`--scan-types containers`) |
| `container_matches.csv` | The `container_findings.csv` rows that match `--package` and `--cve` |
| `coverage.csv` | One row per project, branch and scan type (per scan with `--dump-all`): what was exported, and any gaps or errors |
| `projects.csv` | Projects in scope with tags, groups and applications |
| `applications.csv` | Applications with tags, description, criticality and project IDs |
| `application_projects.csv` | One row per application/project pair; use as a bridge table in Power BI |
| `scans.csv` | Every scan retrieved, with status, engines and tags |
| `run.json` | Time, scope, filters, SSL mode, metadata errors and limitations |
| `raw/*.cdx.json` | Original CycloneDX report for each exported scan |
| `raw/*.scan-report.json` | Original Checkmarx scan report (`--raw-scan-report` / `--dump-all`) |
| `raw/*.containers.json` | Original Container Security result records for each exported scan |
| `raw/scans-PROJECT_ID.jsonl` | Original scan records per project |
| `raw/projects.json`, `raw/applications.json` | Original project and application lists |

### Common columns

Rows in `packages`, `findings`, `matches`, `container_findings`, `container_matches`,
`coverage` and `scans` carry:

- `project`, `project_id`, `product`, `branch`, `scan_id`, `scan_date`, `scan_age_days`
- `applications`: application names as plain text separated by `; ` (empty when none)
- `application_ids_json`, `application_names_json`, `application_tags_json`: exact data,
  keyed by application ID (names can repeat; IDs cannot)
- `application_mapping_status`: `resolved`, `unassigned`, or `partial_or_unknown` when
  applications could not be fully read
- `project_tags_json`, `scan_tags_json`: tags as JSON, keeping empty values

### Container findings columns

`container_findings.csv` has the common columns plus `image_name`, `image_tag`,
`image_file_path` (for example the Dockerfile), `image_origin`, `package`, `version`,
`package_identifier`, `vulnerability` (CVE), `cwe`, `cvss_score`, `severity`, `state`
(triage, for example `TO_VERIFY` or `NOT_EXPLOITABLE`), `status` (`NEW`, `RECURRENT`),
`first_found_at`, `found_at`, `recommended_version`, `description`, `result_id` and
`similarity_id`. Values are copied as Checkmarx returns them; severity is lower-cased.

Raw report files are named by scan ID; find a file's project by looking up its
`scan_id` in `coverage.csv`. (The reports themselves may contain only a project name
or an SCA-internal ID, not the Checkmarx One project ID.)

Application memberships and project/application tags are as they are **at export
time**, not at scan time.

## Reading the results

- **Severity** is the highest rating Checkmarx reports; all ratings are kept in
  `ratings_json`. `recommendation` is copied as given, never invented.
- **Triage state** (`analysis_state`, for example `not_affected`) is preserved. A row is
  a reported association, not a confirmed exploitable vulnerability.
- **Counts:** rows repeat across branches and scans; do not treat row counts as unique
  CVE counts.
- **No findings is not proof of safety.** `vulnerability_section = not_provided` in
  `coverage.csv` means the report had no vulnerability data at all; review that scan.
- **Unlinked findings:** a vulnerability that cannot be linked to a package stays in
  `findings.csv` with `ecosystem = unknown` and `package_link_status = unresolved`, and
  is counted in `unresolved_links`. Ecosystem/package filters can exclude these rows.
- **Packages without a package URL** have ecosystem `unknown`; inspect rather than ignore.
- **Development and test dependencies** are included; `scope` shows what Checkmarx reports.

### coverage.csv statuses

| `status` | Meaning |
| --- | --- |
| `exported` | Report exported; scan is within `--stale-days` |
| `stale_or_unknown_date` | Report exported, but the scan is older than `--stale-days` or undated |
| `no_confirmed_completed_sca` | No scan with a completed SCA engine on this branch (or this scan's SCA did not complete) |
| `no_confirmed_completed_containers` | The same for the Container Security (`containers`) engine |
| `export_error` | Report generation or download failed; see `error` |
| `scan_list_error` | The project's scans could not be listed |
| `no_scans_in_scope` | No scans (on `--branch`, if given) |

- `scan_type`: `sca` or `containers`.
- `newer_scan_than_selected = True`: a newer scan exists than the one exported (it may
  have failed, still be running, or lack that engine). Worth a look.
- For container rows, `package_count` is the number of distinct image/package/version
  combinations with findings (Checkmarx's results list holds only vulnerable packages).
- `scan_role` (`--dump-all`): `current` for each branch's newest completed SCA scan,
  `historical` for older ones.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Everything exported, recent, and linked; no gaps flagged |
| 2 | Files written, but `coverage.csv` or `run.json` shows something to review |
| 1 | Fatal error (configuration, login, network); details on the `ERROR:` line |

Older (`historical`) scans in a full dump only cause exit 2 if their export fails.
Even exit 0 does not mean a product is safe. Deleted or expired scans, and projects
outside the API identity's permissions, cannot be exported.

## Security notes

- `config.ini` holds your key in plain text; keep it readable only by you. All `*.ini`
  files except `config.example.ini` are ignored by Git. **Never commit a real config**:
  this repository is public.
- Credentials are never written to output files or error messages. Error text has
  request paths, query strings and proxy passwords removed.
- Reports are downloaded from the authenticated
  `/api/sca/export/requests/{exportId}/download` endpoint on your `base_url`; container
  results are read from `/api/results` on the same host. If that
  redirects to another host (for example cloud storage), the API token is not sent there.
- Report files are saved byte-for-byte as received.
- CSV cells starting with `=`, `+`, `-` or `@` get a leading `'` so Excel does not run
  them as formulas. The raw JSON keeps the original values.
- Treat all output as internal security information.

## Development

```powershell
python -m unittest -v test_checkmarx_exposure.py
```

The tests use mocked API responses and sample CycloneDX data: pagination, per-branch
fallback when SCA failed, container results and their paging, scan-type selection,
project ID lists and CSV files, finding and project filters, unlinked references, missing
vulnerability data, export polling (including temporary 400/404 replies), downloads
and redirects, UTF-8 BOM handling, SSL settings, config handling and secret redaction.
They have not been run against a live tenant.

API behaviour is based on the Checkmarx documentation and the official Checkmarx CLI:

- [SCA REST API: Export Service](https://docs.checkmarx.com/en/34965-145615-checkmarx-sca--rest--api---export-service.html)
- [Generating an API key](https://docs.checkmarx.com/en/34965-68618-generating-an-api-key.html)
- ast-cli wrappers: [export-http.go](https://github.com/Checkmarx/ast-cli/blob/main/internal/wrappers/export-http.go),
  [client.go](https://github.com/Checkmarx/ast-cli/blob/main/internal/wrappers/client.go),
  [scans.go](https://github.com/Checkmarx/ast-cli/blob/main/internal/wrappers/scans.go),
  [projects.go](https://github.com/Checkmarx/ast-cli/blob/main/internal/wrappers/projects.go),
  [results-http.go](https://github.com/Checkmarx/ast-cli/blob/main/internal/wrappers/results-http.go)
  and [results-json.go](https://github.com/Checkmarx/ast-cli/blob/main/internal/wrappers/results-json.go)
  (container results), [result.go](https://github.com/Checkmarx/ast-cli/blob/main/internal/commands/result.go)
