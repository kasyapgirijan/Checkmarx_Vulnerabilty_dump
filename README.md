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
  - [Choose scan types (SCA, containers, SAST, IaC, secrets)](#choose-scan-types)
  - [True positives only (triage states)](#true-positives-only)
  - [Choose projects (including a CSV of project IDs)](#choose-projects)
  - [All options](#all-options)
- [Load into PostgreSQL (incremental)](#load-into-postgresql-incremental)
- [Exposure report (Log4Shell, Spring4Shell, React2Shell, ...)](#exposure-report)
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
| Which projects use Java (Maven/Gradle) libraries (in `package_matches.csv`) | `python checkmarx_exposure.py --ecosystems maven --out java-inventory` |
| Which versions of a package are in use, vulnerable or not (in `package_matches.csv`) | `python checkmarx_exposure.py --package log4j-core --out log4j-versions` |
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

This skips certificate and hostname checks and accepts the legacy renegotiation some
proxies use. TLS 1.2 or newer and the default cipher list are still required. The run starts with `WARNING: SSL checks are disabled ...`, and `run.json`
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

| Scan type | Engine | What it finds |
| --- | --- | --- |
| `sca` (default) | SCA | Vulnerable open-source packages; also fills `packages.csv` (the inventory) |
| `containers` | Container Security | Vulnerable OS and image packages |
| `sast` | SAST | Code weaknesses such as SQL injection or XSS, with file and line |
| `kics` (or `iac`) | KICS / IaC Security | Terraform, Kubernetes, Dockerfile, CloudFormation misconfigurations |
| `secrets` | Secret detection | Passwords, keys and tokens committed to the repository |

Combine them with commas, for example `--scan-types sca,containers,sast,iac,secrets` to
dump everything. **Every finding from every engine goes into one `findings.csv`**, with an
`engine` column and the same core columns (`category`, `cwe`, `severity`,
`vulnerability`, `triage_state`); package columns are filled for SCA and containers,
`file_path` and `line` for SAST, IaC and secrets.

- `container-security` and `container` are accepted for `containers`, `iac-security`
  for `kics`, `secret-detection` for `secrets` (as in the Checkmarx CLI). Case is ignored.
- All output files are always created; one with nothing to export only has a header row.
- **Category** is a readable class from the finding's CWE (for example CWE-89 is
  `SQL/NoSQL Injection`, CWE-502 `Deserialization`, CWE-917 `Code/Command Injection
  (RCE)`). Without a CWE it comes from keywords in the finding name, IaC findings use
  their KICS group (`IaC: Insecure Configurations`), secrets are always `Hardcoded
  Credentials / Secrets`, and anything else is `Other`. SCA CWEs come from the
  CycloneDX report.
- Container, SAST, IaC and secret findings are read the way the official Checkmarx CLI
  (`cx results show`) reads them: `GET /api/results?scan-id=...`, fetched once per scan
  for all of them. A scan counts only when that engine completed.
- Secret detection runs as a Checkmarx "micro-engine"; its engine and result names were
  taken from the Checkmarx CLI, not yet seen on your tenant. If `coverage.csv` shows
  `no_confirmed_completed_secrets` for scans that did run secret detection, send me the
  `statusDetails` names from `scans.csv`.
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

### True positives only

By default only findings triaged as **true positives** are written to `findings.csv` and
loaded into the database. Checkmarx One uses the same triage states for every engine
(SAST, SCA, containers, IaC and secrets):

| State | Meaning | Loaded by default |
| --- | --- | --- |
| `TO_VERIFY` | Default for every new result: nobody has triaged it yet | No |
| `PROPOSED_NOT_EXPLOITABLE` | Someone proposed it as a false positive; waiting for approval | No |
| `NOT_EXPLOITABLE` | Triaged as a false positive (not a defect) | No |
| `CONFIRMED` | Triaged as a real issue | **Yes** |
| `URGENT` | Triaged as a real issue to fix first | **Yes** |
| Custom states | Names your tenant added (`cx triage get-states`) | Only if listed |

Change the list with `--keep-states` (case, spaces and `_` are ignored, so `NotExploitable`
and `NOT_EXPLOITABLE` are the same):

| Option | Loads |
| --- | --- |
| *(default)* `--keep-states CONFIRMED,URGENT` | Verified true positives only |
| `--keep-states CONFIRMED,URGENT,TO_VERIFY` | Everything except false positives and proposed false positives |
| `--keep-states CONFIRMED,URGENT,"Accepted Risk"` | Adds a custom state |
| `--keep-states all` | Every finding, whatever its state |

- **SCA states come from the Checkmarx results API** (`/api/results`), the same states
  you set in the Checkmarx UI. The CycloneDX report's own `analysis_state` is kept in a
  separate column and used only when the results API has no state for a finding
  (`exploitable` = `CONFIRMED`, `in_triage` = `TO_VERIFY`, `not_affected` and
  `false_positive` = `NOT_EXPLOITABLE`). If the results API cannot be read, that scan is
  reported as an `export_error` instead of being loaded with unknown states.
- `coverage.csv` shows `finding_count` (loaded) and `excluded_findings` (left out by
  triage) per scan.
- In the database, a finding that was loaded and is later triaged out (for example
  marked Not Exploitable) gets `status = excluded`, not `fixed`, with an `excluded`
  event; if it is triaged back in, it returns to `open` with an `included` event. A
  finding that was never a true positive is never added.
- After upgrading, run once with `--db --full` so findings already in the database are
  checked against their current state.

### Choose findings

These narrow `matches.csv` and `package_matches.csv` only; the
other files always keep everything. `package_matches.csv` is the package inventory
(vulnerable or not) filtered by `--ecosystems` and `--package`; it is only filled when
one of those is given. They cannot be combined with `--dump-all` (filter the findings files in
Excel or Power BI instead).

| Option | Matches |
| --- | --- |
| `--ecosystems npm,pypi` | Package types (`node`/`nodejs` = npm, `python` = pypi; also maven, nuget, ...) |
| `--package TEXT` | Package names containing this text |
| `--cve ID` | Exact vulnerability ID or alias |

A finding must match every option given. `--ecosystems` applies to SCA only, since
container results describe image (OS) packages without a package-URL ecosystem; for
container rows only `--package` and `--cve` are used. SAST, IaC and secret findings
are never in `matches.csv` (filter `findings.csv` on `engine` and `category` instead).

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
| `--out DIR` | `checkmarx-output` (timestamped subfolder with `--db`) | New folder for this run's files; must not exist yet |
| `--config FILE` | `config.ini` beside the script | Settings file; non-empty `CX_*` environment variables override it |
| `--insecure` | off | Turn SSL checks off for this run (same as `verify_ssl = false`) |
| `--raw-csv` | off | Write CSV values exactly as returned, without the Excel formula guard (see Security notes) |
| `--no-progress` | off | Hide the progress bar and status lines on stderr |
| `--db [FILE.ini]` | off | Also load findings into PostgreSQL incrementally (see [below](#load-into-postgresql-incremental)). Alone, it reads `[postgres]` from the `--config` file |
| `--full` | off | With `--db`: reload the newest completed scan of every branch, even if already loaded |
| `--no-files` | off | With `--db`: load only the database, without keeping CSV and raw files |
| **What to export** | | |
| `--scan-types TYPES` | `sca` | Comma-separated: `sca`, `containers`, `sast`, `kics` (or `iac`), `secrets` |
| `--keep-states STATES` | `CONFIRMED,URGENT` | Triage states to load; `all` for every finding. See [True positives only](#true-positives-only) |
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

`--dump-all` cannot be combined with `--branch`, `--ecosystems`, `--package`, `--cve` or `--db`.

### Progress

While it runs, the script shows its progress on stderr, so stdout and the output files
stay clean. In a terminal this is one updating line:

```text
[########----------------]  33% 4/12 projects | 2m10s | ~4m20s left | payments-api: waiting for CycloneDxJson report (15s)
```

It shows projects done, time elapsed, an estimate of the time left (from the average
per project so far), and the project, scan and step running now. When stderr is
redirected to a file or CI log, it prints one plain line per project and per scan
instead. Use `--no-progress` to turn it off.

### Map projects to products

By default the `product` column is the project name (`product_mapping =
project_name_fallback`). To group projects into products, create a CSV with exact
project IDs (from `projects.csv`) and pass `--product-map products.csv`:

```csv
project_id,product
REPLACE_WITH_PROJECT_UUID,Product A
```

## Load into PostgreSQL (incremental)

Add `--db` to load findings into PostgreSQL as well. Each run loads only scans
that are new since the last run, and keeps track of when every finding was first seen,
fixed, or reopened.

```powershell
python -m pip install -r requirements-db.txt      # psycopg 3
notepad config.ini                                # add a [postgres] section (below)
python checkmarx_exposure.py --db --scan-types sca,containers
```

The connection settings go in a `[postgres]` section, the same layout as the Jira
extract project. Put it in your existing `config.ini` and use `--db` alone, or keep it
in a separate file and pass `--db postgres.ini` (copy `postgres.example.ini`):

```ini
[postgres]
host = localhost
port = 5432
database = checkmarx
user = checkmarx_loader
password =
sslmode = prefer
schema = checkmarx
```

Also accepted: `dbname` (instead of `database`), `sslrootcert` and `connect_timeout`.
Tables are created in `schema` (default `checkmarx`). Leave `password` empty to use the
`PGPASSWORD` environment variable or a pgpass file instead of writing it in the file.
Both `config.ini` and `postgres.ini` are ignored by Git. The database and user must
exist; the user needs rights to create the schema on the first run, and to read and write
its tables after that.

**How a run works**

- For each project, branch and scan type, the first run loads the newest completed scan
  as the baseline. Later runs load every completed scan newer than the last one loaded,
  oldest first, so a fix is dated by the scan that first showed it.
- Scans that are already loaded are not exported again (`coverage.csv` status
  `already_loaded`). A scan whose export failed is not recorded, so the next run tries
  it again.
- A finding is **fixed** when a newer completed scan of the same project, branch and scan
  type no longer contains it. It is **reopened** if it comes back later.
- Findings are never closed by a scan whose engine did not complete, or whose report had no
  vulnerability section, because a missing result there says nothing about a fix.
- Checkmarx triage (for example `not_affected` from SCA, or `NOT_EXPLOITABLE` for
  containers) is kept in `triage_state`. It does not close a finding.
- CSV and raw files are still written. A run with `--db` gets a new timestamped folder
  under `checkmarx-output` unless you pass `--out`. Add `--no-files` to load only the
  database.
- `--db` cannot be combined with `--dump-all`; the database builds the history instead.
- `--full` reloads the newest completed scan of every branch even if it is already
  loaded. Use it once after an upgrade that adds columns, to fill them for existing rows.
- Each scan is committed on its own. If a run stops partway, scans already loaded stay,
  and the next run carries on from there. The run is recorded in `runs` with
  `status = FAILED` and the reason in `error`.
- Only one load per schema runs at a time (a PostgreSQL advisory lock); a second run
  stops with `Another Checkmarx load ... is already running`.
- Schema changes are applied automatically on each run (`ADD COLUMN IF NOT EXISTS`), and
  the views are recreated, so upgrading the script needs no manual SQL.

**Finding identity.** SCA findings are keyed on vulnerability, ecosystem and package
name, not the version, so moving to another version that is still vulnerable keeps the
same finding (the versions are in `versions`). Container findings are keyed on
vulnerability, image name (not the tag), image file and package, so a new image tag from
the next build does not look like a fix. SAST, IaC and secret findings are keyed on the
Checkmarx similarity ID, which stays the same when code moves to another line (or on
name, file and line when there is none).

**Upgrading.** An existing database is upgraded in place at the start of the next run;
nothing is reloaded and no history is lost. Findings get a `finding_id` and their
`finding_events` are linked to it, `category` and `cwe` are filled from what is already
stored, and the old `branch_state` table is folded into `scan_loads` (read it as
`vw_branch_state`) and dropped.

**Tables** (in the configured schema):

| Table | Contents |
| --- | --- |
| `findings` | One table for every engine: one row per finding per project, branch and `engine`, with a numeric `finding_id`, `project_id` and `project_name`: `status` (`open`, `fixed`, or `excluded` when triaged out of `--keep-states`), `first_seen_at`, `last_seen_at`, `fixed_at`, the scan IDs for each, `reopened_count`, `category`, `cwe`, `severity`, `triage_state`, package or image details (SCA, containers), `file_path` and `line` (SAST, IaC, secrets), and the full engine-specific row in `details` |
| `finding_events` | History: `new`, `fixed`, `reopened`, `excluded` (triaged out) and `included` (triaged back in), with the scan and its date, linked by `finding_id` |
| `vw_findings` (view) | All findings, open and fixed, with project name, product and applications |
| `vw_open_findings` (view) | Open findings from every engine, with project name, product and applications. Point Power BI here |
| `vw_sca`, `vw_containers`, `vw_sast`, `vw_iac`, `vw_secrets` (views) | One engine each, with only the columns that apply to it (open and fixed; filter on `status`) |
| `vw_category_summary` (view) | Open, fixed and excluded counts per project, branch, engine, category and severity |
| `vw_unique_open_findings` (view) | Each open finding **once** per project and engine, with the branches it is on (`branches`, `branch_count`), the worst severity and first/last seen. Use it to count findings without branch duplicates |
| `packages` | Package inventory per project and branch, vulnerable or not: `ecosystem`, `package`, `version`, `dependency_type`, `introduced_by`, `status` (`present`/`removed`), first and last seen, and when it was removed. Keyed with the version, so an upgrade shows the old version as removed and the new one as present |
| `vw_current_packages` (view) | Packages present now, with project name, product and applications |
| `projects`, `scans` | Latest project metadata and every scan seen |
| `scan_loads` | Which scan was loaded for which scan type, and whether it could close findings |
| `vw_branch_state` (view) | The last scan loaded per project, branch and scan type; the next run continues from here |
| `runs` | One row per run: `status` (`RUNNING`, `SUCCESS` or `FAILED`), `error`, the `run.json` summary and database counts |

```sql
-- Open critical/high findings, oldest first
SELECT project, branch, engine, vulnerability, package, versions, image_name, triage_state, first_seen_at
FROM checkmarx.vw_open_findings WHERE severity IN ('critical', 'high') ORDER BY first_seen_at;

-- Open findings by category across every engine
SELECT engine, category, sum(open_findings) AS open_findings
FROM checkmarx.vw_category_summary GROUP BY engine, category ORDER BY open_findings DESC;

-- Open SQL injection found by SAST, with file and line
SELECT project, branch, vulnerability, file_path, line, language, severity
FROM checkmarx.vw_sast WHERE status = 'open' AND category = 'SQL/NoSQL Injection';

-- Which projects use Java libraries (Maven or Gradle)
SELECT DISTINCT project, branch FROM checkmarx.vw_current_packages WHERE ecosystem = 'maven';

-- Every log4j-core version in use, and whether it is a direct dependency
SELECT project, branch, version, dependency_type, introduced_by
FROM checkmarx.vw_current_packages WHERE package = 'org.apache.logging.log4j/log4j-core' ORDER BY version;

-- Fixed in the last 30 days, with time to fix
SELECT project_id, branch, vulnerability, package, fixed_at, fixed_at - first_seen_at AS time_to_fix
FROM checkmarx.findings WHERE status = 'fixed' AND fixed_at > now() - interval '30 days';
```

The package inventory comes from SCA (Container Security only reports packages with
findings, so image packages are not part of it). SCA reads build files and lockfiles: it
lists the libraries a project uses, not the Java, Node.js or Python runtime it runs on.

`first_seen_at` is the date of the first scan this tool loaded that contained the
finding (Container Security's own `firstFoundAt` when it is earlier). For findings that
already existed before your first `--db` run, it is the baseline scan's date.

## Exposure report

`exposure_report.py` answers "where are we exposed to Log4Shell / Spring4Shell /
React2Shell / ...?" as a CSV. It matches on **package name and version range**, not on
Checkmarx's CVE list, so a vulnerable version is reported even when Checkmarx shows no
CVE for it (`checkmarx_cves = NA`). Each vulnerability is a section in an INI file.

```powershell
Copy-Item report.example.ini report.ini
notepad report.ini                         # source, output, and the vulnerabilities to look for
python exposure_report.py --config report.ini
python exposure_report.py --config report.ini --only Log4Shell --out log4shell.csv
```

**Where the data comes from** (`source` in `[report]`):

- `db`: the PostgreSQL database that `checkmarx_exposure.py --db` fills (the current
  package inventory and open findings). `db_config` names the file with the `[postgres]`
  section, for example `config.ini`.
- A folder written by `checkmarx_exposure.py` (latest mode, not `--dump-all`), for example
  `source = checkmarx-output\20261118T101500Z`. No database needed.

**A vulnerability section** (see `report.example.ini` for Log4Shell, Spring4Shell and
React2Shell):

```ini
[Log4Shell]
cves = CVE-2021-44228, CVE-2021-45046, CVE-2021-45105, CVE-2021-44832
ecosystem = maven
packages = org.apache.logging.log4j/log4j-core
affected = >=2.0-beta9,<2.3.2 ; >=2.4,<2.12.4 ; >=2.13.0,<2.17.1
fixed = 2.17.1 (Java 8+), 2.12.4 (Java 7), 2.3.2 (Java 6)
```

In `affected`, `,` means AND and `;` means OR; a bare version means exactly that
version. `packages` takes names as they appear in `packages.csv` (Maven `group/artifact`)
and `*` globs. Use `[Name/label]` sections to give one vulnerability several package
rules, as React2Shell does for `react-server-dom-*` and `next`.

**Output.** One row per project, branch, scan type (and image for containers), package
and version that a rule matches, with the project, product and applications, the
dependency type and what introduced it, and:

| `verdict` | Meaning |
| --- | --- |
| `affected` | The version is inside an affected range |
| `reported_by_checkmarx` | Checkmarx reports one of the `cves`, but no package rule matched (check the rule) |
| `version_unknown` | The package matched but its version could not be read |
| `not_affected` | The package is used, at a version outside the ranges |

`checkmarx_reported_target_cve` says whether Checkmarx itself reports one of the `cves`
on that package version (`no` with `affected` is the case this report exists for);
`checkmarx_cves` lists every vulnerability Checkmarx reports there, or `NA`. A second file,
`<output>-summary.csv`, has one row per vulnerability and project.

Limits: version comparison handles npm/semver, Maven, PyPI and common OS package
versions; check `version_unknown` rows by hand. Container Security only lists packages
that have findings, so container rows appear only for packages with at least one finding,
and they are matched by name only. Neither source shows the Java or Node.js runtime
itself. The example ranges come from public advisories; check them against the vendor
advisory before relying on the result.

## Output files

| File | Contents |
| --- | --- |
| `packages.csv` | Every package in every exported scan, vulnerable or not, with `dependency_type` (`direct`/`transitive`/`unknown`) and `introduced_by` |
| `package_matches.csv` | The `packages.csv` rows that match `--ecosystems` and `--package` (empty without them) |
| `findings.csv` | Every finding from every chosen engine, one row each: `engine`, `category`, `cwe`, `severity`, `triage_state`, and the package, image or file details that apply |
| `matches.csv` | The SCA and container rows of `findings.csv` that match `--ecosystems`, `--package` and `--cve` |
| `coverage.csv` | One row per project, branch and scan type (per scan with `--dump-all`): what was exported, and any gaps or errors |
| `projects.csv` | Projects in scope with tags, groups and applications |
| `applications.csv` | Applications with tags, description, criticality and project IDs |
| `application_projects.csv` | One row per application/project pair; use as a bridge table in Power BI |
| `scans.csv` | Every scan retrieved, with status, engines and tags |
| `run.json` | Time, scope, filters, SSL mode, metadata errors and limitations |
| `raw/*.cdx.json` | Original CycloneDX report for each exported scan |
| `raw/*.scan-report.json` | Original Checkmarx scan report (`--raw-scan-report` / `--dump-all`) |
| `raw/*.containers.json`, `raw/*.sast.json`, `raw/*.kics.json`, `raw/*.secrets.json` | Original result records of each engine for each exported scan |
| `raw/scans-PROJECT_ID.jsonl` | Original scan records per project |
| `raw/projects.json`, `raw/applications.json` | Original project and application lists |

### Common columns

Rows in `packages`, `findings`, `matches`, `coverage` and `scans` carry:

- `project`, `project_id`, `product`, `branch`, `scan_id`, `scan_date`, `scan_age_days`
- `applications`: application names as plain text separated by `; ` (empty when none)
- `application_ids_json`, `application_names_json`, `application_tags_json`: exact data,
  keyed by application ID (names can repeat; IDs cannot)
- `application_mapping_status`: `resolved`, `unassigned`, or `partial_or_unknown` when
  applications could not be fully read
- `project_tags_json`, `scan_tags_json`: tags as JSON, keeping empty values

### Direct and transitive dependencies

`packages.csv`, `findings.csv` and `matches.csv` have a `dependency_type` column, read
from the dependency graph in the CycloneDX report:

- `direct`: the project depends on it itself (or nothing else in the graph pulls it in)
- `transitive`: pulled in by another package; `introduced_by` names the direct
  dependencies it comes through (up to 5, then `+N more`)
- `unknown`: the report had no dependency graph

### Findings columns by engine

Every row of `findings.csv` has the common columns plus `engine`, `vulnerability`,
`category`, `cwe`, `severity` (lower-cased), `triage_state` (for example `not_affected`,
`TO_VERIFY`, `NOT_EXPLOITABLE`), `result_status` (`NEW`, `RECURRENT`) and `description`.
The rest depend on the engine; columns that do not apply are empty:

| Engine | Extra columns |
| --- | --- |
| `sca` | `package`, `version`, `ecosystem`, `purl`, `dependency_type`, `introduced_by`, `aliases`, `ratings_json`, `recommendation`, `affected_versions_json`, `source_url`, `package_link_status` |
| `containers` | `image_name`, `image_tag`, `image_file_path` (for example the Dockerfile), `image_origin`, `package`, `version`, `package_identifier`, `cvss_score`, `recommendation` (recommended version) |
| `sast` | `language`, `file_path`, `line` (first node of the data flow), `result_id`, `similarity_id` |
| `kics` | `platform` (Terraform, Kubernetes, ...), `group`, `file_path`, `line`, `issue_type`, `expected_value`, `actual_value` |
| `secrets` | `file_path`, `line`, `result_id`, `similarity_id` |

Output folders from earlier versions had a separate `container_findings.csv`; the
exposure report still reads those.

Raw report files are named by scan ID; find a file's project by looking up its
`scan_id` in `coverage.csv`. (The reports themselves may contain only a project name
or an SCA-internal ID, not the Checkmarx One project ID.)

Application memberships and project/application tags are as they are **at export
time**, not at scan time.

## Reading the results

- **Severity** is the highest rating Checkmarx reports; all ratings are kept in
  `ratings_json`. `recommendation` is copied as given, never invented.
- **Triage state** (`triage_state`) is the Checkmarx state (`CONFIRMED`, `URGENT`, ...);
  see [True positives only](#true-positives-only). For SCA, `analysis_state` keeps the
  CycloneDX value as reported.
- **Counts:** rows repeat across branches (use `vw_unique_open_findings` in the database); do not treat row counts as unique
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
| `already_loaded` | `--db` only: this scan is already in the database, so it was not exported again |

- `scan_type`: `sca` or `containers`.
- `newer_scan_than_selected = True`: a newer scan exists than the one exported (it may
  have failed, still be running, or lack that engine). Worth a look.
- For container rows, `package_count` is the number of distinct image/package/version
  combinations with findings (Checkmarx's results list holds only vulnerable packages).
- `scan_role`: `current` for the evidence that represents each branch today: the
  selected scan in latest mode, and in `--dump-all` each branch's newest scan whose
  engine completed (or the newest scan, if none completed). Other scans are `historical`.
- A branch with no completed scan for a requested scan type is `current` with
  `no_confirmed_completed_*`, so it makes the run exit 2. With `--scan-types
  sca,containers`, projects that never ran Container Security are flagged too.

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
  request paths, query strings and proxy passwords removed. Local file errors (for
  example an existing `--out` folder) show the reason and path.
- Reports are downloaded from the authenticated
  `/api/sca/export/requests/{exportId}/download` endpoint on your `base_url`; container
  results are read from `/api/results` on the same host. If that
  redirects to another host (for example cloud storage), the API token is not sent there.
- Report files are saved byte-for-byte as received.
- CSV cells starting with `=`, `+`, `-` or `@` get a leading `'` so Excel does not run
  them as formulas. This also changes scoped npm names (`@scope/pkg` becomes
  `'@scope/pkg`). If the CSVs feed a script, database or Power BI rather than Excel, use
  `--raw-csv` to keep values unchanged. The `purl` column and raw JSON are never changed.
- `config.ini` or `postgres.ini` may hold a database password; prefer `PGPASSWORD` or a pgpass file, and
  use `sslmode = verify-full` for a database on another machine. Database errors are
  shown without the password.
- Treat all output as internal security information.

## Development

```powershell
python -m unittest -v test_checkmarx_exposure.py test_checkmarx_db.py test_exposure_report.py
```

The PostgreSQL tests are skipped unless `CX_TEST_PG` points at a disposable database,
for example `CX_TEST_PG="host=localhost port=5432 user=postgres dbname=postgres"`. Each
test creates its own schema and drops it afterwards.

The tests use mocked API responses and sample CycloneDX data: pagination, per-branch
fallback when SCA failed, container results and their paging, scan-type selection,
project ID lists and CSV files, finding and project filters, unlinked references, missing
vulnerability data, export polling (including temporary 400/404 replies and 429 rate limits), short
result pages, missing-scan coverage gaps, progress output, downloads
and redirects, UTF-8 BOM handling, SSL settings, config handling and secret redaction,
and incremental PostgreSQL loading (baseline, new, fixed, reopened, failed scans,
missing vulnerability sections, retries after export errors, containers).
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
