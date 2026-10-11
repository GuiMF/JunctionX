# QuantumTrace

QuantumTrace discovers cryptographic facts in Python/Java/Go source, saved network
captures and AWS JSON snapshots. A shared rule engine assesses findings, calculates
asset exposure, and exports JSON or a schema-validated CycloneDX 1.6 CBOM.

See [scanner support and remaining boundaries](docs/scanners.md#unsupported-versus-unknown)
for what is supported, why some evidence remains unknown, and extension paths.

The React dashboard starts with an empty inventory. Open **Import data**, select source,
AWS snapshot, or capture files and click **Scan selected files** to analyze them
with the local API, inspect the returned findings, and export the active scan.

## Run locally

Install **Python 3.12+** and **Node.js 22+ with npm**, then run the root
launcher. No Bash, WSL, virtual-environment activation, or separate terminals are needed.

**Windows (PowerShell):**

```powershell
py start.py
```

If Python was installed without the `py` launcher, use `python start.py` instead.

**macOS / Linux:**

```sh
python3 start.py
```

The launcher finds an installed Python 3.12+, creates `.venv`, installs Python and
frontend dependencies, and starts both the API and dashboard. The first run needs
internet access; later runs reuse dependencies until the dependency files change.
Keep the terminal open and visit **http://127.0.0.1:5173** when it prints `Ready!`.
Press **Ctrl-C** to stop both services. If either service fails, the launcher stops
the other and reports the error.

The API runs at `http://127.0.0.1:8000`, with its contract at `/openapi.json` and
interactive documentation at `/docs` (Swagger UI assets load from a CDN).
To use a different API port, add `--port 8001`; the dashboard connects to that
port automatically. If dashboard port 5173 is busy, add `--web-port 5174`;
the launcher configures API access for the selected port. Use `--reinstall` to repair dependencies.
All options work with any of the commands above.

Scanning and export work offline after setup. PCAP parsing additionally requires
TShark installed on the host and available on `PATH`. Source and cloud scans do
not require TShark. On Windows, enable Python's PATH option during installation;
after installing Python, Node.js, or TShark, reopen the terminal.

### Start services separately (optional)

For backend-only development on macOS/Linux, `./scripts/run-local.sh` still
starts the API (`PYTHON=python3.13` and `PORT=8001` can override its defaults).
For frontend-only development, run `npm ci` and `npm run dev` from `web/`.
Vite proxies same-origin `/api` requests to `http://127.0.0.1:8000`; when starting the frontend
separately against another API port, set `VITE_API_BASE_URL` to your API origin before starting Vite. It is a build-time
setting, so also set it for `npm run build` when needed.

## Dashboard workflow

For hosting, see [Vercel services deployment](docs/deployment.md), including
the remaining backend storage and upload constraints.

Open **Import data** and select `.py`, `.java`, `.go`, `.pcap`, `.pcapng`, `.cap`, or AWS snapshot `.json`
files, or use **Browse folder** (or drop a folder) to recursively discover compatible
files in every subfolder, then click **Scan selected files**. Folder discovery shows
compatible/skipped counts and skips unrelated extensions and non-AWS JSON. Relative
paths are preserved in the selection, evidence and exports, so same-named files in
different subfolders remain distinct. Source and cloud files must be UTF-8;
captures are encoded as base64. JSON must contain a `Keys`, `Certificates`, or
`LoadBalancers` snapshot, or the [documented AWS bundle](docs/api.md). Select related
AWS snapshots in the same folder: the dashboard bundles each folder into one input so certificate
references resolve. Select only one snapshot of each kind per folder; keep different environments
in separate folders. Individually selected files are grouped together. Native AWS
DescribeKey (`KeyMetadata`) and DescribeCertificate (`Certificate`) JSON responses
are also accepted; each is submitted separately with its original evidence paths.

Select 1–10,000 files with unique relative paths. Encoded inputs are limited to 64 MiB each and
3 GB combined (3,000,000,000 bytes), including base64 expansion and the combined
AWS bundles. Folders above 64 MiB upload in batches to temporary disk storage; the
server reads inputs one at a time and produces one combined scan and exports. Invalid
selections explain how to correct them before submission. Source files separately
allow up to 16 MiB and 20,000 detected occurrences per file. The previous result stays
visible while scanning. A returned `partial` or `failed` result replaces it and
shows per-input errors; `201` alone does not mean all inputs succeeded.

Use **Retry scan** after fixing a connection problem, or reselect corrected files.
Individual requests time out after 5 minutes; completing a batched scan allows
30 minutes, and exports allow 10 seconds. **Cancel scan** discards pending results
in the browser (server work may continue). Incomplete uploads expire after one
hour of inactivity and are removed on the next upload operation or API shutdown.
At most two uploads may await completion. Exports submit the active result held
by the browser for conversion, so they work after the server restarts or another
instance receives the export request. Refreshing the page clears that result.

## Scan and demonstrate

```sh
# Exercise the API without opening a server socket; writes reports/.
.venv/bin/python -m scripts.demo --in-process

# Scan a source directory and export a validated CBOM for each batch.
.venv/bin/python -m scripts.scan_source tests/fixtures/source --synthetic \
  --output reports/source.json --cyclonedx-dir reports/source-cbom

# Scan a saved network capture through assessment and scoring.
.venv/bin/python network-capture.py capture.pcap

# Compare original and modified synthetic cloud configuration.
.venv/bin/python -m adapters.cloud_demo
.venv/bin/python -m adapters.cloud_demo --certificate-renewal
```

Omit `--in-process` to run the demo against a running API. Inputs under
`cloud-posture/`, `tests/fixtures/` and `examples/` are explicitly synthetic.
The cloud examples edit metadata fixtures; they do not change AWS resources.

## Maintain and verify

```sh
.venv/bin/python -m scripts.generate_contract
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m scripts.evaluate_source
npm --prefix web test
npm --prefix web run build
git diff --check
```

The generator updates `schemas/`, `examples/`, and the frontend API types from the
Python models and canonical inputs. Frontend tests use the generated examples;
edit their source inputs/builders instead of maintaining separate mock reports.
Independent evaluation labels in `tests/fixtures/source/` are never generated
from scanner output. GitHub Actions verifies tests, builds and artifact drift.
Board browser tests require Chrome/Chromium and skip when it is absent.

## Learn the project

- [Architecture, shared contract and exports](docs/architecture.md)
- [Assessment rules and scoring](docs/assessment.md)
- [Scanner support, cloud demos and source evaluation](docs/scanners.md)
- [API transport and examples](docs/api.md)

The original [team plan](QUANTUMTRACE_PLAN.md) and
[task board](QUANTUMTRACE_TASK_BOARD.html) remain historical coordination artifacts;
the guides above describe current behavior. Board progress is browser-local.

This is a synchronous local MVP with no authentication or persistent database.
The newest 100 scans live in one process and disappear on restart. Bind the API to
`127.0.0.1`. Evidence should contain metadata, not private keys or secret material.
A processed input, a favorable primitive classification, or a valid export does
not establish whole-application security; unknowns and coverage remain explicit.
