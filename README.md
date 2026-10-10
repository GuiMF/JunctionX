# QuantumTrace

QuantumTrace discovers cryptographic facts in Python/Java/Go source, saved network
captures and AWS JSON snapshots. A shared rule engine assesses findings, calculates
asset exposure, and exports JSON or a schema-validated CycloneDX 1.6 CBOM.

The React dashboard starts with synthetic demo fixtures. Open **Import data**, select source,
AWS snapshot, or capture files and click **Scan selected files** to analyze them
with the local API, inspect the returned findings, and export the active scan.

## Run locally

Use Python 3.12+ and Node.js 22+ with npm. From the repository root, start the API:

```sh
./scripts/run-local.sh
```

This creates `.venv`, installs pinned dependencies on first use, and starts
`http://127.0.0.1:8000`. Set `PYTHON=python3.13` or `PORT=8001` if needed.
The API contract is at `/openapi.json`; interactive documentation is at `/docs`
(the Swagger UI loads assets from a CDN).

In another terminal, start the dashboard:

```sh
cd web
npm ci
npm run dev
```

For a custom API port, set the same origin in the frontend (restart Vite after changes):

```sh
# Backend terminal, from repository root
PORT=8001 ./scripts/run-local.sh
# Frontend terminal, from web/
VITE_API_BASE_URL=http://127.0.0.1:8001 npm run dev
```

`VITE_API_BASE_URL` defaults to `http://127.0.0.1:8000` and is used for scans and
both live exports. It is a build-time setting; set it for `npm run build` too.

Open the URL printed by Vite, normally `http://localhost:5173`. Stop either server
with Ctrl-C. npm commands belong in `web/`; there is no root Node application.

Scanning and export work offline after setup. PCAP parsing additionally requires
TShark installed on the host. Source and cloud scans do not require TShark.

## Dashboard workflow

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
in separate folders. Individually selected files are grouped together.

Select 1–10,000 files with unique relative paths. Encoded inputs are limited to 64 MiB each and
256 MiB combined, including base64 expansion and the combined AWS bundle. Invalid
selections explain how to correct them before submission. Source files separately
allow up to 16 MiB and 20,000 detected occurrences per file. The previous result stays
visible while scanning. A returned `partial` or `failed` result replaces it and
shows per-input errors; `201` alone does not mean all inputs succeeded.

Use **Retry scan** after fixing a connection problem, or reselect corrected files.
Scans time out after 5 minutes; exports after 10 seconds. **Cancel scan** or
**Load demo dataset** discards pending results in the browser (server work may continue).
Reset restores the offline demo and its JSON/CBOM exports. Live exports use the
active scan ID; if it was evicted or the API restarted, scan the files again.
The migration tab is a separate, labeled synthetic demo comparison.

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
Python models and canonical inputs. The frontend imports the generated examples;
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
