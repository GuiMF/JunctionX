# QuantumTrace

QuantumTrace discovers cryptographic facts in Python/Java/Go source, saved network
captures and AWS JSON snapshots. A shared rule engine assesses findings, calculates
asset exposure, and exports JSON or a schema-validated CycloneDX 1.6 CBOM.

The React dashboard currently displays generated demo fixtures. Selecting files
in the UI does not submit them to the backend yet. Use the API or CLI for scans.

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

Open the URL printed by Vite, normally `http://localhost:5173`. Stop either server
with Ctrl-C. npm commands belong in `web/`; there is no root Node application.

Scanning and export work offline after setup. PCAP parsing additionally requires
TShark installed on the host. Source and cloud scans do not require TShark.

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
