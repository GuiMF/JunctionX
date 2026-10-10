# QuantumTrace core backend

Task 04 connects discovery adapters to deterministic cryptographic assessments,
an asset-based score, and JSON/CycloneDX reports. This branch implements the
shared backend; teammates supply the network, source, and cloud scanners.

## Run locally

Install Python 3.12 or newer, then from this repository:

```sh
./scripts/run-local.sh
```

The script creates `.venv`, installs pinned dependencies on first use, and starts
one local server at `http://127.0.0.1:8000`. Initial setup requires package download
access; scanning and export run offline. Set `PYTHON=python3.13` if appropriate,
or `PORT=8001` to choose another port. Stop with Ctrl-C.

The API contract is at `/openapi.json`. The optional interactive Swagger page is
at `/docs` and loads its UI assets from a CDN. Checked-in schemas and the demo
command below work without that page or an internet connection.

In another terminal, exercise all three synthetic inputs and save both exports:

```sh
.venv/bin/python -m scripts.demo
```

Read `reports/demo-summary.json`, `reports/scan.json`, and `reports/scan.cdx.json`.
These are explicitly labelled integration fixtures, not organizer-input scans.
Raw inputs return `unsupported_adapter` until a teammate's scanner is registered.

If the environment blocks opening local ports, exercise the same HTTP routes
without a server socket with `.venv/bin/python -m scripts.demo --in-process`.

## Review and integrate

- [Implementation plan](docs/implementation-plan.md) maps E1–E5 to deliverables.
- [Review report](docs/review-report.md) explains changes, validation, and remaining handoffs.
- [Shared contract](docs/contract.md) explains fields, IDs, and adapter responsibilities.
- [API and adapter integration](docs/api.md) gives endpoints and registration code.
- [Assessment policy](docs/assessment.md), [scoring policy](docs/scoring.md), and [export mapping](docs/export.md) explain results.
- [Example request](examples/scan-original.request.json) and [response](examples/scan-original.response.json) unblock the frontend.
- [Original project plan](QUANTUMTRACE_PLAN.md) and [task board](QUANTUMTRACE_TASK_BOARD.html) retain the team-wide scope.

## Verify

```sh
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m scripts.generate_contract
git diff --check
```

The generator refreshes JSON schemas, OpenAPI, role examples, before/after requests,
and a validated sample CBOM. Generated examples use fixed timestamps/scan IDs for
reproducibility; actual scans use their real start time and a fresh scan ID.

This is a local, synchronous MVP: newest 100 scans in memory, one process,
no authentication or persistent storage. Restarting clears stored scans.
Evidence should contain metadata only; adapters must not emit private keys or
other secret material. Scan input contents are hashed but not stored in results.
