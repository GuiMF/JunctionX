# QuantumTrace discovery backend

Task 04 connects discovery adapters to deterministic cryptographic assessments,
an asset-based score, and JSON/CycloneDX reports. This branch implements the
shared backend, raw cloud snapshots and task 02 source discovery; network
discovery remains a separate workstream.

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
Raw Python, Java and Go inputs use the built-in source scanner, and raw cloud
snapshots use the cloud adapter. Raw network inputs return `unsupported_adapter`
until their scanner is registered.

Scan local source and export validated CBOMs:

```sh
.venv/bin/python -m scripts.scan_source tests/fixtures/source --synthetic \
  --output reports/source.json --cyclonedx-dir reports/source-cbom
```

See [source discovery](docs/source-discovery.md) for supported APIs, evidence,
limits, the CryptoScan trial, and the [labelled evaluation](docs/source-evaluation.md).

If the environment blocks opening local ports, exercise the same HTTP routes
without a server socket with `.venv/bin/python -m scripts.demo --in-process`.

## Review and integrate

- [Implementation plan](docs/implementation-plan.md) maps E1–E5 to deliverables.
- [Source plan](docs/source-implementation-plan.md) and [plan review](docs/source-plan-review.md) cover S1–S5.
- [Review report](docs/review-report.md) explains changes, validation, and remaining handoffs.
- [Shared contract](docs/contract.md) explains fields, IDs, and adapter responsibilities.
- [API and adapter integration](docs/api.md) gives endpoints and registration code.
- [Assessment policy](docs/assessment.md), [scoring policy](docs/scoring.md), and [export mapping](docs/export.md) explain results.
- [Example request](examples/scan-original.request.json) and [response](examples/scan-original.response.json) unblock the frontend.
- [Original project plan](QUANTUMTRACE_PLAN.md) and [task board](QUANTUMTRACE_TASK_BOARD.html) retain the team-wide scope.
- [Cloud adapter](docs/cloud-adapter.md) documents raw snapshot input, directory CLI,
  configured TLS capabilities, and synthetic migration/renewal fixtures.

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

GitHub Actions runs tests, the in-process demo, dependency checks, and generated
artifact drift checks on every push and pull request.

This is a local, synchronous MVP: newest 100 scans in memory, one process,
no authentication or persistent storage. Restarting clears stored scans.
Evidence should contain metadata only; adapters must not emit private keys or
other secret material. Scan input contents are hashed but not stored in results.
