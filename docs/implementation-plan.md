# Task 04 implementation plan

Build the shared Python backend on `feat/04-core-integration`, branched from local `main` at `de99139`. The user confirmed FastAPI, Pydantic, and all five task steps. Other teammates are building the discovery adapters concurrently.

## Scope and ownership

| Step | Implementation | Review evidence |
| --- | --- | --- |
| E1 Shared contract | Pydantic models, JSON schemas, stable ID helpers, source/network/cloud example envelopes, API request examples | Contract validation and identity tests |
| E2 Integration skeleton | Adapter registry, isolated per-input dispatch, synchronous FastAPI endpoints, in-memory scan store | API tests including partial failures and exports |
| E3 Assessment | Versioned deterministic rules with primary references and conservative unknown handling | Labelled algorithm and evidence edge cases |
| E4 Score and export | Asset-based published heuristic, JSON export, CycloneDX 1.6 export with vendored validation schemas | Duplicate/unknown scoring tests and schema validation |
| E5 Release gate | Pinned dependencies, local start command, reproducible demo, teammate integration guide and review report | Full automated suite and HTTP smoke test |

The parent agent owns the contract, identity, scoring, examples, packaging, and final review. Three subagents own assessment, API/orchestration, and CycloneDX export respectively. All work is on this feature branch with distinct file ownership.

## Decisions

Use Python 3.12 or newer. Start synchronously with JSON request bodies carrying file contents (UTF-8 or base64), so callers never specify a server filesystem path. A normalized fixture importer exercises integration until the real adapters arrive; fixture scans are labelled synthetic. Raw inputs without a registered adapter return an explicit unsupported result.

Store scans in bounded process memory for the local hackathon. Restarting clears them. No database, production deployment, authentication, live cloud remediation, or UI is part of this task.

Separate detector evidence, quantum assessment, classical weaknesses, and operational posture. Never infer safe status from missing observations or inflate scores with repeated packets. Validate CycloneDX offline against a pinned official schema.

## Integration and release sequence

1. Define the shared models and helpers before integrating agent implementations.
2. Build assessment and export concurrently with the scan API.
3. Commit example envelopes for each adapter role and a complete frontend response.
4. Exercise a complete scan → retrieval → JSON/CBOM export flow.
5. Test unknowns, duplicate sightings, conflicting IDs, parser failures, unsupported adapters, and explicit relationships.
6. Record verified behavior, commands, design decisions, and outstanding teammate handoffs in the review report.

The contract is a concrete proposal ready for teammate review. Their agreement and real scanner integration remain external handoffs; fixture tests cannot certify their discovery accuracy. No remote push or merge is required for this local implementation.
