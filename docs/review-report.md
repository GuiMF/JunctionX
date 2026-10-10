# Task 04 implementation review

Task 04 now has a working local backend: one shared contract, a scan API,
deterministic assessment rules, reproducible asset scoring, and validated
CycloneDX 1.6 exports. The network, source, and cloud scanners remain teammate
deliverables; the included synthetic fixtures let everyone integrate now.

Work is on `feat/04-core-integration`, based on `main` commit
`de99139d9b5693fb420efed05e6875e360184637`. A successful remote fetch confirmed
`origin/main` at the same commit. The original project plan and task board remain
the team-wide reference.

## What was built

| Task | Files to review | Result |
| --- | --- | --- |
| E1 Shared contract | `core/models.py`, `core/identity.py`, `schemas/`, `examples/adapters/` | Validated models and JSON schemas, explicit unknowns, stable IDs, error/coverage/relationship contracts, role examples, generated OpenAPI |
| E2 Integration skeleton | `adapters/`, `core/service.py`, `api/main.py` | Registry, isolated input processing, synchronous create/get/export endpoints, bounded result storage, fixed adapter evaluation context |
| E3 Assessment | `core/assessment.py`, `docs/assessment.md` | Versioned rules with cited explanations and usage-specific migration advice |
| E4 Score and CBOM | `core/scoring.py`, `export/cyclonedx.py`, `schemas/vendor/` | Documented asset-level heuristic, lossless project JSON, offline validated standard export |
| E5 Release checks | `tests/`, `scripts/`, `requirements.txt`, `README.md` | Pinned environment, startup/demo commands, generated handoffs and regression suite |

The parent agent implemented the contract, IDs, scoring, examples, packaging,
documentation, and integration verification. Three subagents implemented
assessment, API/orchestration, and CycloneDX export. They also reviewed each
other's work. Review fixes include conflicting owner handling, distinguishing
not-applicable from unknown, contradictory algorithm/group metadata, TLS 1.2
group handling, exact export algorithm matching, and embedded AES parameters.

## How the backend works

1. The caller submits named inline contents as UTF-8 or base64. No API-supplied
   filename is opened on the server.
2. The service hashes decoded input and selects its registered adapter. A fixed
   `evaluated_at` reaches each adapter through an independent context object.
3. Each adapter returns facts with evidence and coverage. The core validates its
   output and retains successful inputs if another input fails.
4. Versioned rules assess normalized facts. They keep quantum exposure, classical
   weaknesses, operational posture, confidence, and evidence kind separate.
5. Duplicate finding IDs merge corroborating evidence. The score weights each
   assessed asset once, using its worst known quantum tier.
6. The response is retained in process memory and can be retrieved or exported.
   Every CBOM export validates against the pinned official schema before return.

The minimal API uses JSON bodies containing file contents. Multipart upload,
background jobs, persistent storage, authentication, and deployment are outside
this local MVP. The default store keeps the newest 100 scans and clears on restart.

## Decisions that affect interpretation

Unknown values never become safe. Offered groups are excluded from the score;
configured capability never becomes observed negotiation. Unknown-only assets
are excluded from the score denominator with visible counts. A low score concerns
known quantum exposure only and must be displayed with classical issues and
unknowns. Scoring weights are `critical: 100`, `medium: 50`, `resilient: 0`.

Stable IDs identify a resource and cryptographic role, so a configuration change
can be compared across scans. The core rejects conflicting facts under one ID
within the same scan instead of silently choosing one. Cross-source correlations
require explicit identity evidence from adapter owners.

Assessment never consults an AI service. It preserves detector confidence and
provides source URLs with each applicable rule. Primitive resilience does not
certify an application. See the bounded algorithm coverage and qualifications in
[assessment policy](assessment.md).

CycloneDX uses real `cryptographic-asset` components and standard evidence
occurrences. All original finding and scan fields also survive in namespaced
properties. Explicit, unambiguous dependency relationships use standard edges;
other relationship types and unresolved/ambiguous links remain visible in project
properties. Schema validation establishes structure, not detector accuracy.

## Verification results

**180 tests pass** after the PR review. The regression suite covers models and IDs, assessment rules, scoring, parser
failures, bad adapter output, concurrent result storage, the HTTP API, exports,
generated schemas, and all three example source types. It also verifies that
adapter mutation cannot change another input's evaluation time.

The breakdown is 83 assessment cases, 30 export cases, 40 API/service cases,
23 contract/identity/scoring cases, and 4 complete example-flow cases. The API
cases include browser preflight requests for explicit local development origins
and rejection of other origins. Generated schemas and examples reproduce exactly.

The pinned dependencies were installed into a separate fresh Python 3.12
environment using downloaded wheels for the initial 142-test release. That suite
and the in-process HTTP demo passed there. The expanded suite and demo passed in
the project environment after review, and `pip check` reported no broken requirements. One upstream
Starlette/httpx deprecation warning remains; it does not fail the suite.

The synthetic demonstration produced:

- 10 findings across source, network, and cloud examples, representing 8 assets.
- 7 assessed assets, 1 unknown-only asset, and 2 assets containing unknown findings.
- Original exposure score 85.71, with independent classical/posture counts.
- A schema-valid CycloneDX 1.6 report retaining evidence and provenance.
- Exactly one configured finding changed in the modified example, with stable
  identity and unchanged network observations.
- A partial scan that retained all 10 successful findings when an additional raw
  input had no registered scanner.

The startup script installed/verified dependencies and reached application startup.
The execution sandbox denied binding `127.0.0.1:8014`, so an actual listening
server could not be verified here. HTTP routes were exercised through FastAPI's
in-process ASGI client instead. The remaining local check is to run the documented
server command in a normal terminal and run the live demo against it.

## PR review fixes

Three subagents independently reviewed the API/service, assessment rules, and
CBOM export. The parent reviewed contracts, scoring, identity, integration, and
the fixes themselves. The review added 38 regression cases and corrected:

| Issue | Result after the fix |
| --- | --- |
| HTTP 422 validation errors echoed complete input contents | Error responses retain type, location, and message while omitting submitted values and exception context |
| Tool-version names collided when input or tool names contained slashes | Each namespace segment is independently percent-encoded, preserving both versions |
| Conflicting signature metadata could claim resilience | Unsupported or contradictory algorithm/group pairs remain unknown |
| Conflicting AES/HMAC metadata hid ECB or MD5 issues | Both claims remain visible, including the weakness, without a resilient verdict from contradictions |
| Compatible algorithm-family/group combinations became unknown | ML-KEM, DH/DHE, EC/ECC, and equivalent curve aliases now refine consistently |
| Curve-only signature findings exported as key agreement | Ambiguous curve use retains unknown primitive; cipher modes no longer attach to signatures, hashes, MACs or KEMs |
| Reordering findings changed an otherwise identical CBOM serial | The serial derives from canonical exported content after sorting |
| Duplicate owner checks repeatedly traversed all prior observations | Owner tracking is incremental; conflicts are still rejected in any order |

The ruleset is now `1.0.1`; generated responses and CBOM were refreshed. A local
10,000-observation duplicate probe fell from approximately 0.73 seconds to 0.05
seconds; this is a small local measurement, not a production benchmark.

GitHub Actions now runs the test suite, dependency check, in-process demo, and
generated-schema/example drift check on pushes and pull requests. Action revisions
are pinned and workflow permissions are read-only.

One assessment limitation remains explicit: generated and detector-provided issue
lists do not carry separate provenance. After changing facts, reassess fresh
adapter output, not an edited previously assessed result; otherwise historical
issue/reference strings intentionally remain. The engine does not guess which
supplied issues to delete.

## What remains for the team

1. Review and agree the shared contract, particularly identity slots, coverage
   units, and evidence conventions. This implementation is a concrete proposal,
   not a claim that teammates have already approved it.
2. Register the three real scanners using [the API handoff](api.md). Each accepts
   `ScanInput` and `AdapterContext`, returning `AdapterResult`.
3. Run organizer inputs and each owner's labelled fixtures to measure actual
   discovery accuracy. Current tests verify core logic with synthetic facts.
4. Connect the frontend to the generated response examples and real endpoints.
5. Rehearse the complete UI plus scanners on a normal local launch before marking
   the team-wide release gate complete.

Normalized fixture imports always carry `synthetic: true`; raw inputs without a
scanner return explicit unsupported errors. No real source scanner, TShark
parser, AWS policy mapping, live cloud change, frontend, or production deployment
was added in task 04. No private keys or organizer datasets are included.

## Review commands

```sh
./scripts/run-local.sh
# In another terminal:
.venv/bin/python -m scripts.demo
.venv/bin/python -m pytest -q
```

For a port-restricted environment, use:

```sh
.venv/bin/python -m scripts.demo --in-process
```

Generated artifacts are under `reports/` and ignored by Git. Checked-in examples
under `examples/` use fixed metadata so reviewers can compare changes. Start with
[the shared contract](contract.md), then the example response, scoring policy,
assessment rules, and export mapping. No push or merge is part of this handoff.
