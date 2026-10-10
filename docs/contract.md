# Shared contract v1

The source of truth is `core/models.py`. Generated JSON schemas live in `schemas/`.
Examples under `examples/adapters/` show the shape for each scanner owner. This
contract is ready for the team's review; implementing it does not imply the other
owners have already accepted it.

## Objects and ownership

| Object | Meaning | Filled by |
| --- | --- | --- |
| `ScanInput` | Named inline file content, source type, raw/normalized format, encoding | API caller |
| `AdapterContext` | Fixed timezone-aware evaluation time | Core |
| `Finding` | One algorithm occurrence, usage, parameters, exact supporting evidence | Adapter, then core assessment |
| `AdapterResult` | Findings, coverage, errors, explicit relationships, detector versions for one input | Adapter |
| `ScanRequest` | Inputs, optional evaluation time, label and synthetic flag | UI or script |
| `ScanResult` | Full assessed result, versions, hashes, score, errors, coverage and provenance | Core |

`source_type` is `source`, `pcap`, or `cloud`. All fields reject unknown extra keys.
Evidence requires a nonempty `file`, `locator`, and `detail`; `file` is provenance,
not permission to read that path. Use line locations, frame/stream identifiers, or
JSON pointers. Evidence must substantiate the finding without including secrets.

Use canonical algorithms where possible, such as `AES` plus `key_bits: 256` and
`mode: GCM`. Sizes are **bits**, iterations are positive integers, and missing
parameters are `null`. The current optional parameters are `key_bits`, `mode`,
`named_group`, `hash_algorithm`, and `iterations`.

Adapters set identity, source, algorithm, parameters, usage, evidence kind,
evidence, confidence, ownership, observation time, and any independently evidenced
classical/posture issues. The core overwrites quantum status, challenge tier,
rule ID, rationale and recommendation using its versioned rules. Default quantum
fields are `unknown`; pending explanations are `null`. Core rules add classical
issues without discarding detector-supplied ones.

## Meaning of evidence and uncertainty

| Value | Meaning |
| --- | --- |
| `declared` | Source-level declaration; runtime execution unverified |
| `configured` | Configuration snapshot; actual runtime use unverified |
| `offered` | Capability advertised by a peer; selection unverified |
| `observed` | Observation of the specific captured operation |
| `null` | A scalar fact is unavailable |
| `unknown` | A classification cannot be established |
| `not_applicable` | That assessment dimension does not apply; not a safe result |

`observed_at` records the evidence timestamp and stays null when unavailable. For
cloud input, retain the export timestamp, not the time of this scan. `started_at`
is the actual scan start; `evaluated_at` is the explicit evaluation time used for
time-dependent checks. Use `context.evaluated_at` in adapter expiry logic. All
timestamps need a timezone.

An empty issues list means no issues were reported by these checks. It is not
a proof of secure implementation. `confidence` describes detection confidence;
the core preserves it rather than promoting it based on algorithm recognition.

## Stable identity and repeated observations

Use `stable_asset_id(source_type, identity)` with a stable logical resource or
occurrence identity: an ARN, a repository-relative symbol/call-site identity,
or a capture/flow identity. Do not use a mutable algorithm, current key size,
timestamp of the scan, array index that may reorder, or entire file hash as an
asset identity. A network capture hash plus stream can identify a flow inside
one capture; matching flows across different captures requires explicit evidence.

Use `stable_finding_id(asset_id, usage, slot, evidence_kind)` for a stable role
such as `signing-key` or `selected-group`. Independent occurrences and multiple
offered candidates need distinct slots. Keep the role stable when configuration
changes so before/after comparison matches the same finding. Offered and observed
observations always have different IDs.

Deduplication merges repeated **finding IDs** only, retaining distinct evidence,
all issues, a known consistent owner, latest observation time and the lower
confidence. Different facts or conflicting non-null owners under the same finding
ID within a scan reject the offending input. Different facts under the same ID
across two scans are expected during migration. The score separately deduplicates
asset IDs, so multiple findings on one asset cannot inflate its weight.

Explicit relationships contain `source_asset_id`, `target_asset_id`, `kind`, and
nonempty evidence. Unresolved targets remain visible. Similar names or shared
algorithms are not grounds for creating a relationship.

## Coverage and errors

Report coverage by input, source type and unit (`files`, `sessions`, `packets`,
`resources`, or `inputs`). Within each reported population, `assessed`, `unknown`,
`unsupported`, and `failed` are disjoint nonnegative integer counts. If reporting
both sessions and packets, use separate entries; never sum them into a percentage.

Coverage describes the adapter's input processing, while quantum unknown counts
describe the assessment of detected assets. For example, a successfully processed
session can contain known key exchange and unknown authentication. A successfully
checked file with no finding is not an inventoried safe asset.

Errors identify `source_type`, `input_name`, `code`, and a concise non-secret
`message`. An unavailable parser reports one unsupported `inputs` unit because
the true file/session/resource population is not known. An input failure preserves
other successful inputs. Requests with invalid structure are rejected before scanning.

## Handoff

Each adapter owner should review one role example, choose stable identity slots,
and implement `adapter(input: ScanInput, context: AdapterContext) -> AdapterResult`.
The frontend can begin with the complete example response. Registration details
and JSON transport are in [the API guide](api.md).
