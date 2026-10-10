# Report exports

The API supports project JSON and CycloneDX 1.6. Project JSON is the complete
`ScanResult.model_dump(mode="json")` contract. For CBOM use
`export.cyclonedx.export_cyclonedx(scan)`; it returns a dictionary **after validating**
it against the full pinned schema. `validate_cyclonedx(document)` is also public.

## CycloneDX mapping

Each normalized finding becomes one `cryptographic-asset` component identified by
`quantumtrace:finding:<finding.id>`. Separate occurrences stay separate, even when
they use the same algorithm. The original asset ID is retained as
`quantumtrace:asset_id`, permitting consumers to group findings on one resource.
This exporter does not invent certificate/key component types from asset names:
the Finding contract describes algorithm occurrences, not full certificate/key
records. Explicit TLS/SSH observations can be represented as protocol assets.

Exact normalized names share the assessment engine’s pinned taxonomy and map
to the standard primitive field. Embedded AES parameters (for example
`AES-256-GCM`) and supplied parameters map to standard algorithm properties.
Conflicting embedded/supplied AES facts produce primitive `unknown` without
choosing either parameter value; both original claims survive in properties.
Family-like names such as `AES-SOMETHING` are not accepted as known primitives. Unknown algorithms retain
their original name and primitive `unknown`. Unsupported modes become `other`
while the original value remains in project properties. A key length is never
reported as a security-strength value. No NIST quantum level is inferred.

Exact evidence files become standard component `evidence.occurrences`; their
locator, detail, and evidence kind remain in `additionalContext`. All finding
fields, including evidence, owner, nulls, quantum status, classical issues,
posture issues, parameters, recommendation, and references, also survive as
`quantumtrace:<field>` properties. Strings are stored literally; objects, arrays,
nulls, numbers and booleans use JSON text. These properties are the authoritative
lossless representation of the shared project contract.

Scan fields other than findings are retained in metadata properties, including
coverage, errors, scores, tool/rule versions, input hashes, synthetic labels,
and explicit relationships with their evidence. This preserves unresolved
references and typed relationships without guessing links. Only `depends_on`
relationships whose two asset IDs each resolve to exactly one component also
become standard dependency edges. Other kinds, unresolved targets, and assets
with multiple algorithm components remain in the project relationship list.
Omitted dependency nodes mean unknown dependencies, not proven absence.

The report timestamp is the scan's evaluation timestamp. A UUIDv5 serial number
is generated from the full canonical scan content; identical scans produce
identical output and changed content gets a different serial number. No wall
clock, random ID, external service, or file beyond the vendored schema is used
while exporting.

## Offline validation and provenance

Schemas are unmodified copies from the official [CycloneDX specification tag
1.6](https://github.com/CycloneDX/specification/tree/55343ba19dee1785acf1ce9191540d5fd7b590db/schema),
pinned to commit `55343ba19dee1785acf1ce9191540d5fd7b590db`. The full BOM schema,
SPDX schema, and JSF schema are vendored under `schemas/vendor/cyclonedx-1.6/`.
`manifest.json` records exact URLs and SHA-256 hashes; `LICENSE` retains the
upstream Apache-2.0 license. Original embedded attribution remains in each file,
including JSF attribution to Anders Rundgren/OpenKeyStore.

Validation uses the complete Draft 7 schema, date-time/URI format checks, and a
local `referencing.Registry` with no network retriever. The minimal dependency
set does not install the optional IRI-reference format checker; IRI syntax in
externally supplied fields outside our export mapping is therefore not checked.
The exporter itself does not produce fields requiring that checker. Additional checks enforce version 1.6, unique
`bom-ref` values, and resolved local dependency edges, which JSON Schema alone
cannot guarantee. Schema violations raise `jsonschema.ValidationError`;
reference/version violations raise `ValueError`. Schema validation does not
verify cryptographic signatures or prove that a detector's findings are true.

Run `python -m pytest tests/test_export.py` in the project environment. The tests
exercise minimal/populated exports, unknowns, evidence/relationships, ambiguous
and unresolved links, malformed reports, provenance hashes, and both external
schema references with network access disabled.
