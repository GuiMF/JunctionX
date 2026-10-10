# Source discovery (task 02)

The default local API now accepts raw Python (`.py`), Java (`.java`) and Go (`.go`)
files. Submit one file's text as `content` and its repository-relative filename as
`name`, with `source_type: source` and `format: raw`. UTF-8 and base64-encoded UTF-8
are supported. The API never opens `name`, imports source or runs submitted code.

The checked-in [raw handoff request](../examples/scan-source.request.json),
[assessed response](../examples/scan-source.response.json) and
[validated CBOM](../examples/scan-source.cdx.json) demonstrate risky RSA,
an AES-256-GCM primitive, and unresolved AES key parameters.

```sh
.venv/bin/python -m scripts.scan_source tests/fixtures/source --synthetic \
  --output reports/source.json --cyclonedx-dir reports/source-cbom
.venv/bin/python -m scripts.scan_source ../JunctionX-QuantumTrace/sample-repos \
  --synthetic --output reports/organizer-source.json
.venv/bin/python -m scripts.evaluate_source
```

The CLI reads a local directory explicitly selected by its caller. It selects
`.py`, `.java`, `.go`, skips `.git`, `.venv`, `node_modules` and caches, and reports
symlinks, oversized files and unreadable files. It sends up to 16 files per scan
within request byte limits. The output contains separate scan results and scores;
it does not claim a combined repository score. Exit 1 means there were file errors,
failed/partial scans, or no source files. Findings do not cause a nonzero exit.
Use `--synthetic` for organizer and other synthetic examples.

## Detection and evidence

The original bounded detector is pinned as `quantumtrace-source 0.1.0`, rules
`source-api-v1`. Python uses the standard-library AST. Java and Go use lexical
tokens and supported API patterns, not compilers or whole-program analysis.
See [Python AST documentation](https://docs.python.org/3.12/library/ast.html).

Supported families include RSA generation/signature APIs, Ed25519, AES factories
and explicit ECB/GCM configuration, MD5, SHA-1, SHA-2, PBKDF2 factories and HMAC.
Specific supported and unsupported examples are documented in the
[labelled evaluation](source-evaluation.md) and language regression tests.
Imports, comments and string mentions alone are not crypto usage. Aliases and
simple constants are resolved conservatively; dynamic values remain null.

All findings are `declared`, with null observation timestamps. Evidence gives
file, 1-based line/column, API, detector version and detector rule. No raw source,
literal keys or passwords are included. Core assessment replaces `rule_id` with
the assessment rule; detector identity survives in evidence and tool versions.
Columns are parser positions (Python AST UTF-8 byte offsets, Java/Go character
offsets). IDs use filename, position and occurrence slot. Editing an algorithm or
parameter at the same call site keeps identity; inserting lines, moving calls,
renaming files or changing usage can change IDs. No semantic refactoring match is
claimed.

Nested hash constructor calls are separate hash observations, even when a parent
signature/KDF/MAC also records the digest parameter. A reference to a constructor
without calling it is not a hash observation. AES inside a Python `Cipher` is one
occurrence at `Cipher`; Go GCM construction enriches the bound AES block factory.
Java factories are occurrence anchors; bound initializer calls can add parameters.

RSA generation keeps usage unknown. Core rules 1.0.2 classify the known RSA
primitive as quantum-vulnerable and flag explicitly weak key sizes while asking
the user to establish usage before choosing a replacement. This follows the
existing [NIST rationale](https://csrc.nist.gov/projects/post-quantum-cryptography/faqs).
HMAC remains a MAC, and Ed25519 remains a classical signature.

## Boundaries and honest unknowns

- Files are limited to 1 MiB and 5,000 occurrences; excessive input fails visibly.
- A processed file is one assessed file even with zero findings or dynamic
  parameters. That is processing coverage, never proof of cryptographic safety.
- Unsupported extensions count as unsupported files. UTF-8/parse/limit failures
  count as failed files; other submitted files continue.
- Python syntax is parsed without execution. Java/Go lexical errors and delimiter
  failures are detected; passing them does not prove valid Java/Go syntax.
- No interprocedural key-size inference, external dependency/source resolution,
  reachability proof or comprehensive data-flow analysis. A function default does
  not establish that every call uses that default. Local bindings can be unknown.
- Bare AES block creation does not establish a mode. Handwritten Go ECB loops and
  handwritten PBKDF2 are evaluation gaps rather than fabricated matches.
- Python signature calls require a resolved cryptographic receiver; an untyped
  function parameter with padding arguments alone does not prove the API. Such
  organizer calls stay in the evaluation denominator as misses.
- Imports and APIs can be dynamically replaced at runtime; all evidence remains
  a static declaration. Unsupported wrappers and language constructs can be missed.

Explicitly supplied `AdapterRegistry()` instances remain empty; call
`registry.register("source", scan_source)` when using a custom registry. The
default service registers source discovery and the cloud adapter integrated on
main. PCAP discovery remains a separate workstream. Normalized fixture imports
keep their existing synthetic behavior.

## CryptoScan reuse trial (S1)

Evaluated [CryptoScan v1.4.0](https://github.com/csnp/cryptoscan/releases/tag/v1.4.0),
commit `11f0e46`, Darwin arm64 binary SHA-256
`b44a7d329e6ab83757b1449f3c1f2f37fe4d4a688e1eff4cf8d7f4022bbd2b5e`.
The downloaded archive's checksum matched its release digest. Command:

```sh
cryptoscan scan /path/to/sample-repos --include '*.py,*.java,*.go' \
  --include-quantum-safe --format json --output trial.json --stream=false
```

The actual run returned exit 1 with a JSON report: 72 findings, 23 files reported
scanned (7 Python, 8 Java, 8 Go), versus 24 source files in the pinned organizer
tree. This discrepancy was not treated as complete coverage. File/line evidence
exists, but sampled RSA/AES findings had no structured key-size/mode fields, and
matches included imports and type references. Ed25519 appeared as generic ECC.
The output's usage/risk labels and blanket RSA migration guidance do not directly
match the shared contract. These observations justify the board's bounded-rule
fallback; they are not a precision/recall benchmark of CryptoScan.

No CryptoScan source or executable is bundled or used at runtime. The trial
archive (including its Apache-2.0 LICENSE) remains an external evaluation tool.
The new detector is original code and adds no third-party dependency. Organizer
source is scanned from an external checkout, not copied into this repository;
the evaluation stores labels and hashes with its source commit.
