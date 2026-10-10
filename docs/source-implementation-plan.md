# Task 02: source discovery implementation plan

## Scope and acceptance

Implement board tasks S1–S5 on `feat/02-source-discovery`, branched from main
at `69b38fc`. Preserve the shared v1 contract and deterministic core assessment.
Before publishing, rebased onto `b23d35b` after the cloud adapter merged into main;
the default registry now includes both scanners, with a mixed-input API/export
regression protecting cloud inventory and snapshot fields.
Deliver offline Python, Java and Go scanning of inline source, exact file/line
evidence, versioned detector identity, conservative parameters, and a reproducible
labelled evaluation of the 24 organizer files plus independent holdout variations.
All findings are `declared`; source analysis never proves runtime execution.

## Design

1. **S1 — bounded reuse evaluation.** Inspect CryptoScan's primary documentation,
   try a pinned release against the organizer corpus if installation is available,
   record actual results or the concrete setup blocker. Do not reuse its risk
   labels. If setup or normalization is awkward, use original bounded API rules
   with a version constant; retain provenance/notices for any copied material.
2. **S2 — adapter and transport.** Add `adapters/source.py` exporting
   `scan_source(ScanInput, AdapterContext) -> AdapterResult`. One inline input is
   one file, dispatched by `.py`, `.java`, or `.go`; never read input.name as a
   path, execute source, fetch URLs, or unpack archives. Decode using the existing
   helper. Unsupported extensions and parse failures get disjoint file coverage
   and sanitized errors. Default service registers source scanning; explicit
   custom registries keep their existing semantics. CLI scans local directories
   in batches respecting the 16-input API bound and uses relative evidence paths.
3. **S3/S4 — bounded parsers.** Python uses stdlib AST plus import/alias resolution;
   Java/Go use a small tokenizer that excludes comments and strings from call
   matching, resolves imports and simple local constants, and tracks calls and
   direct receiver assignments conservatively. Share a small internal occurrence
   structure: `Detection(line, column, algorithm, usage, parameters, api, rule)`
   in `adapters/source_common.py`; parsers expose `detect(text) -> list[Detection]`.
   Generate IDs from input name plus source location/slot, excluding mutable
   algorithm and parameters; document line-edit identity limitations. Evidence
   contains API/rule metadata rather than raw source or secret literals.
4. Cover RSA generation and RSA/SHA-1 signing, Ed25519, AES ECB/GCM, MD5, SHA-1,
   SHA-2, PBKDF2 and HMAC for documented APIs. Resolve only direct literals,
   simple constant references and explicit local lengths; bytes become bits only
   for APIs with byte units. Unresolved values stay null. Do not infer key size
   across arbitrary functions, infer AES mode from a bare block cipher, or label
   a hand-written KDF as PBKDF2 without sufficient semantic evidence. Recognized
   crypto factories with dynamic algorithms yield unknown observations. Imports,
   comments, strings, lookalike APIs and alias shadowing must not produce confident
   false findings. Record unsupported custom implementations as known gaps.
5. **S5 — evaluation.** Build a checked-in, manually labelled synthetic corpus and
   holdout variations covering all three languages, risky/resilient/unknown facts,
   aliases, comments, unused imports, strings, dynamic parameters and byte/bit
   conversion. Separately label and scan the 24 local organizer sources at pinned
   commit `39e8f18dcfb5edc66eda0f47bb44884aa7db5c9c`; do not copy unlicensed
   organizer code into this repository. An evaluation script accepts the corpus
   path, uses occurrence-level labels (file/line/algorithm/usage plus supported
   parameters), reports TP/FP/FN and precision/recall with denominators, exposes
   known gaps, and never derives expected labels from scanner results.

## Work division after plan review

- Agent A: Python parser and Python regression tests; owns
  `adapters/source_python.py`, `tests/test_source_python.py`.
- Agent B: Java/Go tokenizer and parsers, language tests; owns
  `adapters/source_jvm_go.py`, `tests/test_source_jvm_go.py`.
- Agent C: labelled fixtures/evaluation and its tests; owns
  `tests/fixtures/source/`, `scripts/evaluate_source.py`,
  `tests/test_source_evaluation.py`, `docs/source-evaluation.md`.
- Coordinator: common contract, adapter/service registration, CLI, integration
  tests, README/API/scanner docs, reuse evaluation, review and release checks.

The review agent checks scope, unsupported claims, parser false positives,
identity/coverage semantics, evaluation independence and integration risks before
implementation agents start. Share finalized interfaces before parallel edits.

## Validation and PR gate

Plan review completed in [source-plan-review.md](source-plan-review.md). Accepted
clarifications: the common Detection interface has 1-based positions, Parameters,
stable slot and confidence; Java/Go expose `detect_java` and `detect_go`. Nested
hash constructor calls are independent occurrences; constructor references are
not. RSA key generation has unknown usage. File coverage is assessed after
successful bounded processing even if no findings or parameters are unknown.
Scope/order/reassignment invalidate uncertain bindings. Java/Go perform lexical
validation only. CLI batching also honors byte limits and reports unreadable files.
Evaluation separates detection recall from parameter correctness and retains
known-gap misses. These requirements are passed to each implementation agent.

Run the complete pytest suite, dependency check, normalized in-process demo,
source CLI and labelled evaluation, API raw-source-to-CycloneDX validation, and
generated-artifact drift check. Inspect the diff and independently review scanner
edge cases; fix material findings. Record exact results and limitations. Commit
only task changes, push this branch and open a PR targeting main. Verify remote
main ancestry before publishing when network access is available. Do not merge.
