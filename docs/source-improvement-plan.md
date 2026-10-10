# Source detection improvement plan

## Goal and baseline

Improve source discovery against the unchanged, hash-pinned organizer corpus and
independent holdout, while preserving precise evidence and conservative unknowns.
The starting organizer result is 48 true positives, zero false positives and four
false negatives out of 52 labelled occurrences (92.31% recall). The holdout has
26 true positives and no false positives or false negatives.

The four gaps are two Python RSA signature calls through function parameters,
a handwritten Go ECB block loop, and a handwritten Go PBKDF2 implementation.
Full coverage of these examples is a target, not permission to guess or weaken
the evaluation oracle.

## Research and implementation workstreams

1. **Python key provenance:** inspect AST binding and call semantics; track
   explicit key provenance through a bounded set of local function returns,
   tuple unpacking and call arguments. Preserve uncertainty for ambiguous,
   shadowed, decorated, mutated or unsupported code. Padding arguments alone
   must never establish a signature receiver's cryptographic type.
2. **Go algorithm structure:** compare the handwritten implementations with
   primary algorithm specifications. Recognize independent AES block processing
   only with evidence excluding chaining. Recognize PBKDF2 only when the HMAC,
   block counter, iteration and XOR dataflow are supported. Identifier names
   and the presence of crypto imports are not algorithm evidence.
3. **Independent review:** challenge both implementations with misleading
   lookalikes, rebinding, mutations, ambiguous control flow and renamed variants.
   Review bounded execution and preservation of existing findings.

Each workstream owns separate implementation/test files. The integration owner
maintains documentation, versions, generated artifacts and release checks.

## Validation gates

- Keep original fixture contents, hashes and expected labels unchanged.
- Compare organizer and holdout detection and parameter metrics before/after.
  Retain existing true positives, zero benchmark false positives and all
  previously correct labelled parameter fields.
- Add independently meaningful positive transformations and negative near misses
  for each new detector. Do not infer general accuracy from a small corpus.
- Run focused tests during development, then the full Python suite, dependency
  check, source evaluation, CLI scan/export and in-process API demonstration.
- Regenerate contracts/examples and verify intentional changes; run frontend
  tests and production build with the supported Node version.
- Complete an independent implementation review and resolve blocking findings.

## Delivery

Use branch `codex/source-detection-improvements` based on `origin/main` in an
isolated worktree. Record achieved metrics, remaining limitations and research
references in the scanner documentation. Commit only this work, push the branch
and open a pull request explaining the behavioral changes and validation.
If a proposed detector cannot satisfy conservative evidence requirements, leave
that miss explicit and document it rather than claiming unsupported accuracy.

## Implementation outcome

All three workstreams completed. Organizer detection improved to 52/52 with
zero false positives; the holdout remains 26/26. The original 48 findings retain
their identities, parameters and evidence locations. All 59 organizer and 25
holdout parameter checks pass. The original fixture files and manifests have no
changes. Added 112 tests, including 40 authored by the independent reviewer.

Local validation passed 452 Python tests and 12 subtests outside the board
browser module, eight frontend tests, the production build, dependency checks,
API demonstration, and source JSON/CycloneDX exports. Both pre-existing board
browser tests produce their passing page result but local macOS Chrome fails to
exit before timeout, including on the baseline. The unchanged full suite also
runs in GitHub Actions for the PR.

Scope and budgets remain explicit: new Python flow is RSA-only; Go recognizes
strict supported idioms. Supplemental work limits preserve ordinary API findings
when further analysis cannot be completed. Independent review found and fixed
callback context, namespace shadowing and deep nesting issues before delivery.
