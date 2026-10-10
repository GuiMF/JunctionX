# Task 02 release verification

Implemented S1–S5 after an independent plan review, with separate implementation
agents for Python, Java/Go, and the labelled evaluation. An independent code review
found five correctness issues; all were fixed and their reproductions rerun. See
[plan review](source-plan-review.md), [code review](source-code-review.md),
[scanner guide](source-discovery.md), and [accuracy results](source-evaluation.md).

The branch was created from main `69b38fc`, then rebased onto main `b23d35b`
after the cloud workstream merged. Registry wiring preserves cloud and source
scanning together. A mixed raw cloud/source HTTP request and its CBOM are tested,
including the cloud inventory and snapshot metadata. Main was not modified.

Local release checks on 2026-10-10:

- Before rebase: complete suite, 268 passed.
- After rebase and the mixed-input regression: 312 passed, 12 subtests passed with
  `pytest -q --ignore=tests/test_board.py`.
- Full post-rebase run also attempted the two unchanged browser-board tests;
  local Chrome aborted at launch (return code -6) before either assertion suite
  could run. These tests are unchanged from main and remain enabled in CI.
- `pip check`: no broken requirements.
- Normalized in-process demo: completed, validated CBOM, expected partial failure.
- Source CLI: nine synthetic files and all 24 organizer files processed; per-batch
  CBOMs validated. Files stayed within the 16-input and byte limits.
- Independent labels: holdout 26 TP / 0 FP / 0 FN; organizer 48 TP / 0 FP / 4 FN.
  All 75 scored parameter fields across the two corpora matched. Four misses stay
  visible; these small corpora do not establish general production accuracy.
- Generated contracts/examples reproduced with no drift; `git diff --check` clean.

The existing Starlette/httpx deprecation warning is unchanged. Java/Go parsing is
bounded lexical recognition; Python has no interprocedural type inference.
Scanner and policy versions, unresolved parameters, declared evidence semantics,
and the real CryptoScan trial results are documented in the scanner guide.
