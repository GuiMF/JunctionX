# Reproducible source discovery evaluation

Run from the repository root with the project's Python environment:

```sh
python scripts/evaluate_source.py
python scripts/evaluate_source.py --organizer-root ../JunctionX-QuantumTrace/sample-repos
```

The default evaluates nine original synthetic source files. The optional command
also evaluates all 24 organizer Python, Java and Go sources pinned to organizer
commit `39e8f18dcfb5edc66eda0f47bb44884aa7db5c9c`. Every input is checked against
its SHA-256 manifest before scanning; changed or missing corpus files fail the
command. The organizer repository is not a runtime dependency. Its source is not
copied here because no reuse license was established. The organizer manifest
contains only relative filenames, content hashes and independently authored facts.
All files are scanned as text through the real `scan_source` adapter; corpus code
is never imported, compiled or executed.

## Oracle and occurrence policy

Expected labels were written by reading numbered source before running the
scanner. They are checked-in JSON, never generated from detections. Synthetic
fixtures cover explicit positives, negative comments/strings/unused imports and
lookalikes, and unresolved algorithm/key parameters in each language. They also
cover aliases, byte-to-bit key length conversion, weak and stronger algorithms,
and direct factory parameters. These are small deterministic regression corpora,
not a representative benchmark of arbitrary production repositories.

An occurrence key is `(relative file, 1-based line, algorithm, usage)`. Matching is
multiset matching: duplicates consume one expected and one observed occurrence
at most. A wrong algorithm, usage or line produces both a false positive and a
false negative. Columns are preserved by scanning but not scored by these labels.

Python Cipher owns its directly nested AES constructor fact; AESGCM is anchored
to its constructor. A called hash constructor is a separate hash occurrence even
inside PBKDF2 or an RSA signature; a bare function reference is not an occurrence.
Java observations are anchored to imported crypto `getInstance` factories;
PBEKeySpec and SecretKeySpec are parameter helpers, not separate observations.
Go NewGCM enriches the bound AES NewCipher observation rather than duplicating it.
RSA generation and Java AES key generation have unknown usage. Ed25519 has
signature usage because the algorithm is a signature primitive. Parameters do
not propagate across functions, and Python's generic webhook sign/verify methods
are outside the explicit API occurrence inventory.

The organizer manifest deliberately retains semantic facts beyond the
bounded API rules: handwritten PBKDF2 at `go/auth-gateway/main.go:55`, and the ECB
block loop at `go/batch-pipeline/main.go:29`. The ECB label is separate from the
bare NewCipher observation, which by itself has no mode. These known gaps remain
in the headline recall denominator. Review also exposed a false-positive risk in
inferring Python RSA signatures from padding arguments on an untyped receiver.
The detector now requires a resolved cryptographic receiver. The two original RSA
signature labels at `python/license_token.py:11` and `:16` remain as known-gap
misses; their expected algorithm, usage and parameter labels were not removed or
changed. A separately named `supported_subset` reports
recall without known-gap labels; it must not replace the headline result.

## Metrics and interpretation

The JSON reports expected/actual occurrence counts, detection TP/FP/FN, precision
`TP / (TP + FP)` and recall `TP / (TP + FN)`, plus every unmatched label and
unmatched detection. A zero denominator yields JSON null, not a perfect score.
File assessment and scan errors are reported separately from detection recall.
Known-gap misses leave the command successful so the report can be inspected;
input-integrity errors or adapter failures produce a nonzero exit status.

Parameter scoring is separate and checks only fields explicitly included in each
manual label. An explicit null means the parameter should remain unresolved; an
omitted field is not scored. Extra detected parameter fields are not penalized by
this subset metric. Matched labelled occurrences, total parameter-labelled
expected occurrences, checked field counts and mismatches are all exposed.
Missing detections are counted by recall, not silently added as parameter passes.
Within duplicate occurrence keys, bipartite matching maximizes complete parameter
matches before the remaining observations are paired. Full production accuracy
cannot be inferred from this subset check or these small corpora.

## Recorded results

Recorded on 2026-10-10 using `quantumtrace-source` 0.1.0 and `source-api-v1`,
then revalidated unchanged with 0.1.1 / `source-api-v2` after the PR #6 additions:

| Corpus | Assessed files | Expected | TP | FP | FN | Precision | Full recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Synthetic holdout | 9/9 | 26 | 26 | 0 | 0 | 100% | 100% |
| Organizer | 24/24 | 52 | 48 | 0 | 4 | 100% | 92.31% |

The organizer's four false negatives are the handwritten PBKDF2/ECB facts and
two untyped Python RSA signature calls described above. Supported-subset recall
is 48/48 (100%); the headline result remains 48/52. There were no scan errors in
either corpus.

All 25 checked parameter fields across 16 matched holdout occurrences were
correct. All 50 checked parameter fields across 25 matched organizer occurrences
were correct. The organizer has 29 parameter-labelled expected occurrences;
the four missing semantic occurrences were not part of parameter accuracy.

Validation: `.venv/bin/python -m pytest tests/test_source_evaluation.py -q`
passed all 8 tests. The documented evaluation command produced these counts
against the hash-pinned organizer files. Run it again after detector changes;
these recorded values are a snapshot, not the evaluation oracle.
