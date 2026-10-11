# Scanner support and evaluation

## Source discovery

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

The bounded detector is pinned as `quantumtrace-source 0.2.0`, rules
`source-api-v3`. Python uses the standard-library AST. Java and Go use lexical
tokens and supported API patterns, not compilers or whole-program analysis.
See [Python AST documentation](https://docs.python.org/3.12/library/ast.html).

Supported families include RSA generation/signature APIs, Ed25519, AES factories
and explicit ECB/GCM configuration, MD5, SHA-1, SHA-2, PBKDF2 factories and HMAC.
Specific supported and unsupported examples are documented in the
[labelled evaluation](scanners.md) and language regression tests.
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

RSA generation keeps usage unknown. Core rules 1.1.0 classify the known RSA
primitive as quantum-vulnerable and flag explicitly weak key sizes while asking
the user to establish usage before choosing a replacement. This follows the
existing [NIST rationale](https://csrc.nist.gov/projects/post-quantum-cryptography/faqs).
HMAC remains a MAC, and Ed25519 remains a classical signature.

## Boundaries and honest unknowns

- Files are limited to 16 MiB and 20,000 occurrences; excessive input fails visibly.
- A processed file is one assessed file even with zero findings or dynamic
  parameters. That is processing coverage, never proof of cryptographic safety.
- Unsupported extensions count as unsupported files. UTF-8/parse/limit failures
  count as failed files; other submitted files continue.
- Python syntax is parsed without execution. Java/Go lexical errors and delimiter
  failures are detected; passing them does not prove valid Java/Go syntax.
- No interprocedural key-size inference, external dependency/source resolution,
  reachability proof or comprehensive data-flow analysis. A function default does
  not establish that every call uses that default. Local bindings can be unknown.
- Bare AES block creation does not establish a mode. The additional Go rules
  recognize the strict ECB and PBKDF2 idioms described below; alternative
  handwritten implementations can remain undetected.
- Python signature calls require a resolved cryptographic receiver; an untyped
  function parameter with padding arguments alone does not prove the API.
  Bounded local RSA key provenance can now establish that receiver.
- Imports and APIs can be dynamically replaced at runtime; all evidence remains
  a static declaration. Unsupported wrappers and language constructs can be missed.

Explicitly supplied `AdapterRegistry()` instances remain empty; call
`registry.register("source", scan_source)` when using a custom registry. The
default service registers source discovery and the cloud adapter integrated on
main. The default API also registers the PCAP adapter from main. Normalized fixture imports
keep their existing synthetic behavior.

## Bounded RSA flow and handwritten Go idioms

Python adds RSA signature observations when direct calls to module-local,
undecorated synchronous functions establish a receiver's key provenance. It
supports explicit arguments, simple return values and tuple unpacking; it does
not carry key sizes across function boundaries. All analyzed contexts for an
added occurrence must agree. Ambiguous calls, escaping callbacks, recursion,
unsupported wrappers and exhausted budgets suppress the supplemental findings
while retaining the original API scan. Limits are eight call levels, 256 calls
and 50,000 supplemental AST visits. This pass adds RSA observations only;
existing Ed25519 discovery is unchanged. AST and binding rules follow the
[Python AST documentation](https://docs.python.org/3.12/library/ast.html) and
[Python execution model](https://docs.python.org/3.12/reference/executionmodel.html).

Go recognizes a strict independent-block idiom: a resolved AES cipher encrypts
matching, nonoverlapping block slices into a fresh output buffer, in a loop with
no extra operations, followed by returning that output. The Encrypt call gets
its own ECB observation; the original NewCipher observation remains mode-unknown.
This follows the independent block transform in
[NIST SP 800-38A, section 6.1](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf).

The Go PBKDF2 recognizer matches a complete statement structure with linked
identifiers: HMAC over salt and a four-byte big-endian block counter, repeated
HMAC over the prior result, XOR accumulation, block concatenation and final
truncation. It supports SHA-1, SHA-256 and SHA-512 implementations of this idiom.
A resolved call to the recognized function produces the KDF observation, with
iterations and output size only when explicit call arguments resolve. The
internal HMAC observations remain. Files above 50,000 tokens skip the supplemental
Go analysis and retain ordinary API discovery. These requirements follow
[RFC 8018, section 5.2](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2).

These are bounded structural recognizers, not general algorithm equivalence
proofs. Import aliases, local identifier renaming, comments and formatting do
not establish or remove algorithm identity. Changed dependencies, shadowed
builtins, additional operations and unsupported structures are rejected.
Independent regressions exercise those near misses as well as positive variants.
No filename or organizer-specific identifier controls recognition, and corpus
contents and labels remain unchanged. See the [implementation plan](source-improvement-plan.md).

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
The detector adds no third-party dependency. Organizer
source is scanned from an external checkout, not copied into this repository;
the evaluation stores labels and hashes with its source commit.

## Additions consolidated from PR #6

[PR #6](https://github.com/GuiMF/JunctionX/pull/6), originally contributed by
Francisco Pereira, supplied the optional cross-check and extra API coverage ideas.
They are integrated into the existing bounded parser, with alias/shadowing tests.
The original commit remains in Git history; the duplicate root scanner and tests
requiring an external sibling checkout were replaced by self-contained regressions.

Go now recognizes the four explicit RSA `EncryptOAEP`, `DecryptOAEP`,
`EncryptPKCS1v15`, and `DecryptPKCS1v15` functions as encryption usage. A resolved
OAEP digest is preserved; key sizes remain unknown without direct evidence.
SHA-512/224 and SHA-512/256 `New512_*` and `Sum512_*` APIs are also recognized,
including constructor references used by HMAC. API references:
[Go RSA](https://pkg.go.dev/crypto/rsa), [Go SHA-512](https://pkg.go.dev/crypto/sha512).

Optionally compare an existing CryptoScan report for the same source root:

```sh
.venv/bin/python -m scripts.scan_source /path/to/source \
  --cryptoscan-json /path/to/cryptoscan.json --output reports/source.json
```

The batch report gains `cryptoscan.tool`, `matched`, `unmatched`, `ignored_hits`
and `duplicate_hits`. Matching requires the same scanned relative file, line and
canonical algorithm, with exactly one candidate occurrence. Broad labels such as
ECC cannot corroborate Ed25519; multiple same-algorithm calls on one line remain
ambiguous. Absolute paths must be under the supplied source root; unrelated paths
and import/dependency hits are ignored. Scanner version is self-reported. No raw
source snippets or arbitrary scanner contexts are copied. Reports are limited to
8 MiB and 20,000 hits; malformed input fails visibly.

This is supplemental metadata: it does not change findings, confidence, quantum
assessment, coverage, scores, or CBOM contents. It never runs or installs
CryptoScan. Unmatched hits remain candidates for review, not confirmed findings.

## Cloud discovery

All cloud entry points use the root README's Python 3.12+ environment and pinned dependencies. Run commands from the repository root:

```sh
.venv/bin/python -m adapters.cloud cloud-posture --evaluated-at 2026-10-10T12:00:00Z > /tmp/quantumtrace-cloud.json
.venv/bin/python -m unittest discover -s tests -p test_cloud.py -v
```

Without `--evaluated-at`, the adapter uses the current UTC time. The CLI writes
JSON to stdout and returns exit code 1 on a partial input failure, while keeping
successful results. Invalid evaluation timestamps return exit code 2.

Input JSON rejects duplicate fields, non-finite numbers and nonstandard constants
such as `NaN`. Invalid dates or resource fields produce explicit errors while
preserving valid inputs. KMS and ACM algorithm names are mapped separately.

The full pytest suite also runs HTML board checks in headless Chrome/Chromium
when installed; otherwise those browser tests are skipped. Each browser test
uses a temporary profile, leaving your saved board progress untouched.

## Raw service/API integration

The default API registers `cloud_adapter(ScanInput, AdapterContext) -> AdapterResult`.
It consumes inline JSON only; input names are never opened as paths. Submit either
one snapshot or a bundle of the three snapshot objects keyed by their filenames.
Bundling resolves the explicit certificate references in one invocation.

For a running server started with the root README command:

```python
import json
from pathlib import Path
from urllib.request import Request, urlopen

snapshots = {file.name: json.loads(file.read_text())
             for file in Path("cloud-posture").glob("*.json")}
payload = {"inputs": [{"name": "cloud.json", "source_type": "cloud", "format": "raw",
                      "content": json.dumps(snapshots)}],
           "evaluated_at": "2026-10-10T12:00:00Z", "synthetic": True}
request = Request("http://127.0.0.1:8000/api/scans", data=json.dumps(payload).encode(),
                  headers={"Content-Type": "application/json"})
with urlopen(request) as response:
    scan = json.load(response)
print(scan["scan_id"], scan["status"], len(scan["assets"]), len(scan["findings"]))
```

Expected: `completed`, 28 inventory assets and 27 findings (25 cryptographic
observations plus two HTTP listener configuration observations). Use the returned
ID with `/api/scans/{id}/export?format=json|cyclonedx`. Set the fixture directory
to `tests/fixtures/cloud-modified` or `tests/fixtures/cloud-renewed` for comparisons.

For direct Python integration, register `adapters.cloud.cloud_adapter`
in `AdapterRegistry` and pass it to `ScanService`, as shown in `docs/api.md`.
The default service registers source and cloud; the default API also registers the network adapter.

The shared result preserves all inventory resources, including load balancers
without cryptographic findings, and snapshot provenance/freshness. Configured
findings use snapshot `GeneratedAt` as `observed_at` under the shared contract;
this is the configuration evidence timestamp, not a wire observation.
`context.evaluated_at` controls expiry and snapshot age. Snapshot age can be
negative when evaluating before the export date.

Findings retain posture codes and their exact evidence; signature findings retain
`parameters.hash_algorithm` so SHA-1 reaches core assessment. HTTP forwarding has
its own configured HTTP observation. `parameters.configured_tls_policy` preserves
policy name, protocols, cipher membership, documented hybrid groups, classical
fallback and mapping references. `named_group` and `negotiated_group` remain null;
the core's quantum assessment remains unknown for policy-only evidence. The
modified fixture changes the descriptor, without inventing selected key exchange
or PQ authentication. Both exports preserve these facts; CycloneDX uses namespaced
component properties and inventory/snapshot metadata properties.

Resource coverage counts parsed resources separately from failures, without using
quantum status as parser coverage. Snapshot/file failures use separate `inputs`
coverage because the failed file's resource count is unknown. Missing certificate
ARNs stay unresolved relationship targets with explicit scan errors. Unknown
policy names retain null capabilities.

Run `.venv/bin/python -m pytest -q` for cloud unit tests, raw service/API tests,
JSON/CycloneDX validation and the existing core suite. Browser tests may be skipped
when Chrome/Chromium is absent. Tests prefer installed Google Chrome over Chromium
and retain the browser sandbox.

## Standalone directory report

```python
from adapters.cloud import scan_cloud

report = scan_cloud("cloud-posture", evaluated_at="2026-10-10T12:00:00Z")
```

`scan_cloud` returns:

- `assets`: KMS keys, certificates, load balancers and child listeners. ARNs are
  stable asset IDs. Original configuration, team tags and snapshot timestamps
  are retained. Unavailable owners remain null.
- `findings`: normalized cryptographic observations with stable IDs, file/JSON
  pointer evidence, usage and parameters. Certificate public keys and issuer
  signatures are separate: the issuer's key size cannot be inferred from the
  subject's key size.
- `relationships`: parent/listener and listener/certificate links. Missing
  certificates remain unresolved and produce errors.
- `posture_issues`: expiry, SHA-1 signatures, rotation disabled, pending deletion,
  legacy TLS and HTTP forwarding. HTTP-to-HTTPS redirect configuration is
  preserved as `http_actions`, distinct from HTTP forwarding.
- `snapshots`, `input_hashes`, `coverage`, `errors`: input provenance, snapshot age,
  inventory/finding counts and partial failures.

This is an **adapter report**, not the final shared ScanResult. Risk assessment,
scoring, recommendations, scan IDs, HTTP endpoints and CycloneDX export belong
to the core. `assessment_status` is `pending_core`; all finding risk fields remain
unknown and `observed_at` is null. A configured TLS policy does not establish the
algorithm negotiated by a connection. Certificates' public-key usage remains
unknown because the supplied snapshots omit key-usage extensions.

Coverage keeps resources and findings separate. `assessed` is zero until the core
assesses observations; `normalized` counts known primitive names, not safe assets.
File failures have unknown resource totals. Invalid resources are counted as
failed; valid siblings and other files are retained.

## Supported inputs and mappings

The three original snapshots and README under `cloud-posture/` were downloaded
unchanged from organizer commit
`39e8f18dcfb5edc66eda0f47bb44884aa7db5c9c`:
[material repository](https://github.com/joaoalves3901/JunctionX-QuantumTrace/tree/39e8f18dcfb5edc66eda0f47bb44884aa7db5c9c/cloud-posture).
They are synthetic snapshots from September 2026, not live AWS inventory.

Mappings were checked on 2026-10-10 against
[KMS key specs](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html),
[ACM certificate fields](https://docs.aws.amazon.com/acm/latest/APIReference/API_CertificateDetail.html),
[ALB policies](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html)
and [NLB policies](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html).
The adapter covers the supplied key specs and five TLS policies, plus the demo
hybrid policy. Cipher lists report membership, not negotiation preference order.
The symmetric mapping covers `eu-west-1`; other regions remain unknown until
mapped explicitly. Other algorithms and policies also remain unknown. The adapter
does not fetch live policies or infer links to source code or network captures.

## Modified demonstration

`tests/fixtures/cloud-modified/` is a **modified synthetic fixture**, not an AWS
change. Its KMS and certificate files are unchanged copies of the original inputs.
Only the HTTPS listener policy of `partner-api-alb` changes to
`ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09`.

To scan the modified inputs or run the comparison:

```sh
.venv/bin/python -m adapters.cloud tests/fixtures/cloud-modified --evaluated-at 2026-10-10T12:00:00Z > /tmp/quantumtrace-cloud-modified.json
.venv/bin/python -m adapters.cloud_demo > /tmp/quantumtrace-cloud-demo.json
```

Asset and finding IDs remain stable. The changed listener becomes
`hybrid_pq_capable: true`; `negotiated_group` remains null and its ECDSA certificate
remains unchanged. AWS documents classical fallback and client support requirements
for this hybrid policy. No observed PQ negotiation or PQ authentication is claimed.

The demo uses a fixed evaluation date by default for reproducibility; pass
`--evaluated-at` to change it. It emits one changed policy, original/modified
evidence, coverage, two owner-tagged KMS examples and a linked listener/certificate
example. It refuses to produce a comparison if scans fail, asset IDs differ,
more than one policy changes, or any other resource configuration changes.

## Certificate renewal demonstration

`tests/fixtures/cloud-renewed/` is a separate **synthetic reimport scenario** for
the expired `legacy-tcp.internal.example.com` certificate. It changes only its
validity dates, import date and issuer signature (SHA-1 to SHA-256), plus the
certificate snapshot timestamp. ARN, domain, RSA-2048 key type/size, listener
links and renewal eligibility remain unchanged. KMS and load balancer files
are unchanged copies of the organizer inputs.

```sh
.venv/bin/python -m adapters.cloud_demo --certificate-renewal > /tmp/quantumtrace-cloud-renewal.json
.venv/bin/python -m adapters.cloud tests/fixtures/cloud-renewed --evaluated-at 2026-10-10T12:00:00Z
```

The comparison includes exact before/after evidence and resolved posture issues;
it rejects unrelated configuration changes and a replacement certificate that is
not valid at the evaluation time. At the default date, expiry and SHA-1 warnings
disappear for this certificate; legacy TLS and the other resources' issues remain.
RSA authentication remains classical. No certificate or key material is generated.

[AWS requires manual renewal and reimport for imported certificates](https://docs.aws.amazon.com/acm/latest/userguide/import-certificate.html).
[Reimport preserves associations and requires the same key type and size](https://docs.aws.amazon.com/acm/latest/userguide/import-reimport.html).
Changing fixture metadata demonstrates detection; it does not issue a certificate
or renew anything in AWS. Run the comparison command above to generate the current summary.

## Network discovery

`adapters/network.py` reads saved PCAP data through PyShark/TShark. It examines
supported TLS ServerHello cipher suites and key-share groups, keeps frame evidence,
and distinguishes offered capabilities from selected values. Registries are bounded:
unsupported or unknown values remain explicit. Encrypted TLS 1.3 authentication
cannot be inferred from a visible ServerHello. Install TShark separately to parse
captures; scanning is passive and does not initiate connections.

```sh
.venv/bin/python network-capture.py capture.pcap > reports/network.json
```

The CLI prints the complete assessed `ScanResult` as JSON. A partial or failed scan
returns exit code 1; invalid arguments or unreadable input return 2. Other entry
points and transport limits are described in [the API guide](api.md).

## Reproducible source discovery evaluation

Run from the repository root with the project's Python environment:

```sh
.venv/bin/python -m scripts.evaluate_source
.venv/bin/python -m scripts.evaluate_source --organizer-root ../JunctionX-QuantumTrace/sample-repos
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

The organizer manifest retains four originally unsupported facts: handwritten
PBKDF2 at `go/auth-gateway/main.go:55`, the separate ECB block observation at
`go/batch-pipeline/main.go:29`, and RSA signatures at
`python/license_token.py:11` and `:16`. Version 0.2.0 recognizes all four through
the bounded analysis above. The manifest's historical `known_gap` annotations,
hashes, algorithms, usages and parameter labels are unchanged. Consequently,
the report's `known_gaps` list is historical metadata; current misses are listed
in `false_negatives`. The separately named `supported_subset` still excludes
those four historical labels and must not replace the full headline result.

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

Recorded on 2026-10-10 against unchanged manifests and source hashes. The 0.1.1
baseline uses `source-api-v2`; version 0.2.0 uses `source-api-v3`:

| Corpus / version | Assessed files | Expected | TP | FP | FN | Precision | Full recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Synthetic holdout / 0.1.1 | 9/9 | 26 | 26 | 0 | 0 | 100% | 100% |
| Organizer / 0.1.1 | 24/24 | 52 | 48 | 0 | 4 | 100% | 92.31% |
| Synthetic holdout / 0.2.0 | 9/9 | 26 | 26 | 0 | 0 | 100% | 100% |
| Organizer / 0.2.0 | 24/24 | 52 | 52 | 0 | 0 | 100% | 100% |

The four additions are the handwritten PBKDF2/ECB facts and two Python RSA
signature calls described above. All 48 original organizer findings retain
their IDs, asset IDs, algorithms, usages, parameters, confidence and evidence
locations. Detector version metadata changes intentionally. There were no scan
errors in either corpus.

All 25 checked parameter fields across 16 matched holdout occurrences were
correct before and after. Organizer parameter checks increased from 50 fields
across 25 matched occurrences to 59 fields across all 29 labelled occurrences;
all were correct. Inferred RSA signatures retain unknown key sizes.

Reproduce the benchmark with:

```sh
.venv/bin/python -m scripts.evaluate_source \
  --organizer-root ../JunctionX-QuantumTrace/sample-repos
.venv/bin/python -m pytest tests/test_source_evaluation.py \
  tests/test_source_python_flow.py tests/test_source_go_semantics.py \
  tests/test_source_semantic_adversarial.py -q
```

The second command includes independent counterexamples and transformed positive
cases. The external organizer checkout is optional and is never required by CI.
These results describe the fixed small corpora, not general production accuracy.
The recorded values are a snapshot, not the evaluation oracle.
