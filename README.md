# QuantumTrace — cloud adapter

Python 3.9+; no external dependencies. Run from the repository root:

```sh
python3 -B -m adapters.cloud cloud-posture --evaluated-at 2026-10-10T12:00:00Z > /tmp/quantumtrace-cloud.json
python3 -B -m unittest discover -s tests -v
```

Without `--evaluated-at`, the adapter uses the current UTC time. The CLI writes
JSON to stdout and returns exit code 1 on a partial input failure, while keeping
successful results. Invalid evaluation timestamps return exit code 2.

Input JSON rejects duplicate fields, non-finite numbers and nonstandard constants
such as `NaN`. Invalid dates or resource fields produce explicit errors while
preserving valid inputs. KMS and ACM algorithm names are mapped separately.

The test command also runs the HTML board checks in headless Chrome/Chromium
when installed; otherwise those browser tests are skipped. Each browser test
uses a temporary profile, leaving your saved board progress untouched.

## Backend integration

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
python3 -B -m adapters.cloud tests/fixtures/cloud-modified --evaluated-at 2026-10-10T12:00:00Z > /tmp/quantumtrace-cloud-modified.json
python3 -B -m adapters.cloud_demo > /tmp/quantumtrace-cloud-demo.json
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

See [the cloud handoff](docs/cloud-handoff.md) for C1–C5 completion, expected
results and the demonstration script. A generated example is in
[cloud-demo.json](docs/cloud-demo.json); it is a selected handoff summary, not a
complete scan or a final core assessment.

## Certificate renewal demonstration

`tests/fixtures/cloud-renewed/` is a separate **synthetic reimport scenario** for
the expired `legacy-tcp.internal.example.com` certificate. It changes only its
validity dates, import date and issuer signature (SHA-1 to SHA-256), plus the
certificate snapshot timestamp. ARN, domain, RSA-2048 key type/size, listener
links and renewal eligibility remain unchanged. KMS and load balancer files
are unchanged copies of the organizer inputs.

```sh
python3 -B -m adapters.cloud_demo --certificate-renewal > /tmp/quantumtrace-cloud-renewal.json
python3 -B -m adapters.cloud tests/fixtures/cloud-renewed --evaluated-at 2026-10-10T12:00:00Z
```

The comparison includes exact before/after evidence and resolved posture issues;
it rejects unrelated configuration changes and a replacement certificate that is
not valid at the evaluation time. At the default date, expiry and SHA-1 warnings
disappear for this certificate; legacy TLS and the other resources' issues remain.
RSA authentication remains classical. No certificate or key material is generated.

[AWS requires manual renewal and reimport for imported certificates](https://docs.aws.amazon.com/acm/latest/userguide/import-certificate.html).
[Reimport preserves associations and requires the same key type and size](https://docs.aws.amazon.com/acm/latest/userguide/import-reimport.html).
Changing fixture metadata demonstrates detection; it does not issue a certificate
or renew anything in AWS. A generated summary is in
[cloud-renewal-demo.json](docs/cloud-renewal-demo.json).
