# Deterministic assessment v1.1.1

Version 1.1.1 adds secp256k1 to compatible classical EC groups, including AWS KMS
ECDSA keys. It follows the existing discrete-logarithm assessment for classical
elliptic-curve cryptography; conflicting or unknown groups remain unknown.

`core.assessment.assess_finding(Finding) -> Finding` returns a deep copy. It reads the normalized algorithm, usage, parameters, and evidence scope. There is no LLM, network call, clock dependency, or inference from evidence text, comments, filenames, owner, or asset names. The adapter supplies those facts; assessment cannot establish whether a detector is correct.

Every result includes a versioned rule ID, rationale, recommendation, and authoritative reference URLs. Unknown cases receive an explicit unknown rule. Confidence, identity, evidence kind, timestamps, ownership, and detector-supplied issues survive assessment. Evidence is never upgraded from offered/configured/declared to observed.

Assessment consumes fresh detector facts. Repeating assessment on an unchanged result is idempotent, but when correcting parameters or comparing a migration, rebuild the finding from the original adapter data. Do not edit a previously assessed output and resubmit it: the shared issue/reference lists deliberately preserve their input values and currently do not distinguish detector entries from earlier rule output. Discarding matching strings would risk deleting independently evidenced detector claims.

| Supported fact | Quantum status / challenge tier | Limits and action |
| --- | --- | --- |
| RSA, DH, ECDH, ECDSA, Ed25519/Ed448 in compatible uses | vulnerable / critical | Future quantum exposure. Signing advice points to ML-DSA/SLH-DSA; key establishment to ML-KEM or supported hybrid protocols. RSA encryption requires a reviewed KEM-plus-authenticated-encryption design. |
| RSA with unknown usage (for example key generation) | vulnerable / critical | RSA's primitive is known; confirm signing/encryption/key-establishment usage before choosing a replacement. Explicit key sizes below 2048 bits remain a classical issue. |
| AES-128 encryption | resistant_primitive / medium | Medium is project policy, not NIST deprecation or a practical quantum break. |
| AES-192/256 encryption | resistant_primitive / resilient | Only the primitive; no inference about key exchange, authentication, nonce handling, or application safety. |
| FIPS ML-KEM family / valid named parameter sets | resistant_primitive / resilient | Key establishment only. Family-level evidence does not validate the actual parameter set. |
| FIPS ML-DSA / SLH-DSA families and valid named sets | resistant_primitive / resilient | Signatures only. Verify implementation and platform support. |
| RFC 10024 exact hybrid groups | hybrid / resilient | X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024. This says nothing about authentication. |
| Kyber drafts, unknown group IDs, unsupported algorithms, incompatible usage | unknown / unknown | No substring-based certification or guessed registry mapping. |
| MD5 / SHA-1 used as a hash | quantum_weakened / medium | Explicit challenge migration policy; existing collision weaknesses stay visible. A non-security checksum is not assumed to be a security use. This does not classify a containing HMAC, signature or KDF. |
| Classical EC/ECC key with unknown usage | vulnerable / critical | Known classical primitive, but signing versus key establishment is unresolved. Conflicting or unsupported named groups remain unknown. |
| Configured cloud HTTP listener | not_applicable / unknown | No TLS primitive to classify; the UI displays Not applicable. HTTP forwarding issues remain operational findings. Excluded from both exposure and uncertainty counts. |
| Other hashes, HMAC, PBKDF2 | unknown / unknown | Required security properties, secret entropy, tags, salts, PRF, or password handling are not fully established by this contract. |

The challenge tier concerns quantum migration only. Existing weaknesses are in `classical_issues`; cloud expiry/rotation and similar operational facts remain in `posture_issues`. For example, AES-256-ECB retains a resistant primitive classification **and** an ECB weakness. This is intentional: the inventory must show both, and no view should display the tier as a whole-system safety verdict.

Classical checks cover RSA keys below 2048 bits, ECB information leakage, MD5/SHA-1 collision-sensitive uses, and a PBKDF2 work factor below the historical SP 800-132 minimum. Meeting that old minimum is never presented as safe. Hash checks distinguish a security use from a non-security checksum; HMAC-MD5 guidance does not assert that MD5 collisions directly break HMAC. CBC/CTR names alone do not establish absence of authentication or bad IV handling.

Unknown AES sizes and conflicting AES name/parameter values remain unknown. Conflicting metadata cannot hide an ECB mode or HMAC-MD5 identifier; the weakness stays visible while the contradiction requires resolution. Named groups refine compatible generic families: ML-KEM accepts its parameter sets, DH/DHE accept FFDHE groups, and EC/ECC accept known classical curves. P-256/P-384/P-521 are recognized as aliases of secp256r1/secp384r1/secp521r1. Contradictory specific algorithm/group pairs remain unknown, including signature findings; an ML-DSA name with a classical curve must not receive a resilient assessment. ECDH/ECDHE accept known EC or explicit hybrid groups, not pure KEM or finite-field groups. TLS 1.2 accepts known classical groups; the pinned TLS 1.3 PQ/hybrid groups remain unknown when paired with TLS 1.2. Adapters should normalize algorithms (for example `RSA`, `AES` with separate parameters), express sizes in **bits**, and emit separate findings for key establishment, signatures, and symmetric encryption. Supported aliases are a bounded allowlist in the module; it is not a universal cryptographic name parser.

An offered group is a capability, not a selected group. Configuration is not runtime use. Declared source is not execution. Observed findings apply only to the captured operation. In passive TLS 1.3, encrypted handshake records normally conceal certificate/CertificateVerify details after ServerHello; absent authentication remains unknown. A scan cannot certify application resilience by seeing TLS 1.3, AES-256, or one hybrid exchange.

Legacy-hash policy follows the project brief’s medium SHA-1 example and extends the same conservative migration tier to MD5 hash occurrences. `quantum_weakened` distinguishes this challenge policy from Shor-vulnerable public-key primitives and from primitive resistance. It makes no practical-attack or whole-application security claim. The NIST PQC FAQ and hash guidance inform the limits and classical warnings; they do not define this project’s medium tier. Modern hash names, HMAC and PBKDF2 still require context.

Ruleset 1.1.0 also gives unresolved AES parameters and unobserved configured TLS negotiation distinct rule IDs, so the dashboard can explain and filter uncertainty without guessing from rationale text. The API adds `quantum_weakened` to the quantum-status enum; consumers with exhaustive enum handling must accept it. The existing challenge-tier enum is unchanged.

Original references checked 10 October 2026; NIST PQC/hash guidance rechecked for the legacy-hash policy on 11 October 2026; the implemented rules and allowlists are pinned by `RULESET_VERSION`. No registry refresh occurs during scans. Changes to these decisions require a ruleset version change and regression review.

- [NIST PQC FAQ](https://csrc.nist.gov/Projects/post-quantum-cryptography/faqs): symmetric-key nuance and generic quantum search. AES-128's medium tier is this project's simplification.
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final): standardized KEM and signature roles.
- [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html) and [IANA TLS registry](https://www.iana.org/assignments/tls-parameters): exact hybrid groups and obsolete Kyber draft distinction.
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html): TLS selection and encrypted handshake evidence limits.
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html): EdDSA is elliptic-curve cryptography.
- [SP 800-131A Rev. 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final): the pinned classical transition baseline, including distinctions for legacy signature verification.
- [SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final): ECB's deterministic block behavior.
- [NIST hash guidance](https://csrc.nist.gov/projects/hash-functions), [RFC 6151](https://www.rfc-editor.org/rfc/rfc6151.html), and [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.html): hash use context and HMAC distinctions.
- [SP 800-132](https://csrc.nist.gov/pubs/sp/800/132/final): password derivation parameters and the historical work-factor baseline.

Regression cases in `tests/test_assessment.py` cover incorrect blanket RSA replacement advice, Ed25519, AES modes and contradictory sizes, wrong PQ primitive roles, obsolete draft groups, evidence limits, HMAC/hash differences, PBKDF2 uncertainty, provenance preservation, deterministic reassessment, and misleading filenames/comments. These are rule-level synthetic cases, not a claim of scanner precision or recall on organizer inputs.

## Asset scoring policy v1

The score is a project quantum-exposure heuristic between 0 and 100; higher means
more exposure. It is not a NIST score, attack probability, compliance verdict, or
measure of whole-application safety. Classical and operational issues remain
separate counts.

For each unique asset ID, take its worst known challenge tier across non-offered
findings: `critical = 100`, `medium = 50`, `resilient = 0`. Average these values
with equal asset weights and round to two decimals. No packet-level averaging or
guessed business criticality is used. Rules classify tiers; the score does not
read filenames, owners, or missing business context.

Unknown-only, offered-only, and not-applicable-only assets are excluded from the
denominator and reported separately. With no assessed assets, the score is `null`,
not zero. Adding unknown assets cannot improve the number. If an asset has both
known and unknown findings, its worst known value is used and it is also counted
under `assets_with_unknowns`. A hybrid connection with unknown authentication can
therefore have a low known-exposure score with explicit incomplete assessment;
the UI must show those unknowns alongside the number.

Example: one RSA asset (100) and one AES-256 asset (0) yield 50. Twenty sightings
of the RSA asset still yield 50. Adding an unknown asset still yields 50, with
`unknown_assets = 1`. A separate AES-128 asset (50) makes three assessed assets
whose score remains 50. AES-128's tier is project policy, not a practical quantum
break claim; see [assessment policy](assessment.md).

The output includes the exact weights, denominator explanation, assessed and total
asset counts, unknown/offer/N/A counts, assets with unknowns, vulnerable/hybrid
counts, classical/posture issue asset counts, and asset counts by evidence kind.
Evidence-kind counts overlap when an asset has multiple kinds and must not be
summed as a unique total. Raw input coverage remains in `ScanResult.coverage`.
