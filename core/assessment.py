"""Deterministic, evidence-scoped assessments. No network access at scan time."""

import re

from core.models import Finding

RULESET_VERSION = "1.1.0"
NIST_PQC = "https://csrc.nist.gov/Projects/post-quantum-cryptography/faqs"
FIPS203 = "https://csrc.nist.gov/pubs/fips/203/final"
FIPS204 = "https://csrc.nist.gov/pubs/fips/204/final"
FIPS205 = "https://csrc.nist.gov/pubs/fips/205/final"
TRANSITION = "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"
HASHES = "https://csrc.nist.gov/projects/hash-functions"
MD5 = "https://www.rfc-editor.org/rfc/rfc6151.html"
PBKDF = "https://csrc.nist.gov/pubs/sp/800/132/final"
MODES = "https://csrc.nist.gov/pubs/sp/800/38/a/final"
TLS = "https://www.rfc-editor.org/rfc/rfc8446.html"
HYBRID = "https://www.rfc-editor.org/rfc/rfc10024.html"
IANA = "https://www.iana.org/assignments/tls-parameters"

# Exact, pinned names: matching a substring such as "MLKEM" is insufficient.
HYBRID_GROUPS = {"X25519MLKEM768", "SECP256R1MLKEM768", "SECP384R1MLKEM1024"}
KEMS = {"MLKEM", "MLKEM512", "MLKEM768", "MLKEM1024"}
SIGNATURES = {"MLDSA", "MLDSA44", "MLDSA65", "MLDSA87", "SLHDSA"} | {
    f"SLHDSA{hash_name}{strength}{variant}"
    for hash_name in ("SHA2", "SHAKE")
    for strength in (128, 192, 256)
    for variant in ("S", "F")
}
CLASSICAL_USES = {
    "RSA": {"signature", "key_establishment", "encryption"},
    "RSAPSS": {"signature"}, "RSAOAEP": {"encryption", "key_establishment"},
    "ECC": {"signature", "key_establishment"}, "EC": {"signature", "key_establishment"},
    "ECDSA": {"signature"}, "ED25519": {"signature"}, "ED448": {"signature"},
    "EDDSA": {"signature"}, "DSA": {"signature"},
    "ECDH": {"key_establishment"}, "ECDHE": {"key_establishment"},
    "DH": {"key_establishment"}, "DHE": {"key_establishment"},
    "X25519": {"key_establishment"}, "X448": {"key_establishment"},
}
CLASSICAL_EC_GROUPS = {
    "X25519", "X448", "SECP256R1", "SECP384R1", "SECP521R1", "P256", "P384", "P521",
}
CLASSICAL_GROUPS = CLASSICAL_EC_GROUPS | {
    "FFDHE2048", "FFDHE3072", "FFDHE4096", "FFDHE6144", "FFDHE8192",
}
HASH_NAMES = {"MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
              "SHA3224", "SHA3256", "SHA3384", "SHA3512"}


def _name(value: str | None) -> str:
    return re.sub(r"[-_\s]", "", value or "").upper()


def _group_name(value: str | None) -> str:
    name = _name(value)
    return {"P256": "SECP256R1", "P384": "SECP384R1", "P521": "SECP521R1"}.get(name, name)


def _compatible_key_group(algorithm: str, group: str) -> bool:
    """A generic family can refine to its members; specific names must agree."""
    families = {
        "UNKNOWN": CLASSICAL_GROUPS | HYBRID_GROUPS | (KEMS - {"MLKEM"}),
        "KEYEXCHANGE": CLASSICAL_GROUPS | HYBRID_GROUPS | (KEMS - {"MLKEM"}),
        "TLS": CLASSICAL_GROUPS | HYBRID_GROUPS | (KEMS - {"MLKEM"}),
        "TLS1.3": CLASSICAL_GROUPS | HYBRID_GROUPS | (KEMS - {"MLKEM"}),
        "TLS1.2": CLASSICAL_GROUPS,
        "HYBRID": HYBRID_GROUPS,
        "ECDH": CLASSICAL_EC_GROUPS | HYBRID_GROUPS,
        "ECDHE": CLASSICAL_EC_GROUPS | HYBRID_GROUPS,
        "EC": CLASSICAL_EC_GROUPS,
        "ECC": CLASSICAL_EC_GROUPS,
        "DH": CLASSICAL_GROUPS - CLASSICAL_EC_GROUPS,
        "DHE": CLASSICAL_GROUPS - CLASSICAL_EC_GROUPS,
        "MLKEM": KEMS - {"MLKEM"},
    }
    return group in families.get(algorithm, set()) or _group_name(algorithm) == group


def _compatible_signature_group(algorithm: str, group: str) -> bool:
    families = {
        "EC": CLASSICAL_EC_GROUPS - {"X25519", "X448"},
        "ECC": CLASSICAL_EC_GROUPS - {"X25519", "X448"},
        "ECDSA": CLASSICAL_EC_GROUPS - {"X25519", "X448"},
        "EDDSA": {"ED25519", "ED448"},
        "MLDSA": {"MLDSA44", "MLDSA65", "MLDSA87"},
        "SLHDSA": {name for name in SIGNATURES if name.startswith("SLHDSA")},
    }
    return group in families.get(algorithm, set()) or algorithm == group


def assess_finding(finding: Finding) -> Finding:
    """Return a deep copy; classify normalized facts, never evidence text or filenames.

    Challenge tiers describe this project's quantum migration policy. Classical
    and operational issues are independent fields, never silently folded into it.
    """
    algorithm = _name(finding.algorithm)
    group = _group_name(finding.parameters.named_group)
    usage = finding.usage
    issues = list(finding.classical_issues)
    refs = list(finding.references)
    status, tier, rule = "unknown", "unknown", "UNKNOWN"
    rationale = "The normalized algorithm, parameters, or usage are insufficient for a supported assessment."
    recommendation = "Confirm the algorithm and usage from direct evidence; retain unresolved facts as unknown."

    def classify(new_status, new_tier, new_rule, reason, action, *references):
        nonlocal status, tier, rule, rationale, recommendation
        status, tier, rule = new_status, new_tier, new_rule
        rationale, recommendation = reason, action
        refs.extend(references)

    # A specific named group refines generic key-establishment observations only.
    # A contradictory specific algorithm/group pair is deliberately not resolved.
    key_name = algorithm
    if usage == "key_establishment" and group:
        key_name = group if _compatible_key_group(algorithm, group) else "CONFLICTINGGROUP"

    if algorithm == "HTTP" and usage == "unknown" and finding.source_type == "cloud" and finding.evidence_kind == "configured":
        classify("not_applicable", "unknown", "HTTP-NOT-APPLICABLE",
                 "An HTTP listener has no TLS cryptographic primitive to classify for quantum migration. "
                 "This does not establish secure transport; forwarding and redirect behavior are separate operational concerns.",
                 "Review the listener's forwarding or HTTPS redirect configuration and assess TLS on the destination separately.")
    elif algorithm in {"EC", "ECC"} and usage == "unknown" and (not group or group in CLASSICAL_EC_GROUPS):
        classify("vulnerable", "critical", "EC-UNKNOWN-USAGE",
                 "The known classical elliptic-curve public key relies on discrete logarithms and is quantum-vulnerable. "
                 "The evidence does not establish whether it is used for signatures or key establishment.",
                 "Confirm whether the key signs or establishes shared secrets before choosing a compatible post-quantum replacement.",
                 NIST_PQC)
    elif usage == "signature" and group and not _compatible_signature_group(algorithm, group):
        rationale = "The signature algorithm and named-group metadata conflict or their combination is unsupported."
        recommendation = "Resolve the signing algorithm and its parameter set from direct evidence before assessing it."
    elif key_name in HYBRID_GROUPS and usage == "key_establishment":
        classify("hybrid", "resilient", "HYBRID-MLKEM",
                 "This exact RFC 10024 group combines classical ECDHE with standardized ML-KEM. "
                 "The assessment covers key establishment only; authentication remains independently assessed.",
                 "Verify platform support, peer interoperability, negotiated selection, and authentication separately.",
                 HYBRID, FIPS203, IANA)
    elif key_name in KEMS and usage == "key_establishment":
        classify("resistant_primitive", "resilient", "MLKEM",
                 "FIPS 203 standardizes ML-KEM for establishing a shared secret, not signing or bulk encryption.",
                 "Use a supported protocol implementation and verify its parameter set, key handling, and authentication.",
                 FIPS203)
    elif algorithm in SIGNATURES and usage == "signature":
        reference = FIPS205 if algorithm.startswith("SLHDSA") else FIPS204
        classify("resistant_primitive", "resilient", "PQC-SIGNATURE",
                 "This standardized post-quantum signature primitive supports signing; it does not establish a secret key.",
                 "Verify implementation, parameter set, certificate/protocol support, and signature verification on every peer.",
                 reference)
    elif "KYBER" in key_name or "DRAFT" in key_name:
        classify("unknown", "unknown", "PRESTANDARD-PQC",
                 "A draft or pre-standard identifier is not treated as standardized ML-KEM or a verified hybrid group.",
                 "Identify the exact group/version and migrate to a supported standardized group after compatibility checks.",
                 IANA, FIPS203)
    elif key_name == "RSA" and usage == "unknown":
        classify("vulnerable", "critical", "RSA-UNKNOWN-USAGE",
                 "The declared RSA primitive relies on factoring and is quantum-vulnerable; "
                 "key generation alone does not establish how the key is used.",
                 "Confirm whether this key signs, encrypts, or establishes keys before choosing "
                 "a compatible post-quantum replacement. Do not substitute a KEM for a signature.",
                 NIST_PQC)
        if finding.parameters.key_bits is not None and finding.parameters.key_bits < 2048:
            issues.append("RSA key below 2048 bits; unsuitable for new protection under the pinned transition policy.")
            refs.append(TRANSITION)
    elif ((key_name in CLASSICAL_GROUPS and usage == "key_establishment") or
          (key_name in CLASSICAL_USES and usage in CLASSICAL_USES[key_name])):
        if usage == "signature":
            action = "Plan a supported ML-DSA or SLH-DSA signature migration; verify certificate and peer compatibility."
            references = (FIPS204, FIPS205)
        elif usage == "encryption":
            action = ("Plan a vetted encryption protocol combining ML-KEM key establishment with authenticated symmetric "
                      "encryption; ML-KEM is not a drop-in bulk-encryption API.")
            references = (FIPS203,)
        else:
            action = "Plan supported ML-KEM or a standardized hybrid key-establishment protocol; assess signatures separately."
            references = (FIPS203, HYBRID)
        classify("vulnerable", "critical", "CLASSICAL-ASYMMETRIC",
                 "This classical asymmetric primitive relies on factoring or discrete logarithms, which are vulnerable "
                 "to a sufficiently capable quantum computer. This does not assert a practical attack today.",
                 action, NIST_PQC, *references)
        if key_name in {"ED25519", "ED448", "EDDSA"}:
            refs.append("https://www.rfc-editor.org/rfc/rfc8032.html")
        if key_name in {"RSA", "RSAPSS", "RSAOAEP"} and finding.parameters.key_bits is not None:
            if finding.parameters.key_bits < 2048:
                issues.append("RSA key below 2048 bits; unsuitable for new protection under the pinned transition policy.")
                refs.append(TRANSITION)
    elif re.fullmatch(r"AES(?:(128|192|256))?(GCM|ECB|CBC|CTR|CCM)?", algorithm) and usage == "encryption":
        match = re.fullmatch(r"AES(?:(128|192|256))?(GCM|ECB|CBC|CTR|CCM)?", algorithm)
        named_bits = int(match[1]) if match[1] else None
        bits = finding.parameters.key_bits if finding.parameters.key_bits is not None else named_bits
        mode = _name(finding.parameters.mode) or match[2] or ""
        conflict = named_bits is not None and finding.parameters.key_bits not in {None, named_bits}
        mode_conflict = bool(match[2] and finding.parameters.mode and _name(finding.parameters.mode) != match[2])
        if bits in {128, 192, 256} and not conflict and not mode_conflict:
            classify("resistant_primitive", "medium" if bits == 128 else "resilient", "AES",
                     f"AES-{bits} is a symmetric primitive. Generic quantum search does not establish a practical break. "
                     + ("The medium tier for AES-128 is a challenge-policy simplification, not NIST deprecation. " if bits == 128 else "")
                     + "This classification does not establish key-exchange or authentication resistance.",
                     "Verify authenticated encryption, nonce uniqueness, key handling, and separately assess key establishment "
                     "and signatures. Consider AES-256 where policy requires additional margin.", NIST_PQC)
        else:
            rule = "AES-PARAMETERS"
            rationale = "AES key size is absent, unsupported, or contradicts its name, or mode metadata conflicts; assessment remains unknown."
            recommendation = "Resolve AES key size in bits and any conflicting mode metadata from the actual API or configuration."
        if "ECB" in {mode, match[2]}:
            issues.append("ECB reveals equality of plaintext blocks; replace with a suitable authenticated encryption construction.")
            refs.append(MODES)
        # CBC/CTR alone are not proof that authentication or IV handling is absent.
    elif algorithm.startswith("HMAC") and algorithm in {"HMAC"} | {"HMAC" + x for x in HASH_NAMES}:
        if usage == "mac":
            named_hash = algorithm.removeprefix("HMAC")
            supplied_hash = _name(finding.parameters.hash_algorithm)
            rule = "HMAC-PARAMETERS"
            rationale = ("HMAC is a symmetric message authentication construction, not a public-key signature. "
                         "Key entropy, tag length, hash choice, and key handling are not fully established by this contract.")
            recommendation = "Verify the underlying hash, secret entropy and handling, and tag length; prefer supported HMAC-SHA-256 or stronger profiles."
            refs.extend(("https://www.rfc-editor.org/rfc/rfc2104.html", HASHES))
            if named_hash and supplied_hash and named_hash != supplied_hash:
                rationale += " The algorithm name and hash_algorithm metadata conflict."
                recommendation = "Resolve the conflicting HMAC digest evidence before choosing a supported replacement profile."
            if "MD5" in {named_hash, supplied_hash}:
                issues.append("HMAC-MD5 is unsuitable for new designs; MD5 collision attacks alone do not prove HMAC forgery.")
                refs.append(MD5)
    elif algorithm in {"PBKDF2", "PBKDF2HMAC", "PBKDF2HMACSHA1", "PBKDF2HMACSHA256", "PBKDF2HMACSHA512"} and usage == "kdf":
        rule = "PBKDF2-PARAMETERS"
        rationale = "PBKDF2 resistance depends on password entropy, salt, work factor, PRF, and handling; iteration count alone cannot establish resilience."
        recommendation = "Verify a unique random salt, PRF, password policy, and a benchmarked current work factor appropriate for the platform."
        refs.append(PBKDF)
        if finding.parameters.iterations is not None and finding.parameters.iterations < 1000:
            issues.append("PBKDF2 work factor is below the historical SP 800-132 minimum of 1000; meeting that minimum is not a modern safety claim.")
    elif algorithm in HASH_NAMES and usage in {"hash", "signature", "kdf"}:
        rule = "HASH-CONTEXT"
        rationale = "A hash name alone does not establish the required preimage/collision strength or surrounding construction."
        recommendation = "Confirm the hash's security purpose and surrounding construction; assess authentication and key establishment separately."
        refs.append(HASHES)
        if algorithm in {"MD5", "SHA1"} and usage == "hash":
            classify("quantum_weakened", "medium", "LEGACY-HASH",
                     "This legacy hash receives the challenge's medium quantum-migration tier for reduced generic "
                     "preimage-search margin under Grover's algorithm. This is a project policy, not a practical quantum "
                     "break or a NIST safety rating. Existing collision weaknesses are reported separately; "
                     "the surrounding construction and security purpose still require review.",
                     "Replace collision-sensitive uses with a supported SHA-2 or SHA-3 construction; confirm whether "
                     "the hash serves a security purpose or only a non-security checksum. Assess MACs and KDFs separately.",
                     NIST_PQC, HASHES)
        if algorithm in {"MD5", "SHA1"}:
            refs.append(MD5 if algorithm == "MD5" else TRANSITION)
            if usage == "signature":
                issues.append(f"{finding.algorithm} is unsuitable for new digital signatures because of collision weaknesses.")
            elif usage == "hash":
                issues.append(f"{finding.algorithm} lacks collision resistance; review whether collision resistance is required (a non-security checksum is different).")
            elif usage == "kdf":
                recommendation = ("Identify the complete derivation construction and security purpose. A KDF usage label "
                                  "does not establish direct password hashing or transfer collision attacks to that construction.")

    if (status == "unknown" and finding.parameters.configured_tls_policy is not None
            and finding.source_type == "cloud" and finding.evidence_kind == "configured"
            and usage == "key_establishment" and algorithm == "UNKNOWN" and not group):
        rule = "TLS-NEGOTIATION-UNOBSERVED"
        rationale = "The TLS policy describes configured capabilities, but no negotiated key-establishment algorithm was observed."
        recommendation = "Inspect a captured ServerHello to establish the selected cipher suite and key-share group; assess authentication separately."
        refs.append(TLS)

    # Signature digest weaknesses are independent from the asymmetric quantum classification.
    digest = _name(finding.parameters.hash_algorithm)
    if usage == "signature" and digest in {"MD5", "SHA1"}:
        issues.append(f"{finding.parameters.hash_algorithm} is unsuitable for new digital signatures because of collision weaknesses.")
        refs.append(MD5 if digest == "MD5" else TRANSITION)

    limits = {
        "declared": "Declared source evidence does not establish runtime execution.",
        "configured": "Configured capability does not establish observed negotiation or runtime use.",
        "offered": "An offered capability is not a negotiated selection.",
        "observed": "Observed evidence applies only to the captured operation, not other sessions or the whole application.",
    }
    rationale += " " + limits[finding.evidence_kind] + " A primitive assessment does not certify whole-application resilience."
    if finding.source_type == "pcap":
        rationale += " Passive TLS 1.3 normally hides certificate and CertificateVerify details after ServerHello; absent details remain unknown."
        refs.append(TLS)
    return finding.model_copy(deep=True, update={
        "quantum_status": status, "challenge_tier": tier,
        "rule_id": f"QT-{rule}@{RULESET_VERSION}", "rationale": rationale,
        "recommendation": recommendation, "classical_issues": sorted(set(issues)),
        "references": sorted(set(refs)),
    })
