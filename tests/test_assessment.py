"""Labelled security regression cases; no actual cryptography is executed."""

import pytest

from core.assessment import RULESET_VERSION, assess_finding
from core.models import Finding


def finding(algorithm="RSA", usage="signature", **changes):
    return Finding.model_validate({
        "id": "finding-1", "asset_id": "asset-1", "source_type": "source",
        "algorithm": algorithm, "usage": usage, "evidence_kind": "declared",
        "evidence": [{"file": "example.py", "locator": "line 4", "detail": "API declaration"}],
        "confidence": "high", **changes,
    })


@pytest.mark.parametrize("usage,expected,forbidden", [
    ("signature", "ML-DSA", "ML-KEM"),
    ("key_establishment", "ML-KEM", "ML-DSA"),
    ("encryption", "authenticated symmetric", "drop-in bulk-encryption API."),
])
def test_rsa_advice_matches_usage(usage, expected, forbidden):
    result = assess_finding(finding(usage=usage, parameters={"key_bits": 1024, "hash_algorithm": "SHA-1"}))
    assert result.quantum_status == "vulnerable"
    assert result.challenge_tier == "critical"
    assert expected in result.recommendation
    if usage != "encryption":
        assert forbidden not in result.recommendation
    else:
        assert "not a " + forbidden in result.recommendation
    assert any("2048" in issue for issue in result.classical_issues)
    assert any("collision" in issue for issue in result.classical_issues) == (usage == "signature")


@pytest.mark.parametrize("algorithm,usage", [
    ("Ed25519", "signature"), ("ECDSA", "signature"), ("X25519", "key_establishment"),
    ("DH", "key_establishment"), ("RSA-PSS", "signature"),
])
def test_classical_asymmetric_is_not_pqc(algorithm, usage):
    result = assess_finding(finding(algorithm, usage))
    assert result.quantum_status == "vulnerable"
    assert "practical attack today" in result.rationale


@pytest.mark.parametrize("algorithm,usage", [
    ("ML-KEM-768", "signature"), ("ML-DSA-65", "key_establishment"),
    ("Ed25519", "encryption"), ("AES", "signature"), ("RSA", "unknown"),
    ("RSA", "mac"), ("HMAC-SHA256", "signature"),
])
def test_mismatched_or_unknown_usage_is_not_certified(algorithm, usage):
    result = assess_finding(finding(algorithm, usage))
    assert result.quantum_status == "unknown"
    assert result.challenge_tier == "unknown"


@pytest.mark.parametrize("bits,tier", [(128, "medium"), (192, "resilient"), (256, "resilient")])
def test_aes_tier_is_explicit_project_policy(bits, tier):
    result = assess_finding(finding("AES", "encryption", parameters={"key_bits": bits, "mode": "GCM"}))
    assert result.quantum_status == "resistant_primitive"
    assert result.challenge_tier == tier
    assert "does not establish a practical break" in result.rationale
    if bits == 128:
        assert "not NIST deprecation" in result.rationale
    assert not result.classical_issues
    assert "does not establish key-exchange" in result.rationale


def test_ecb_is_classical_and_unknown_mode_is_not_invented():
    ecb = assess_finding(finding("AES-256-ECB", "encryption"))
    cbc = assess_finding(finding("AES-256-CBC", "encryption"))
    assert ecb.quantum_status == "resistant_primitive"
    assert any("ECB" in issue for issue in ecb.classical_issues)
    assert not cbc.classical_issues  # Auth/IV handling cannot be deduced from mode alone.


@pytest.mark.parametrize("algorithm,parameters", [
    ("AES", {}), ("AES", {"key_bits": 32}),
    ("AES-256", {"key_bits": 128}), ("AES-256-GCM", {"mode": "ECB"}),
])
def test_aes_missing_invalid_and_contradictory_parameters(algorithm, parameters):
    assert assess_finding(finding(algorithm, "encryption", parameters=parameters)).quantum_status == "unknown"


@pytest.mark.parametrize("algorithm,usage,status", [
    ("ML-KEM-768", "key_establishment", "resistant_primitive"),
    ("ML-DSA-65", "signature", "resistant_primitive"),
    ("SLH-DSA-SHA2-128s", "signature", "resistant_primitive"),
    ("X25519MLKEM768", "key_establishment", "hybrid"),
    ("SecP256r1MLKEM768", "key_establishment", "hybrid"),
    ("SecP384r1MLKEM1024", "key_establishment", "hybrid"),
    ("X25519Kyber768Draft00", "key_establishment", "unknown"),
    ("Kyber768", "key_establishment", "unknown"),
    ("X25519MLKEM999", "key_establishment", "unknown"),
    ("ML-KEM-999", "key_establishment", "unknown"),
    ("TLS1.3", "key_establishment", "unknown"),
])
def test_pqc_exact_identifiers_and_tls_protocol_limits(algorithm, usage, status):
    result = assess_finding(finding(algorithm, usage))
    assert result.quantum_status == status
    assert "does not certify whole-application" in result.rationale


def test_named_group_can_refine_generic_tls_but_cannot_override_specific_conflict():
    good = finding("TLS1.3", "key_establishment", parameters={"named_group": "X25519MLKEM768"})
    conflict = finding("X25519", "key_establishment", parameters={"named_group": "X25519MLKEM768"})
    assert assess_finding(good).quantum_status == "hybrid"
    assert assess_finding(conflict).quantum_status == "unknown"


def test_tls12_named_group_refines_key_establishment_only():
    parameters = {"named_group": "X25519"}
    exchange = assess_finding(finding("TLS 1.2", "key_establishment", parameters=parameters))
    signature = assess_finding(finding("TLS 1.2", "signature", parameters=parameters))
    assert exchange.quantum_status == "vulnerable"
    assert signature.quantum_status == "unknown"


@pytest.mark.parametrize("algorithm,group,status", [
    ("ECDHE", "ML-KEM-768", "unknown"),
    ("ECDH", "ML-KEM-768", "unknown"),
    ("ECDHE", "ffdhe2048", "unknown"),
    ("ECDH", "RSA", "unknown"),
    ("ECDHE", "X25519", "vulnerable"),
    ("ECDH", "secp256r1", "vulnerable"),
    ("ECDHE", "X25519MLKEM768", "hybrid"),
    ("TLS 1.2", "X25519MLKEM768", "unknown"),
    ("TLS 1.2", "ML-KEM-768", "unknown"),
    ("hybrid", "ML-KEM-768", "unknown"),
    ("hybrid", "X25519MLKEM768", "hybrid"),
    ("TLS 1.3", "RSA", "unknown"),
    ("TLS 1.3", "ML-KEM", "unknown"),
    ("TLS 1.3", "ML-KEM-768", "resistant_primitive"),
])
def test_named_group_must_match_algorithm_family_and_protocol(algorithm, group, status):
    result = assess_finding(finding(algorithm, "key_establishment", parameters={"named_group": group}))
    assert result.quantum_status == status


@pytest.mark.parametrize("kind,expected", [
    ("offered", "not a negotiated selection"),
    ("configured", "does not establish observed negotiation"),
    ("declared", "does not establish runtime execution"),
    ("observed", "only to the captured operation"),
])
def test_evidence_kind_and_capture_limits_survive(kind, expected):
    result = assess_finding(finding("X25519MLKEM768", "key_establishment", evidence_kind=kind, source_type="pcap"))
    assert result.evidence_kind == kind
    assert expected in result.rationale
    assert "authentication remains independently assessed" in result.rationale
    assert "hides certificate and CertificateVerify" in result.rationale


@pytest.mark.parametrize("algorithm", ["HMAC", "HMAC-SHA-256", "HMAC-SHA1", "PBKDF2"])
def test_mac_and_password_strength_cannot_be_inferred_from_algorithm_or_size(algorithm):
    usage = "kdf" if algorithm == "PBKDF2" else "mac"
    result = assess_finding(finding(algorithm, usage, parameters={"key_bits": 256, "iterations": 600000}))
    assert result.quantum_status == "unknown"
    assert result.challenge_tier == "unknown"
    assert not result.classical_issues


def test_md5_hash_signature_and_hmac_have_distinct_issues():
    plain = assess_finding(finding("MD5", "hash"))
    signature = assess_finding(finding("MD5", "signature"))
    mac = assess_finding(finding("HMAC-MD5", "mac"))
    assert any("non-security checksum" in issue for issue in plain.classical_issues)
    assert any("digital signatures" in issue for issue in signature.classical_issues)
    assert any("do not prove HMAC forgery" in issue for issue in mac.classical_issues)
    assert all(result.quantum_status == "unknown" for result in (plain, signature, mac))


def test_pbkdf2_ancient_minimum_is_not_a_safety_threshold():
    low = assess_finding(finding("PBKDF2", "kdf", parameters={"iterations": 999}))
    threshold = assess_finding(finding("PBKDF2", "kdf", parameters={"iterations": 1000}))
    assert any("not a modern safety claim" in issue for issue in low.classical_issues)
    assert not threshold.classical_issues
    assert threshold.quantum_status == "unknown"


def test_hash_in_kdf_does_not_invent_password_usage():
    result = assess_finding(finding("SHA-1", "kdf"))
    assert not result.classical_issues
    assert result.quantum_status == "unknown"
    assert "does not establish direct password hashing" in result.recommendation


def test_assessment_is_pure_idempotent_and_preserves_provenance():
    original = finding(parameters={"key_bits": 1024}, classical_issues=["detector-specific weakness"],
                       posture_issues=["certificate expired"], owner="team-a", confidence="low",
                       references=["https://example.org/evidence"])
    before = original.model_dump()
    result = assess_finding(original)
    assert original.model_dump() == before
    assert result.id == original.id and result.asset_id == original.asset_id
    assert result.owner == "team-a" and result.confidence == "low"
    assert result.posture_issues == ["certificate expired"]
    assert "detector-specific weakness" in result.classical_issues
    assert "https://example.org/evidence" in result.references
    assert RULESET_VERSION in result.rule_id
    assert assess_finding(result).model_dump() == result.model_dump()
    result.evidence[0].detail = "changed"
    assert original.evidence[0].detail == "API declaration"


def test_comments_and_filenames_cannot_create_crypto_facts():
    original = finding("unknown", "unknown", evidence=[{
        "file": "safe_mlkem768_aes256.py", "locator": "line 1",
        "detail": "# Uses ML-KEM-768 and AES-256-GCM; quantum safe!",
    }])
    result = assess_finding(original)
    assert result.quantum_status == "unknown"
    assert not result.classical_issues


@pytest.mark.parametrize("algorithm,group,status", [
    ("ML-KEM", "ML-KEM-768", "resistant_primitive"),
    ("DH", "ffdhe2048", "vulnerable"),
    ("DHE", "ffdhe3072", "vulnerable"),
    ("EC", "secp256r1", "vulnerable"),
    ("ECC", "P-384", "vulnerable"),
    ("P-256", "secp256r1", "vulnerable"),
    ("secp256r1", "P-256", "vulnerable"),
    ("ML-KEM", "X25519MLKEM768", "unknown"),
    ("DH", "X25519", "unknown"),
    ("ML-KEM-512", "ML-KEM-768", "unknown"),
])
def test_compatible_group_families_and_curve_aliases(algorithm, group, status):
    result = assess_finding(finding(algorithm, "key_establishment", parameters={"named_group": group}))
    assert result.quantum_status == status


@pytest.mark.parametrize("algorithm,digest", [("HMAC-MD5", "SHA256"), ("HMAC-SHA256", "MD5")])
def test_conflicting_hmac_digest_metadata_cannot_hide_md5(algorithm, digest):
    result = assess_finding(finding(algorithm, "mac", parameters={"hash_algorithm": digest}))
    assert result.quantum_status == "unknown"
    assert "conflict" in result.rationale
    assert any("HMAC-MD5" in issue for issue in result.classical_issues)


def test_conflicting_aes_mode_cannot_hide_ecb():
    result = assess_finding(finding("AES-256-ECB", "encryption", parameters={"mode": "GCM"}))
    assert result.quantum_status == "unknown"
    assert any("ECB" in issue for issue in result.classical_issues)


@pytest.mark.parametrize("algorithm,group,status", [
    ("ML-DSA-65", "secp256r1", "unknown"),
    ("ML-DSA-65", "ML-DSA-44", "unknown"),
    ("ML-DSA", "ML-DSA-65", "resistant_primitive"),
    ("SLH-DSA", "SLH-DSA-SHA2-128s", "resistant_primitive"),
    ("ECDSA", "secp256r1", "vulnerable"),
    ("ECDSA", "X25519", "unknown"),
    ("Ed25519", "secp256r1", "unknown"),
])
def test_signature_group_metadata_must_be_compatible(algorithm, group, status):
    result = assess_finding(finding(algorithm, "signature", parameters={"named_group": group}))
    assert result.quantum_status == status
