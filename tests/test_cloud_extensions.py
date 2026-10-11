"""AWS response and mapping coverage, including ambiguity and evidence boundaries."""

import json

import pytest

from adapters.cloud import cloud_adapter
from adapters.registry import AdapterRegistry
from core.models import AdapterContext, ScanInput, ScanRequest
from core.service import ScanService


EVALUATED_AT = "2026-10-10T12:00:00Z"


def scan(value):
    return cloud_adapter(
        ScanInput(name="aws.json", source_type="cloud", format="raw", content=json.dumps(value)),
        AdapterContext(evaluated_at=EVALUATED_AT),
    )


def kms(spec="SYMMETRIC_DEFAULT", usage="ENCRYPT_DECRYPT", region="us-east-1", partition="aws"):
    return {"KeyMetadata": {
        "Arn": f"arn:{partition}:kms:{region}:111122223333:key/example",
        "KeySpec": spec, "KeyUsage": usage,
    }}


def assert_evidence(value, result):
    for element in [*result.assets, *result.findings, *result.relationships]:
        for evidence in element.evidence:
            resolved = value
            for segment in evidence.locator.split("/")[1:]:
                resolved = resolved[int(segment)] if isinstance(resolved, list) else resolved[segment]
            assert resolved == json.loads(evidence.detail)


@pytest.mark.parametrize("region,partition,algorithm,bits,mode", [
    ("us-east-1", "aws", "AES", 256, "GCM"),
    ("ap-southeast-2", "aws", "AES", 256, "GCM"),
    ("eu-central-1", "aws", "AES", 256, "GCM"),
    ("us-gov-west-1", "aws-us-gov", "AES", 256, "GCM"),
    ("cn-north-1", "aws-cn", "SM4", 128, None),
    ("cn-northwest-1", "aws-cn", "SM4", 128, None),
])
def test_native_kms_regions_and_partition_evidence(region, partition, algorithm, bits, mode):
    value = kms(region=region, partition=partition)
    result = scan(value)
    assert not result.errors and result.coverage[0].assessed == 1
    finding = result.findings[0]
    assert (finding.algorithm, finding.parameters.key_bits, finding.parameters.mode) == (algorithm, bits, mode)
    assert result.assets[0].region == region
    assert result.assets[0].account == "111122223333"
    assert result.assets[0].snapshot_at is None and finding.observed_at is None
    assert result.snapshots == []
    assert "/KeyMetadata/Arn" in [e.locator for e in finding.evidence]
    assert_evidence(value, result)


@pytest.mark.parametrize("region,partition,envelope_region", [
    ("cn-north-1", "aws", None),
    ("us-east-1", "aws-cn", None),
    ("us-east-1", "aws", "cn-north-1"),
    ("us-east-1", "aws", "us-west-2"),
    ("imaginary-region", "aws", None),
])
def test_ambiguous_symmetric_location_stays_unknown(region, partition, envelope_region):
    value = kms(region=region, partition=partition)
    if envelope_region:
        value["Region"] = envelope_region
    result = scan(value)
    assert not result.errors
    assert result.findings[0].algorithm == "unknown"
    assert result.findings[0].parameters.key_bits is None
    assert_evidence(value, result)


@pytest.mark.parametrize("spec,usage,algorithm,bits,group,hash_name", [
    ("ECC_NIST_P521", "SIGN_VERIFY", "ECDSA", 521, "secp521r1", None),
    ("ECC_SECG_P256K1", "SIGN_VERIFY", "ECDSA", 256, "secp256k1", None),
    ("ECC_NIST_P384", "KEY_AGREEMENT", "ECDH", 384, "secp384r1", None),
    ("ECC_NIST_EDWARDS25519", "SIGN_VERIFY", "Ed25519", 256, "ed25519", None),
    *[(f"HMAC_{bits}", "GENERATE_VERIFY_MAC", "HMAC", bits, None, f"SHA{bits}")
      for bits in (224, 256, 384, 512)],
    *[(f"ML_DSA_{level}", "SIGN_VERIFY", f"ML-DSA-{level}", None, None, None)
      for level in (44, 65, 87)],
    ("SM2", "SIGN_VERIFY", "SM2", 256, None, None),
])
def test_additional_kms_key_specs(spec, usage, algorithm, bits, group, hash_name):
    value = kms(spec, usage)
    result = scan(value)
    assert not result.errors
    finding = result.findings[0]
    assert (finding.algorithm, finding.parameters.key_bits, finding.parameters.named_group,
            finding.parameters.hash_algorithm) == (algorithm, bits, group, hash_name)
    assert finding.usage == {"SIGN_VERIFY": "signature", "KEY_AGREEMENT": "key_establishment",
                             "GENERATE_VERIFY_MAC": "mac"}[usage]
    assert_evidence(value, result)


def test_deprecated_key_spec_alias_and_conflicts():
    value = kms()
    record = value["KeyMetadata"]
    record["CustomerMasterKeySpec"] = record.pop("KeySpec")
    result = scan(value)
    assert result.findings[0].algorithm == "AES"
    assert result.findings[0].evidence[0].locator == "/KeyMetadata/CustomerMasterKeySpec"
    assert_evidence(value, result)
    record["KeySpec"] = "RSA_2048"
    result = scan(value)
    assert result.findings[0].algorithm == "unknown"
    assert_evidence(value, result)


def test_native_missing_key_spec_keeps_resource_evidence_and_unknown_finding():
    value = kms()
    del value["KeyMetadata"]["KeySpec"]
    result = scan(value)
    assert not result.errors
    assert result.findings[0].algorithm == "unknown"
    assert result.findings[0].evidence[0].locator == "/KeyMetadata"
    assert_evidence(value, result)


def test_native_capture_time_is_only_from_explicit_generated_at():
    value = kms()
    value["KeyMetadata"]["CreationDate"] = "2025-01-01T00:00:00Z"
    assert scan(value).findings[0].observed_at is None
    value["GeneratedAt"] = "2026-10-09T00:00:00Z"
    result = scan(value)
    assert result.findings[0].observed_at == result.snapshots[0].generated_at
    assert result.snapshots[0].locator == "/GeneratedAt"


@pytest.mark.parametrize("key_algorithm,algorithm,bits", [
    ("RSA_1024", "RSA", 1024), ("EC_secp521r1", "EC", 521),
])
def test_native_acm_epoch_timestamps_and_additional_keys(key_algorithm, algorithm, bits):
    value = {"Certificate": {
        "CertificateArn": "arn:aws:acm:us-east-1:111122223333:certificate/example",
        "KeyAlgorithm": key_algorithm, "SignatureAlgorithm": "SHA512WITHECDSA",
        "NotBefore": 1700000000, "NotAfter": 1750000000.5,
    }}
    result = scan(value)
    assert not result.errors
    public, signature = result.findings
    assert (public.algorithm, public.parameters.key_bits) == (algorithm, bits)
    assert (signature.algorithm, signature.parameters.hash_algorithm) == ("ECDSA", "SHA512")
    assert "certificate_expired" in public.posture_issues
    assert_evidence(value, result)


@pytest.mark.parametrize("mutate", [
    lambda value: value.update(Keys=[]),
    lambda value: value.update(Certificate={}),
    lambda value: value.update(KeyMetadata=[]),
    lambda value: value["KeyMetadata"].update(Arn="not-an-arn"),
    lambda value: value["KeyMetadata"].update(KeyArn="arn:aws:kms:us-east-1:111122223333:key/other"),
    lambda value: value["KeyMetadata"].update(ValidTo=True),
    lambda value: value["KeyMetadata"].update(ValidTo=10**30),
])
def test_malformed_native_responses_fail_explicitly(mutate):
    value = kms()
    mutate(value)
    result = scan(value)
    assert result.errors
    assert not result.findings


def test_native_response_inside_bundle_preserves_evidence():
    value = {"kms_key_inventory.json": kms("ML_DSA_65", "SIGN_VERIFY")}
    result = scan(value)
    assert not result.errors
    assert result.findings[0].evidence[0].locator == "/kms_key_inventory.json/KeyMetadata/KeySpec"
    assert_evidence(value, result)


def test_ambiguous_response_inside_bundle_fails_without_losing_valid_sibling():
    value = {"kms_key_inventory.json": {**kms(), "Certificate": {}},
             "acm_certificates.json": {"Certificate": {
                 "CertificateArn": "arn:aws:acm:us-east-1:111122223333:certificate/example",
                 "KeyAlgorithm": "RSA_2048", "SignatureAlgorithm": "SHA256WITHRSA",
             }}}
    result = scan(value)
    assert result.errors
    assert len(result.assets) == 1 and result.assets[0].kind == "certificate"
    assert_evidence(value, result)


@pytest.mark.parametrize("value,status,rule", [
    (kms("ML_DSA_65", "SIGN_VERIFY"), "resistant_primitive", "PQC-SIGNATURE"),
    (kms("ECC_NIST_P521", "KEY_AGREEMENT"), "vulnerable", "CLASSICAL-ASYMMETRIC"),
    (kms(region="cn-north-1", partition="aws-cn"), "unknown", "UNKNOWN"),
])
def test_native_responses_flow_through_core_without_assuming_unknown_algorithms_safe(value, status, rule):
    registry = AdapterRegistry()
    registry.register("cloud", cloud_adapter)
    result = ScanService(registry=registry).run_scan(ScanRequest(
        inputs=[ScanInput(name="aws.json", source_type="cloud", format="raw", content=json.dumps(value))],
        evaluated_at=EVALUATED_AT,
    ))
    assert not result.errors
    assert result.findings[0].quantum_status == status
    assert result.findings[0].rule_id.startswith(f"QT-{rule}@")
