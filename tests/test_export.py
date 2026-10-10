"""Export checks cover schema refs, traceability and conservative relationships."""
from copy import deepcopy
import hashlib
import json
import socket

import pytest
from jsonschema import ValidationError

from core.models import Finding, Relationship, ScanResult
from export.cyclonedx import SCHEMA_DIR, export_cyclonedx, validate_cyclonedx


EVIDENCE = {"file": "fixture.json", "locator": "/listeners/0/certificate", "detail": "Explicit certificate identifier"}


def finding(identifier="f1", asset="a1", **changes):
    return Finding.model_validate({"id": identifier, "asset_id": asset, "source_type": "cloud", "algorithm": "RSA", "usage": "signature", "evidence_kind": "configured", "evidence": [EVIDENCE], "confidence": "high", **changes})


def scan(findings=(), relationships=()):
    return ScanResult(scan_id="scan-test", status="completed", started_at="2026-10-10T10:00:00Z", evaluated_at="2026-10-10T10:00:01Z", ruleset_version="1.0", findings=list(findings), relationships=list(relationships))


def props(obj):
    return {p["name"]: p["value"] for p in obj["properties"]}


def test_minimal_and_deterministic_export():
    report = scan()
    document = export_cyclonedx(report)
    validate_cyclonedx(document)
    assert document["components"] == []
    assert document == export_cyclonedx(report)
    assert document["metadata"]["timestamp"] == "2026-10-10T10:00:01Z"


def test_populated_export_keeps_evidence_identity_and_relationships():
    items = [finding(owner="team-one", parameters={"key_bits": 2048}), finding("f2", "a2", algorithm="AES", usage="encryption", parameters={"key_bits": 256, "mode": "GCM"})]
    relation = Relationship(source_asset_id="a1", target_asset_id="a2", kind="depends_on", evidence=[EVIDENCE])
    report = scan(items, [relation])
    document = export_cyclonedx(report)
    rsa, aes = document["components"]
    assert rsa["cryptoProperties"]["algorithmProperties"]["primitive"] == "signature"
    assert aes["cryptoProperties"]["algorithmProperties"] == {"primitive": "ae", "parameterSetIdentifier": "256", "mode": "gcm"}
    assert props(rsa)["quantumtrace:asset_id"] == "a1"
    assert props(rsa)["quantumtrace:owner"] == "team-one"
    assert json.loads(props(rsa)["quantumtrace:evidence"]) == [EVIDENCE]
    assert rsa["evidence"]["occurrences"][0]["location"] == "fixture.json"
    assert json.loads(props(document["metadata"])["quantumtrace:relationships"]) == [relation.model_dump(mode="json")]
    assert document["dependencies"] == [{"ref": rsa["bom-ref"], "dependsOn": [aes["bom-ref"]]}]
    assert len({c["bom-ref"] for c in document["components"]}) == 2


def test_unknowns_and_unresolved_links_are_not_invented():
    item = finding(algorithm="vendor-unknown", usage="unknown", parameters={"mode": "proprietary"})
    relation = Relationship(source_asset_id="a1", target_asset_id="missing", kind="certificate_reference", evidence=[EVIDENCE])
    document = export_cyclonedx(scan([item], [relation]))
    component = document["components"][0]
    assert component["cryptoProperties"]["algorithmProperties"] == {"primitive": "unknown", "mode": "other"}
    assert props(component)["quantumtrace:quantum_status"] == "unknown"
    assert json.loads(props(component)["quantumtrace:parameters"])["key_bits"] is None
    assert "dependencies" not in document
    assert "missing" in props(document["metadata"])["quantumtrace:relationships"]


def test_multiple_algorithms_on_one_asset_do_not_fabricate_dependency_graph():
    relation = Relationship(source_asset_id="a1", target_asset_id="a2", kind="depends_on", evidence=[EVIDENCE])
    document = export_cyclonedx(scan([finding(), finding("f2", "a1", algorithm="AES"), finding("f3", "a2")], [relation]))
    assert "dependencies" not in document
    assert len(document["components"]) == 3


def test_schema_rejects_nonstandard_crypto_fields_and_bad_formats():
    document = export_cyclonedx(scan([finding()]))
    invalid = deepcopy(document)
    invalid["components"][0]["cryptoProperties"]["quantumSafe"] = True
    with pytest.raises(ValidationError):
        validate_cyclonedx(invalid)
    invalid = deepcopy(document)
    invalid["metadata"]["timestamp"] = "not-a-timestamp"
    with pytest.raises(ValidationError):
        validate_cyclonedx(invalid)
    invalid = deepcopy(document)
    invalid["specVersion"] = "1.5"
    with pytest.raises(ValueError, match="specVersion"):
        validate_cyclonedx(invalid)


def test_reference_integrity_is_checked_beyond_json_schema():
    document = export_cyclonedx(scan([finding()]))
    document["dependencies"] = [{"ref": "absent", "dependsOn": []}]
    with pytest.raises(ValueError, match="Unresolved"):
        validate_cyclonedx(document)
    document.pop("dependencies")
    duplicate = deepcopy(document["components"][0])
    duplicate["name"] = "different name, same identity"
    document["components"].append(duplicate)
    with pytest.raises(ValueError, match="Duplicate"):
        validate_cyclonedx(document)


def test_all_external_schema_refs_resolve_offline(monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("Validation must never use the network")
    monkeypatch.setattr(socket, "socket", no_network)
    document = export_cyclonedx(scan([finding()]))
    # Exercise both external schema files rather than only their registration.
    document["components"][0]["licenses"] = [{"license": {"id": "Apache-2.0"}}]
    document["signature"] = {"algorithm": "RS256", "value": "test-schema-only-not-a-real-signature"}
    validate_cyclonedx(document)
    document["components"][0]["licenses"] = [{"license": {"id": "invented-license"}}]
    with pytest.raises(ValidationError):
        validate_cyclonedx(document)


def test_vendored_schema_provenance_hashes():
    manifest = json.loads((SCHEMA_DIR / "manifest.json").read_text())
    assert manifest["commit"] == "55343ba19dee1785acf1ce9191540d5fd7b590db"
    for filename, source in manifest["files"].items():
        assert hashlib.sha256((SCHEMA_DIR / filename).read_bytes()).hexdigest() == source["sha256"]


def test_unknown_group_does_not_become_curve_or_security_strength():
    item = finding(algorithm="vendor-hybrid", usage="key_establishment", parameters={"key_bits": 256, "named_group": "unrecognized-65000"})
    document = export_cyclonedx(scan([item]))
    component = document["components"][0]
    assert component["cryptoProperties"]["algorithmProperties"] == {"primitive": "unknown"}
    assert json.loads(props(component)["quantumtrace:parameters"])["named_group"] == "unrecognized-65000"


@pytest.mark.parametrize("algorithm,expected", [
    ("AES-256-GCM", {"primitive": "ae", "parameterSetIdentifier": "256", "mode": "gcm"}),
    ("AES_128_CCM", {"primitive": "ae", "parameterSetIdentifier": "128", "mode": "ccm"}),
    ("MLKEM768", {"primitive": "kem", "parameterSetIdentifier": "768"}),
    ("ML-KEM-768", {"primitive": "kem", "parameterSetIdentifier": "768"}),
    ("ML-DSA-44", {"primitive": "signature", "parameterSetIdentifier": "44"}),
    ("X25519MLKEM768", {"primitive": "combiner"}),
    ("AES-SOMETHING", {"primitive": "unknown"}),
    ("ML-DSA-fake", {"primitive": "unknown"}),
    ("PBKDF2-whatever", {"primitive": "unknown"}),
    ("HMAC-unknown", {"primitive": "unknown"}),
    ("ML-KEM-768+X25519", {"primitive": "unknown"}),
])
def test_exact_algorithm_taxonomy_and_embedded_parameters(algorithm, expected):
    document = export_cyclonedx(scan([finding(algorithm=algorithm)]))
    assert document["components"][0]["cryptoProperties"]["algorithmProperties"] == expected


@pytest.mark.parametrize("parameters", [{"key_bits": 128}, {"mode": "ECB"}])
def test_conflicting_aes_parameters_remain_unknown(parameters):
    item = finding(algorithm="AES-256-GCM", parameters=parameters)
    document = export_cyclonedx(scan([item]))
    component = document["components"][0]
    assert component["cryptoProperties"]["algorithmProperties"] == {"primitive": "unknown"}
    assert props(component)["quantumtrace:algorithm"] == "AES-256-GCM"
    assert json.loads(props(component)["quantumtrace:parameters"]) == item.parameters.model_dump()


@pytest.mark.parametrize("algorithm", ["P-256", "secp384r1", "P-521"])
def test_curve_name_does_not_turn_signature_into_key_agreement(algorithm):
    document = export_cyclonedx(scan([finding(algorithm=algorithm, usage="signature")]))
    component = document["components"][0]
    assert component["cryptoProperties"]["algorithmProperties"]["primitive"] == "unknown"
    assert props(component)["quantumtrace:usage"] == "signature"

    document = export_cyclonedx(scan([finding(algorithm=algorithm, usage="key_establishment")]))
    assert document["components"][0]["cryptoProperties"]["algorithmProperties"]["primitive"] == "key-agree"


@pytest.mark.parametrize("algorithm,usage,primitive", [
    ("RSA", "signature", "signature"),
    ("HMAC-SHA256", "mac", "mac"),
    ("SHA256", "hash", "hash"),
    ("ML-KEM-768", "key_establishment", "kem"),
])
def test_cipher_modes_are_not_projected_onto_non_cipher_primitives(algorithm, usage, primitive):
    document = export_cyclonedx(scan([finding(algorithm=algorithm, usage=usage, parameters={"mode": "GCM"})]))
    component = document["components"][0]
    algorithm_properties = component["cryptoProperties"]["algorithmProperties"]
    assert algorithm_properties["primitive"] == primitive
    assert "mode" not in algorithm_properties
    assert json.loads(props(component)["quantumtrace:parameters"])["mode"] == "GCM"


def test_serial_uses_canonical_export_order_and_changes_with_preserved_facts():
    first, second = finding("f1", "a1"), finding("f2", "a2", algorithm="AES")
    original = export_cyclonedx(scan([first, second]))
    assert original == export_cyclonedx(scan([second, first]))
    changed = first.model_copy(update={"owner": "different-owner"})
    assert original["serialNumber"] != export_cyclonedx(scan([changed, second]))["serialNumber"]
