import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from adapters.source import scan_source, to_normalized_fixture
from api.main import create_app
from core.assessment import assess_finding
from core.identity import deduplicate_findings
from core.models import Finding
from export.cyclonedx import validate_cyclonedx

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_DIR = REPO_ROOT / "JunctionX-QuantumTrace" / "sample-repos"
CS_JSON = REPO_ROOT / "cs_out.json"


@pytest.fixture(scope="module")
def scan_results():
    cs_path = str(CS_JSON) if CS_JSON.exists() else None
    return scan_source(str(SAMPLE_DIR), cryptoscan_json=cs_path)


def test_scan_coverage_24_files(scan_results):
    coverage = scan_results["coverage"]
    assert coverage["files_scanned"] == {"python": 8, "java": 8, "go": 8}
    assert coverage["files_failed"] == 0
    assert len(scan_results["findings"]) >= 45


def test_findings_validate_pydantic_schema(scan_results):
    for raw in scan_results["findings"]:
        finding = Finding.model_validate(raw)
        assert finding.schema_version == "1.0"
        assert finding.source_type == "source"
        assert finding.evidence_kind == "declared"
        assert len(finding.evidence) >= 1
        assert finding.evidence[0].file.startswith(("go/", "java/", "python/"))
        assert finding.evidence[0].locator.startswith("line ")


def test_rsa_and_ed25519_asymmetric_vulnerabilities(scan_results):
    findings = [Finding.model_validate(f) for f in scan_results["findings"]]
    assessed = [assess_finding(f) for f in findings]

    vulnerable = [a for a in assessed if a.quantum_status == "vulnerable"]
    vuln_algos = {a.algorithm for a in vulnerable}
    assert "RSA" in vuln_algos
    assert "Ed25519" in vuln_algos

    rsa_1024 = [f for f in findings if f.algorithm == "RSA" and f.parameters.key_bits == 1024]
    assert len(rsa_1024) >= 3  # Go, Java, Python all have RSA-1024 keygen


def test_aes_modes_and_parameters(scan_results):
    findings = [Finding.model_validate(f) for f in scan_results["findings"]]
    aes_findings = [f for f in findings if f.algorithm == "AES"]
    modes = {f.parameters.mode for f in aes_findings}
    assert "ECB" in modes
    assert "GCM" in modes

    key_sizes = {f.parameters.key_bits for f in aes_findings if f.parameters.key_bits}
    assert 128 in key_sizes
    assert 256 in key_sizes


def test_pbkdf2_parameters_extraction(scan_results):
    findings = [Finding.model_validate(f) for f in scan_results["findings"]]
    pbkdf2 = [f for f in findings if "PBKDF2" in f.algorithm]
    assert len(pbkdf2) >= 2
    for p in pbkdf2:
        assert p.parameters.iterations == 600000
        assert p.parameters.key_bits == 256
        assert p.parameters.hash_algorithm == "SHA-256"


def test_classical_weaknesses_flagged_by_core(scan_results):
    findings = [Finding.model_validate(f) for f in scan_results["findings"]]
    assessed = [assess_finding(f) for f in findings]

    weakness_algos = {a.algorithm for a in assessed if a.classical_issues}
    assert "MD5" in weakness_algos
    assert "SHA-1" in weakness_algos
    assert "AES" in weakness_algos  # ECB block repetition weakness


def test_cryptoscan_cross_reference_integration(scan_results):
    matched_ev = [
        f for f in scan_results["findings"]
        if any("CryptoScan" in ev["detail"] for ev in f["evidence"])
    ]
    assert len(matched_ev) > 0
    assert len(scan_results["coverage"]["unmatched_scanner_hits"]) > 0


def test_deduplication_integrity(scan_results):
    findings = [Finding.model_validate(f) for f in scan_results["findings"]]
    deduped = deduplicate_findings(findings)
    assert len(deduped) == len(findings)


def test_end_to_end_core_scan_and_cyclonedx_export(scan_results):
    fixture_dict = to_normalized_fixture(scan_results, input_name="source-scan.json")
    client = TestClient(create_app())
    req = {
        "inputs": [
            {
                "name": "source-scan.json",
                "source_type": "source",
                "format": "normalized",
                "content": json.dumps(fixture_dict),
            }
        ]
    }
    resp = client.post("/api/scans", json=req)
    assert resp.status_code == 201
    scan = resp.json()
    assert scan["status"] == "completed"
    assert scan["score"]["value"] is not None
    assert scan["score"]["quantum_vulnerable_assets"] > 0

    cdx_resp = client.get(f"/api/scans/{scan['scan_id']}/export?format=cyclonedx")
    assert cdx_resp.status_code == 200
    validate_cyclonedx(cdx_resp.json())

