import json
from pathlib import Path

from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator

from api.main import create_app
from adapters.normalized import NormalizedFixture
from core.models import AdapterContext, AdapterResult, Finding, ScanInput, ScanRequest, ScanResult
from export.cyclonedx import validate_cyclonedx

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    return json.loads((ROOT / "examples" / name).read_text())


def test_three_sources_flow_and_schema_valid_export():
    with TestClient(create_app()) as client:
        response = client.post("/api/scans", json=load("scan-original.request.json"))
        assert response.status_code == 201
        scan = response.json()
        assert scan["status"] == "completed"
        assert scan["synthetic"] is True
        assert {f["source_type"] for f in scan["findings"]} == {"source", "cloud", "pcap"}
        assert len(scan["findings"]) == 10
        assert scan["score"]["unknown_assets"] > 0
        url = f"/api/scans/{scan['scan_id']}"
        assert client.get(url).json() == scan
        assert client.get(url + "/export?format=json").json() == scan
        validate_cyclonedx(client.get(url + "/export?format=cyclonedx").json())


def test_modified_configuration_preserves_identity_and_network_observations():
    with TestClient(create_app()) as client:
        before = client.post("/api/scans", json=load("scan-original.request.json")).json()
        after = client.post("/api/scans", json=load("scan-modified.request.json")).json()
    before_by_id = {f["id"]: f for f in before["findings"]}
    after_by_id = {f["id"]: f for f in after["findings"]}
    assert before_by_id.keys() == after_by_id.keys()
    changed = [fid for fid in before_by_id if before_by_id[fid] != after_by_id[fid]]
    assert len(changed) == 1
    old, new = before_by_id[changed[0]], after_by_id[changed[0]]
    assert old["asset_id"] == new["asset_id"]
    assert old["quantum_status"] == "vulnerable" and new["quantum_status"] == "hybrid"
    assert new["evidence_kind"] == "configured"
    assert [f for f in before["findings"] if f["source_type"] == "pcap"] == [f for f in after["findings"] if f["source_type"] == "pcap"]


def test_partial_fixture_keeps_successful_findings_and_explicit_unknown_units():
    with TestClient(create_app()) as client:
        scan = client.post("/api/scans", json=load("scan-partial.request.json")).json()
    assert scan["status"] == "partial"
    assert len(scan["findings"]) == 10
    assert scan["errors"][0]["code"] == "unsupported_adapter"
    assert scan["coverage"][-1]["unit"] == "inputs"
    assert scan["coverage"][-1]["unsupported"] == 1


def test_checked_in_contracts_match_models_and_examples():
    for model in (AdapterContext, AdapterResult, Finding, ScanInput, ScanRequest, ScanResult, NormalizedFixture):
        stored = json.loads((ROOT / "schemas" / f"{model.__name__}.schema.json").read_text())
        assert stored == model.model_json_schema()
    assert json.loads((ROOT / "schemas/openapi.json").read_text()) == create_app().openapi()
    for model in (ScanRequest, ScanResult):
        stored = json.loads((ROOT / "schemas" / f"{model.__name__}.schema.json").read_text())
        suffix = "request" if model is ScanRequest else "response"
        for name in ("original", "modified", "partial", "source"):
            example = load(f"scan-{name}.{suffix}.json")
            model.model_validate(example)
            Draft202012Validator(stored).validate(example)
    validate_cyclonedx(load("scan-original.cdx.json"))
