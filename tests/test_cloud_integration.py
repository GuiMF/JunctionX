import base64
from datetime import datetime
import hashlib
import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest
from pydantic import ValidationError

from adapters.cloud_adapter import cloud_adapter
from adapters.registry import AdapterRegistry
from api.main import create_app
from core.models import AdapterContext, AdapterResult, ConfiguredTLSPolicy, ScanInput, ScanRequest, ScanResult
from core.service import ScanService
from export.cyclonedx import validate_cyclonedx


ROOT = Path(__file__).resolve().parents[1]
EVALUATED_AT = "2026-10-10T12:00:00Z"


def raw_cloud(directory="cloud-posture", **changes):
    snapshots = {file.name: json.loads(file.read_text()) for file in (ROOT / directory).glob("*.json")}
    return ScanInput(name="cloud.json", source_type="cloud", format="raw", content=json.dumps(snapshots), **changes)


def request(item, evaluated_at=EVALUATED_AT):
    return ScanRequest(inputs=[item], evaluated_at=evaluated_at, synthetic=True)


def service():
    registry = AdapterRegistry()
    registry.register("cloud", cloud_adapter)
    return ScanService(registry=registry)


def props(obj):
    return {item["name"]: item["value"] for item in obj["properties"]}


def issue_pairs(findings):
    return {(finding["asset_id"], code) for finding in findings for code in finding["posture_issues"]}


def test_raw_adapter_contract_and_service_preserve_inventory_provenance_and_evidence(monkeypatch):
    item = raw_cloud()
    context = AdapterContext(evaluated_at=EVALUATED_AT)
    output = cloud_adapter(item, context)
    AdapterResult.model_validate(output.model_dump())
    # The input name may look like a path; scanning must use only its inline bytes.
    item.name = "/not/a/local/cloud.json"
    with monkeypatch.context() as guard:
        guard.setattr(Path, "read_bytes", lambda *_: pytest.fail("Raw adapter opened a local file"))
        scan = service().run_scan(request(item))
    assert scan.status == "completed" and not scan.errors
    assert len(scan.assets) == 28 and len(scan.findings) == 27
    assert len([asset for asset in scan.assets if asset.kind == "load_balancer"]) == 6
    assert scan.coverage[0].assessed == 28 and scan.coverage[0].failed == 0
    assert scan.input_hashes[item.name] == hashlib.sha256(item.content.encode()).hexdigest()
    assert len([r for r in scan.relationships if r.kind == "uses_certificate"]) == 5
    assert len(scan.snapshots) == 3
    originals = json.loads(item.content)
    for snapshot in scan.snapshots:
        source = originals[snapshot.locator.split("/")[1]]
        assert snapshot.locator.endswith("/GeneratedAt")
        assert snapshot.generated_at == datetime.fromisoformat(source["GeneratedAt"].replace("Z", "+00:00"))
        assert snapshot.age_seconds == (context.evaluated_at - snapshot.generated_at).total_seconds()
    for asset in scan.assets:
        assert asset.snapshot_at is not None
    for finding in scan.findings:
        assert finding.observed_at == next(a.snapshot_at for a in scan.assets if a.asset_id == finding.asset_id)
        assert finding.evidence_kind == "configured"
    for element in [*scan.assets, *scan.findings, *scan.relationships]:
        for evidence in element.evidence:
            assert evidence.file == item.name
            value = originals
            for part in evidence.locator.split("/")[1:]:
                value = value[int(part)] if isinstance(value, list) else value[part]
            assert value == json.loads(evidence.detail)


def test_api_original_modified_and_renewal_survive_json_and_cyclonedx():
    scans = []
    documents = []
    with TestClient(create_app()) as client:
        for directory in ("cloud-posture", "tests/fixtures/cloud-modified", "tests/fixtures/cloud-renewed"):
            response = client.post("/api/scans", json=request(raw_cloud(directory)).model_dump(mode="json"))
            assert response.status_code == 201
            scan = response.json()
            ScanResult.model_validate(scan)
            assert scan["status"] == "completed" and not scan["errors"]
            url = f"/api/scans/{scan['scan_id']}"
            assert client.get(url).json() == scan
            assert client.get(url + "/export?format=json").json() == scan
            export = client.get(url + "/export?format=cyclonedx")
            assert export.status_code == 200
            document = export.json()
            validate_cyclonedx(document)
            metadata = props(document["metadata"])
            for key in ("assets", "snapshots", "relationships", "input_hashes"):
                assert json.loads(metadata["quantumtrace:" + key]) == scan[key]
            exported_findings = [{key.removeprefix("quantumtrace:"): json.loads(value)
                                  for key, value in props(component).items()
                                  if key in ("quantumtrace:parameters", "quantumtrace:posture_issues", "quantumtrace:classical_issues")}
                                 for component in document["components"]]
            for component, finding in zip(document["components"], sorted(scan["findings"], key=lambda f: f["id"])):
                for key in ("parameters", "posture_issues", "classical_issues", "evidence"):
                    assert json.loads(props(component)["quantumtrace:" + key]) == finding[key]
            scans.append(scan)
            documents.append(exported_findings)

    before, modified, renewed = scans
    original_issues = issue_pairs(before["findings"])
    assert len(original_issues) == 8
    assert {code for _, code in original_issues} == {
        "rotation_disabled", "pending_deletion", "certificate_expired",
        "sha1_certificate_signature", "legacy_tls_enabled", "http_forwarding",
    }
    sha1 = next(f for f in before["findings"] if f["parameters"]["hash_algorithm"] == "SHA1")
    assert sha1["usage"] == "signature"
    assert any("SHA1" in issue for issue in sha1["classical_issues"])
    assert any("SHA1" in issue for f in documents[0] for issue in f["classical_issues"])
    assert len([f for f in before["findings"] if f["algorithm"] == "HTTP"]) == 2
    old = {f["id"]: f for f in before["findings"]}
    new = {f["id"]: f for f in modified["findings"]}
    assert old.keys() == new.keys()
    changed = [identifier for identifier in old if old[identifier] != new[identifier]]
    assert len(changed) == 1
    old_policy = old[changed[0]]["parameters"]["configured_tls_policy"]
    new_policy = new[changed[0]]["parameters"]["configured_tls_policy"]
    assert old_policy["hybrid_pq_capable"] is False and new_policy["hybrid_pq_capable"] is True
    assert len(new_policy["hybrid_groups"]) == 3 and new_policy["classical_fallback"] is True
    assert new_policy["negotiated_group"] is None
    assert new[changed[0]]["parameters"]["named_group"] is None
    assert new[changed[0]]["evidence_kind"] == "configured"
    assert new[changed[0]]["quantum_status"] == "unknown"
    assert issue_pairs(modified["findings"]) == original_issues
    assert original_issues - issue_pairs(renewed["findings"]) == {
        (sha1["asset_id"], "certificate_expired"), (sha1["asset_id"], "sha1_certificate_signature"),
    }
    assert {f["id"] for f in renewed["findings"]} == old.keys()
    renewed_signature = next(f for f in renewed["findings"] if f["id"] == sha1["id"])
    assert renewed_signature["parameters"]["hash_algorithm"] == "SHA256"
    assert renewed_signature["classical_issues"] == []
    assert renewed_signature["quantum_status"] == "vulnerable"


def test_context_time_controls_expiry_and_freshness():
    scan = service().run_scan(request(raw_cloud(), "2026-07-01T00:00:00Z"))
    assert not any("certificate_expired" in finding.posture_issues for finding in scan.findings)
    assert all(snapshot.age_seconds < 0 for snapshot in scan.snapshots)


def test_invalid_resource_and_missing_reference_keep_partial_results():
    item = raw_cloud()
    value = json.loads(item.content)
    value["kms_key_inventory.json"]["Keys"][0]["KeySpec"] = []
    removed = value["acm_certificates.json"]["Certificates"].pop(0)
    item.content = json.dumps(value)
    scan = service().run_scan(request(item))
    assert scan.status == "partial" and len(scan.assets) == 26
    assert scan.coverage[0].assessed == 26 and scan.coverage[0].failed == 1
    assert {error.code for error in scan.errors} == {"invalid_cloud_input", "unresolved_certificate"}
    assert any(r.target_asset_id == removed["CertificateArn"] for r in scan.relationships)
    assert "invalid_adapter_output" not in {error.code for error in scan.errors}


@pytest.mark.parametrize("content", ["{broken", "null", '{"Keys":[],"Keys":[]}', '{"Region":NaN}', '{"unexpected":{}}'])
def test_bad_raw_inputs_are_explicit_failures(content):
    item = ScanInput(name="bad.json", source_type="cloud", format="raw", content=content)
    scan = service().run_scan(request(item))
    assert scan.status == "failed" and not scan.findings
    assert scan.errors[0].code == "invalid_cloud_input"
    assert scan.coverage[0].unit == "inputs" and scan.coverage[0].failed == 1


def test_single_snapshot_base64_does_not_require_other_files():
    content = (ROOT / "cloud-posture/kms_key_inventory.json").read_bytes()
    item = ScanInput(name="keys.json", source_type="cloud", format="raw",
                     content=base64.b64encode(content).decode(), encoding="base64")
    scan = service().run_scan(request(item))
    assert scan.status == "completed" and len(scan.findings) == len(scan.assets) == 10
    assert scan.input_hashes[item.name] == hashlib.sha256(content).hexdigest()


@pytest.mark.parametrize("policy_name", ["", " \t\n"])
def test_api_blank_policy_preserves_other_resources(policy_name):
    item = raw_cloud()
    value = json.loads(item.content)
    listener = value["load_balancer_listeners.json"]["LoadBalancers"][0]["Listeners"][0]
    listener["SslPolicy"] = policy_name
    item.content = json.dumps(value)
    with TestClient(create_app()) as client:
        response = client.post("/api/scans", json=request(item).model_dump(mode="json"))
    assert response.status_code == 201
    scan = response.json()
    assert scan["status"] == "partial"
    assert len(scan["assets"]) == 27 and len(scan["findings"]) == 26
    assert all(asset["asset_id"] != listener["ListenerArn"] for asset in scan["assets"])
    assert all(finding["asset_id"] != listener["ListenerArn"] for finding in scan["findings"])
    assert scan["coverage"][0]["assessed"] == 27 and scan["coverage"][0]["failed"] == 1
    assert len(scan["errors"]) == 1
    assert scan["errors"][0]["code"] == "invalid_cloud_input"
    assert scan["errors"][0]["message"].endswith("/load_balancer_listeners.json/LoadBalancers/0/Listeners/0")


def test_unknown_policy_and_bad_snapshot_preserve_valid_data_and_exports():
    item = raw_cloud()
    value = json.loads(item.content)
    value["kms_key_inventory.json"]["GeneratedAt"] = "invalid"
    value["load_balancer_listeners.json"]["LoadBalancers"][3]["Listeners"][0]["SslPolicy"] = "Unmapped-Policy"
    item.content = json.dumps(value)
    with TestClient(create_app()) as client:
        response = client.post("/api/scans", json=request(item).model_dump(mode="json"))
        assert response.status_code == 201
        scan = response.json()
        assert scan["status"] == "partial" and len(scan["assets"]) == 18
        assert scan["coverage"][1]["unit"] == "inputs" and scan["coverage"][1]["failed"] == 1
        policy = next(f["parameters"]["configured_tls_policy"] for f in scan["findings"]
                      if f["parameters"]["configured_tls_policy"] and
                      f["parameters"]["configured_tls_policy"]["name"] == "Unmapped-Policy")
        for key in ("protocols", "cipher_suites", "hybrid_groups", "hybrid_pq_capable", "classical_fallback", "negotiated_group"):
            assert policy[key] is None
        with pytest.raises(ValidationError):
            ConfiguredTLSPolicy.model_validate({**policy, "negotiated_group": "X25519MLKEM768"})
        url = f"/api/scans/{scan['scan_id']}/export"
        assert client.get(url + "?format=json").json() == scan
        validate_cyclonedx(client.get(url + "?format=cyclonedx").json())


@pytest.mark.parametrize("field", ["assets", "snapshots"])
def test_service_revalidates_inventory_and_snapshot_input_identity(field):
    item = raw_cloud()
    output = cloud_adapter(item, AdapterContext(evaluated_at=EVALUATED_AT))
    if field == "assets":
        output.assets[0].source_type = "pcap"
    else:
        output.snapshots[0].input_name = "other-input"
    registry = AdapterRegistry()
    registry.register("cloud", lambda *_: output)
    scan = ScanService(registry=registry).run_scan(request(item))
    assert scan.status == "failed" and not scan.findings and not scan.assets
    assert scan.errors[0].code == "invalid_adapter_output"
