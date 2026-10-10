from fastapi.testclient import TestClient
import pytest

from api.main import create_app
from export.cyclonedx import validate_cyclonedx


@pytest.fixture
def client():
    return TestClient(create_app())


def request_body():
    import json

    name = "source-fixture.json"
    fixture = {
        "fixture_format": "quantumtrace.normalized.v1",
        "result": {
            "findings": [{
                "id": "rsa-signature", "asset_id": "signing-service", "source_type": "source",
                "algorithm": "RSA", "usage": "signature", "parameters": {"key_bits": 2048},
                "evidence_kind": "declared", "confidence": "high",
                "evidence": [{"file": "sign.py", "locator": "line 5", "detail": "RSA signature key configuration"}],
            }],
            "coverage": [{"source_type": "source", "input_name": name, "unit": "files", "assessed": 1}],
        },
    }
    return {"inputs": [{"name": name, "source_type": "source", "format": "normalized", "content": json.dumps(fixture)}]}


def test_create_get_and_both_real_exports(client):
    response = client.post("/api/scans", json=request_body())
    assert response.status_code == 201, response.text
    scan = response.json()
    assert scan["status"] == "completed"
    assert scan["findings"][0]["quantum_status"] == "vulnerable"
    endpoint = f'/api/scans/{scan["scan_id"]}'
    assert client.get(endpoint).json() == scan
    response = client.get(endpoint + "/export?format=json")
    assert response.json() == scan
    assert "attachment" in response.headers["content-disposition"]
    response = client.get(endpoint + "/export?format=cyclonedx")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/vnd.cyclonedx+json"
    validate_cyclonedx(response.json())


def test_partial_success_is_a_persisted_scan():
    from core.service import ScanService
    from adapters.registry import AdapterRegistry
    empty_service = ScanService(registry=AdapterRegistry())
    client = TestClient(create_app(service=empty_service))
    body = request_body()
    body["inputs"].append({"name": "capture.pcap", "source_type": "pcap", "format": "raw", "content": "capture bytes"})
    response = client.post("/api/scans", json=body)
    assert response.status_code == 201
    scan = response.json()
    assert scan["status"] == "partial"
    assert len(scan["findings"]) == 1
    assert scan["errors"][0]["code"] == "unsupported_adapter"


@pytest.mark.parametrize("endpoint", ["/api/scans/missing", "/api/scans/missing/export"])
def test_missing_scan_404(client, endpoint):
    assert client.get(endpoint).status_code == 404


def test_unsupported_export_format_rejected(client):
    assert client.get("/api/scans/missing/export?format=xml").status_code == 422


@pytest.mark.parametrize("body", [
    {"inputs": []},
    {"inputs": [{"name": "test", "source_type": "cloud", "format": "raw", "path": "/etc/passwd"}]},
    {"inputs": [{"name": "test", "source_type": "other", "format": "raw", "content": ""}]},
    {"inputs": [{"name": "test", "source_type": "source", "format": "raw", "content": ""}], "evaluated_at": "2026-10-10T10:00:00"},
])
def test_request_validation_422(client, body):
    assert client.post("/api/scans", json=body).status_code == 422


def test_folder_input_count_limit(client):
    inputs = [
        {"name": f"project/{i}/source.py", "source_type": "source", "format": "raw", "content": "# empty"}
        for i in range(1024)
    ]
    response = client.post("/api/scans", json={"inputs": inputs})
    assert response.status_code == 201
    assert len(response.json()["coverage"]) == 1024
    assert client.post("/api/scans", json={"inputs": inputs + [dict(inputs[0], name="extra.py")]}).status_code == 422


@pytest.mark.parametrize("failure", ["duplicate_names", "extra_field", "oversized_content"])
def test_validation_errors_do_not_echo_submitted_content(client, failure):
    secret = "private-key-material-never-echo-this"
    item = {"name": "test", "source_type": "source", "format": "raw", "content": secret}
    body = {"inputs": [item]}
    if failure == "duplicate_names":
        body["inputs"].append(item.copy())
    elif failure == "extra_field":
        body["credentials"] = secret
    else:
        item["content"] = secret + "x" * (8 * 1024 * 1024)
    response = client.post("/api/scans", json=body)
    assert response.status_code == 422
    assert secret not in response.text
    assert all(set(error) == {"type", "loc", "msg"} for error in response.json()["detail"])


def test_malformed_unicode_error_location_does_not_crash(client):
    response = client.post(
        "/api/scans", content=b'{"inputs": [], "\\ud800": "secret"}',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert "secret" not in response.text


def test_openapi_contains_shared_contract(client):
    schema = client.get("/openapi.json").json()
    assert "ScanRequest" in schema["components"]["schemas"]
    assert "Finding" in schema["components"]["schemas"]
    assert "/api/scans/{scan_id}/export" in schema["paths"]


@pytest.mark.parametrize("origin", [
    "http://localhost:3000", "http://127.0.0.1:3000",
    "http://localhost:5173", "http://127.0.0.1:5173",
])
def test_local_frontend_preflight_allowed(client, origin):
    response = client.options("/api/scans", headers={
        "Origin": origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type",
    })
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == origin
    assert "access-control-allow-credentials" not in response.headers


def test_arbitrary_origin_preflight_rejected(client):
    response = client.options("/api/scans", headers={
        "Origin": "https://untrusted.example",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type",
    })
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_cors_can_be_disabled_or_explicitly_configured():
    headers = {"Origin": "http://localhost:9000", "Access-Control-Request-Method": "GET"}
    disabled = TestClient(create_app(cors_origins=[]))
    response = disabled.options("/api/scans/test", headers=headers)
    assert "access-control-allow-origin" not in response.headers
    configured = TestClient(create_app(cors_origins=["http://localhost:9000"]))
    response = configured.options("/api/scans/test", headers=headers)
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:9000"


from unittest.mock import patch, MagicMock

@patch('adapters.network.pyshark.FileCapture')
def test_raw_pcap_scan(mock_capture_cls, client):
    import base64
    content = base64.b64encode(b"dummy pcap bytes").decode("utf-8")
    body = {
        "inputs": [
            {
                "name": "network.pcap",
                "source_type": "pcap",
                "format": "raw",
                "content": content,
                "encoding": "base64"
            }
        ]
    }
    
    # Mock PyShark to simulate a successful TLS capture
    mock_packet = MagicMock()
    mock_packet.ip.src = "192.168.1.1"
    mock_packet.ip.dst = "192.168.1.2"
    mock_packet.tcp.stream = "1"
    mock_packet.__contains__.return_value = True
    mock_packet.tls.handshake_type = "2"
    mock_packet.tls.handshake_ciphersuite = "0x002f"
    mock_packet.tls.handshake_random = "dummyrandom"
    mock_packet.number = 100
    mock_packet.sniff_timestamp = "1672531200.0"
    
    mock_capture_instance = MagicMock()
    mock_capture_instance.__iter__.return_value = [mock_packet]
    mock_capture_cls.return_value = mock_capture_instance

    response = client.post("/api/scans", json=body)
    assert response.status_code == 201
    scan = response.json()
    assert scan["status"] == "completed"
    assert len(scan.get("errors", [])) == 0
    
    # Verify the pcap findings and coverage
    has_pcap_coverage = any(c["source_type"] == "pcap" for c in scan.get("coverage", []))
    assert has_pcap_coverage
    has_pcap_findings = any(f["source_type"] == "pcap" for f in scan.get("findings", []))
    assert has_pcap_findings
