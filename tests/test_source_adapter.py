"""Raw source ingestion, evidence privacy, failure isolation and export."""

import base64
import json

from fastapi.testclient import TestClient

from adapters.registry import AdapterRegistry
from adapters.source import MAX_SOURCE_BYTES, scan_source
from api.main import create_app
from core.models import AdapterContext, ScanInput, ScanRequest
from core.service import ScanService
from export.cyclonedx import validate_cyclonedx
from scripts.scan_source import main, scan_path

CONTEXT = AdapterContext(evaluated_at="2026-10-10T00:00:00Z")


def source(content, name="example.py", **kwargs):
    return ScanInput(name=name, source_type="source", format="raw", content=content, **kwargs)


def test_default_api_raw_source_export_and_metadata_only():
    secret = "private-test-sentinel-never-export"
    item = source(f'import hashlib\nhashlib.md5(b"{secret}")\n')
    with TestClient(create_app()) as client:
        response = client.post("/api/scans", json={"inputs": [item.model_dump()]})
        assert response.status_code == 201
        scan = response.json()
        assert scan["status"] == "completed" and not scan["synthetic"]
        assert len(scan["findings"]) == 1
        finding = scan["findings"][0]
        assert finding["algorithm"] == "MD5" and finding["evidence_kind"] == "declared"
        assert finding["evidence"][0]["file"] == "example.py"
        assert finding["evidence"][0]["locator"].startswith("line:2:")
        assert "source-api-v1" in finding["evidence"][0]["detail"]
        assert secret not in response.text
        cbom = client.get(f'/api/scans/{scan["scan_id"]}/export?format=cyclonedx')
        assert cbom.status_code == 200 and secret not in cbom.text
        validate_cyclonedx(cbom.json())


def test_encoding_and_input_name_is_never_opened(tmp_path):
    forbidden = tmp_path / "private.py"
    forbidden.write_text("import hashlib\nhashlib.md5(b'not submitted')")
    item = source(base64.b64encode(b"pass\n").decode(), str(forbidden), encoding="base64")
    result = scan_source(item, CONTEXT)
    assert result.findings == [] and result.coverage[0].assessed == 1


def test_failures_keep_successful_files_and_sanitize_parser_text():
    good = source("import hashlib\nhashlib.sha256(b'')", "good.py")
    bad = source("def secret_not_for_output(:", "bad.py")
    unsupported = source("ignored", "source.rs")
    scan = ScanService().run_scan(ScanRequest(inputs=[good, bad, unsupported]))
    assert scan.status == "partial" and len(scan.findings) == 1
    assert [(c.assessed, c.failed, c.unsupported) for c in scan.coverage] == [(1, 0, 0), (0, 1, 0), (0, 0, 1)]
    assert "secret_not_for_output" not in scan.model_dump_json()


def test_adapter_bounds_invalid_utf8_and_explicit_registry():
    result = scan_source(source(" " * (MAX_SOURCE_BYTES + 1)), CONTEXT)
    assert result.errors[0].code == "source_limit_exceeded"
    result = scan_source(source("/w==", encoding="base64"), CONTEXT)
    assert result.errors[0].code == "invalid_source_encoding"
    scan = ScanService(registry=AdapterRegistry()).run_scan(ScanRequest(inputs=[source("pass")]))
    assert scan.errors[0].code == "unsupported_adapter"


def test_ids_stable_when_algorithm_or_key_size_changes():
    before = scan_source(source("import hashlib\nhashlib.md5(data)"), CONTEXT).findings[0]
    after = scan_source(source("import hashlib\nhashlib.sha256(data)"), CONTEXT).findings[0]
    assert before.id == after.id and before.asset_id == after.asset_id


def test_cli_batches_relative_paths_and_file_errors(tmp_path):
    for i in range(17):
        (tmp_path / f"sample_{i:02}.py").write_text("import hashlib\nhashlib.sha1(data)")
    (tmp_path / "broken.py").write_bytes(b"\xff")
    (tmp_path / "large.py").write_bytes(b" " * (MAX_SOURCE_BYTES + 1))
    (tmp_path / "notes.txt").write_text("ignored")
    result = scan_path(tmp_path, synthetic=True)
    assert result["files_selected"] == 19
    assert len(result["file_errors"]) == 2
    assert [len(s["coverage"]) for s in result["scans"]] == [16, 1]
    assert all(s["synthetic"] for s in result["scans"])
    assert all(not f["evidence"][0]["file"].startswith("/") for s in result["scans"] for f in s["findings"])


def test_cli_writes_validated_cbom_and_json(tmp_path, monkeypatch):
    path = tmp_path / "input.py"
    path.write_text("import hashlib\nhashlib.md5(data)")
    output = tmp_path / "report.json"
    cboms = tmp_path / "cbom"
    monkeypatch.setattr("sys.argv", ["scan_source", str(path), "--output", str(output), "--cyclonedx-dir", str(cboms)])
    assert main() == 0
    assert len(json.loads(output.read_text())["scans"][0]["findings"]) == 1
    validate_cyclonedx(json.loads((cboms / "batch-1.cdx.json").read_text()))
