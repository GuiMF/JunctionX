from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from core.models import MAX_SCAN_BYTES, ScanInput, ScanRequest
from core.uploads import UploadError, UploadStore
from export.cyclonedx import validate_cyclonedx


def batch(name="project/crypto.py", content='import hashlib\nhashlib.md5(b"data")\n'):
    return {"inputs": [{"name": name, "content": content, "source_type": "source", "format": "raw"}]}


def test_batched_upload_produces_one_persisted_scan_and_both_exports():
    app = create_app()
    with TestClient(app) as client:
        upload_id = client.post("/api/uploads").json()["upload_id"]
        endpoint = f"/api/uploads/{upload_id}"
        directory = Path(app.state.upload_store._uploads[upload_id].directory.name)
        requests = [batch(), batch("project/nested/crypto.py"), batch("project/broken.py", "def broken(:")]
        for index, request in enumerate(requests):
            response = client.post(endpoint + "/batches", json=request)
            assert response.status_code == 200, response.text
            assert response.json()["input_count"] == index + 1
        assert sorted(path.name for path in directory.iterdir()) == ["0", "1", "2"]
        scan_response = client.post(endpoint + "/complete")
        assert scan_response.status_code == 201, scan_response.text
        scan = scan_response.json()
        assert scan["status"] == "partial"
        assert len(scan["findings"]) == 2
        assert len(scan["coverage"]) == 3
        assert scan["errors"][0]["input_name"] == "project/broken.py"
        assert not directory.exists()
        # Compare the complete result/score to the original single-request pipeline.
        direct = client.post("/api/scans", json={"inputs": [r["inputs"][0] for r in requests]}).json()
        for key in ["score", "findings", "coverage", "errors", "input_hashes"]:
            assert scan[key] == direct[key]
        base = f'/api/scans/{scan["scan_id"]}'
        assert client.get(base).json() == scan
        assert client.get(base + "/export?format=json").json() == scan
        validate_cyclonedx(client.get(base + "/export?format=cyclonedx").json())
        assert client.post(endpoint + "/complete").status_code == 404


def test_three_gb_total_boundary_across_batches_without_allocating_three_gb():
    assert MAX_SCAN_BYTES == 3_000_000_000
    store = UploadStore()
    try:
        key = store.create()
        upload = store._uploads[key]
        # Represent already-uploaded content; exercise the exact accounting boundary.
        upload.received_bytes = MAX_SCAN_BYTES - 4
        receipt = store.append(key, ScanRequest.model_validate(batch(content="éé")))
        assert receipt["received_bytes"] == MAX_SCAN_BYTES
        with pytest.raises(UploadError, match="3 GB"):
            store.append(key, ScanRequest.model_validate(batch("extra.py", "x")))
        assert len(upload.entries) == 1
        assert list(upload.inputs())[0].content == "éé"
    finally:
        store.close()


def test_duplicate_names_and_batch_limits_are_atomic(monkeypatch):
    monkeypatch.setattr("core.uploads.MAX_UPLOAD_BATCH_BYTES", 8)
    monkeypatch.setattr("core.uploads.MAX_SCAN_INPUTS", 2)
    store = UploadStore()
    try:
        key = store.create()
        store.append(key, ScanRequest.model_validate(batch(content="éééé")))
        with pytest.raises(UploadError, match="unique"):
            store.append(key, ScanRequest.model_validate(batch(content="x")))
        with pytest.raises(UploadError, match="64 MiB"):
            store.append(key, ScanRequest.model_validate(batch("large.py", "ééééé")))
        store.append(key, ScanRequest.model_validate(batch("second.py", "")))
        with pytest.raises(UploadError, match="10,000"):
            store.append(key, ScanRequest.model_validate(batch("third.py", "")))
        assert store._uploads[key].received_bytes == 8
    finally:
        store.close()


def test_cancel_expiry_capacity_and_shutdown_remove_temporary_files():
    app = create_app()
    with TestClient(app) as client:
        key = client.post("/api/uploads").json()["upload_id"]
        store = app.state.upload_store
        directory = Path(store._uploads[key].directory.name)
        assert client.post(f"/api/uploads/{key}/complete").status_code == 422
        assert client.post(f"/api/uploads/{key}/batches", json=batch()).status_code == 200
        assert client.delete(f"/api/uploads/{key}").status_code == 204
        assert not directory.exists()
        assert client.delete(f"/api/uploads/{key}").status_code == 204
        assert client.post(f"/api/uploads/{key}/batches", json=batch()).status_code == 404
        keys = [client.post("/api/uploads").json()["upload_id"] for _ in range(2)]
        assert client.post("/api/uploads").status_code == 429
        expired = Path(store._uploads[keys[0]].directory.name)
        store._uploads[keys[0]].updated_at -= 3601
        new_key = client.post("/api/uploads").json()["upload_id"]
        assert not expired.exists()
        remaining = Path(store._uploads[new_key].directory.name)
    assert not remaining.exists()


def test_disk_write_failure_rolls_back_batch(monkeypatch):
    store = UploadStore()
    try:
        key = store.create()
        write = Path.write_bytes
        def fail_second(path, data):
            if path.name == "1":
                raise OSError("disk full")
            return write(path, data)
        monkeypatch.setattr(Path, "write_bytes", fail_second)
        request = ScanRequest.model_validate({"inputs": batch()["inputs"] + batch("other.py")["inputs"]})
        with pytest.raises(UploadError) as error:
            store.append(key, request)
        assert error.value.status == 507
        upload = store._uploads[key]
        assert upload.received_bytes == 0 and upload.entries == []
        assert list(Path(upload.directory.name).iterdir()) == []
    finally:
        store.close()


def test_completion_failure_also_cleans_up(monkeypatch):
    app = create_app()
    def fail(*args, **kwargs):
        raise RuntimeError("test failure")
    monkeypatch.setattr(app.state.scan_service, "run_inputs", fail)
    with TestClient(app, raise_server_exceptions=False) as client:
        key = client.post("/api/uploads").json()["upload_id"]
        directory = Path(app.state.upload_store._uploads[key].directory.name)
        client.post(f"/api/uploads/{key}/batches", json=batch())
        assert client.post(f"/api/uploads/{key}/complete").status_code == 500
        assert not directory.exists()


def test_disk_round_trip_preserves_newlines_and_never_opens_input_names(tmp_path):
    store = UploadStore()
    try:
        key = store.create()
        outside = tmp_path / "not-an-upload"
        source = "# café\r\npass\r\n"
        store.append(key, ScanRequest.model_validate(batch(str(outside), source)))
        assert not outside.exists()
        assert list(store._uploads[key].inputs())[0].content == source
    finally:
        store.close()
