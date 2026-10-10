"""The CLI must assess adapter facts, retain failures, and print one JSON result."""

import base64
import json
from pathlib import Path
import runpy

import pytest

from adapters import network
from core.models import AdapterResult, Coverage, Evidence, Finding, ScanError


@pytest.mark.parametrize("failed", [False, True])
def test_capture_cli_uses_shared_assessment(tmp_path, monkeypatch, capsys, failed):
    capture = tmp_path / "sample.pcap"
    capture.write_bytes(b"test capture")

    def adapter(item, context):
        assert base64.b64decode(item.content) == capture.read_bytes()
        assert context.evaluated_at.tzinfo is not None
        coverage = Coverage(source_type="pcap", input_name=item.name, unit="sessions",
                            assessed=int(not failed), failed=int(failed))
        if failed:
            return AdapterResult(coverage=[coverage], errors=[ScanError(
                source_type="pcap", input_name=item.name, code="capture_error", message="Test failure",
            )])
        return AdapterResult(coverage=[coverage], findings=[Finding(
            id="test-rsa", asset_id="test-session", source_type="pcap", algorithm="RSA",
            usage="key_establishment", evidence_kind="observed", confidence="high",
            evidence=[Evidence(file=item.name, locator="frame:1", detail="Synthetic test observation")],
        )])

    monkeypatch.setattr(network, "parse_pcap_adapter", adapter)
    monkeypatch.setattr("sys.argv", ["network-capture.py", str(capture)])
    script = Path(__file__).resolve().parents[1] / "network-capture.py"
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(str(script), run_name="__main__")
    assert exit_info.value.code == int(failed)
    scan = json.loads(capsys.readouterr().out)
    assert scan["status"] == ("failed" if failed else "completed")
    if not failed:
        assert scan["findings"][0]["quantum_status"] == "vulnerable"
        assert scan["score"]["value"] == 100
