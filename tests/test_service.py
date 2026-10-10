import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json

import pytest
from pydantic import ValidationError

from adapters.registry import AdapterRegistry
from core.models import AdapterResult, Coverage, ScanInput, ScanRequest
from core.service import ScanService, ScanStore, run_scan


def fixture_input(name="fixture.json", source_type="source", algorithm="RSA", **updates):
    finding = {
        "id": "finding-one", "asset_id": "asset-one", "source_type": source_type,
        "algorithm": algorithm, "parameters": {"key_bits": 2048}, "usage": "signature",
        "evidence_kind": "declared", "confidence": "high",
        "evidence": [{"file": "example.py", "locator": "line 3", "detail": "RSA public key size is 2048 bits"}],
    }
    finding.update(updates)
    envelope = {
        "fixture_format": "quantumtrace.normalized.v1",
        "result": {
            "findings": [finding],
            "coverage": [{"source_type": source_type, "input_name": name, "unit": "files", "assessed": 1}],
        },
    }
    return ScanInput(name=name, source_type=source_type, format="normalized", content=json.dumps(envelope))


def raw_input(name="capture.pcap", source_type="pcap"):
    return ScanInput(name=name, source_type=source_type, format="raw", content="raw content")


def test_normalized_is_assessed_and_labelled_not_a_raw_scan():
    item = fixture_input(quantum_status="resistant_primitive", challenge_tier="resilient")
    scan = run_scan(ScanRequest(inputs=[item], evaluated_at="2026-10-10T00:00:00Z"))
    assert scan.status == "completed"
    assert scan.findings[0].quantum_status == "vulnerable"
    assert scan.synthetic is True
    assert scan.label == "Normalized adapter fixtures"
    assert scan.input_hashes[item.name] == hashlib.sha256(item.content.encode()).hexdigest()
    assert scan.evaluated_at.isoformat() == "2026-10-10T00:00:00+00:00"


def test_missing_raw_adapter_preserves_other_inputs():
    scan = run_scan(ScanRequest(inputs=[fixture_input(), raw_input()]))
    assert scan.status == "partial"
    assert len(scan.findings) == 1
    assert scan.errors[0].code == "unsupported_adapter"
    assert scan.coverage[-1].unsupported == 1
    assert scan.coverage[-1].unit == "inputs"


def test_all_unsupported_is_failed_and_not_resilient():
    scan = run_scan(ScanRequest(inputs=[raw_input()]))
    assert scan.status == "failed"
    assert scan.findings == []
    assert scan.coverage[0].unsupported == 1


def test_parser_exception_isolated_and_content_not_echoed():
    registry = AdapterRegistry()

    def broken(_, context):
        raise RuntimeError("secret-input-content")

    registry.register("pcap", broken)
    scan = run_scan(ScanRequest(inputs=[raw_input(), fixture_input()]), registry)
    assert scan.status == "partial"
    assert scan.errors[0].code == "adapter_failed"
    assert "secret-input-content" not in scan.model_dump_json()
    assert len(scan.findings) == 1


@pytest.mark.parametrize("failure", ["source", "coverage", "evidence"])
def test_bad_adapter_output_isolated(failure):
    item = fixture_input()
    envelope = json.loads(item.content)
    if failure == "source":
        envelope["result"]["findings"][0]["source_type"] = "pcap"
    elif failure == "coverage":
        envelope["result"]["coverage"][0]["input_name"] = "other-input"
    else:
        envelope["result"]["findings"][0]["evidence"] = []
    item.content = json.dumps(envelope)
    scan = run_scan(ScanRequest(inputs=[item]))
    assert scan.status == "failed"
    assert scan.findings == []
    assert scan.errors[0].code in {"invalid_adapter_output", "invalid_normalized_fixture"}


def test_fixture_requires_explicit_marker():
    item = fixture_input()
    item.content = json.dumps(json.loads(item.content)["result"])
    scan = run_scan(ScanRequest(inputs=[item]))
    assert scan.errors[0].code == "invalid_normalized_fixture"


def test_identity_collision_rejects_only_later_input():
    scan = run_scan(ScanRequest(inputs=[fixture_input(), fixture_input("second.json", algorithm="Ed25519")]))
    assert scan.status == "partial"
    assert len(scan.findings) == 1
    assert scan.findings[0].algorithm == "RSA"
    assert scan.errors[0].code == "invalid_adapter_output"
    assert scan.errors[0].input_name == "second.json"


def test_base64_decoding_and_bad_encoding():
    item = fixture_input()
    original = item.content.encode()
    item.content = base64.b64encode(original).decode()
    item.encoding = "base64"
    scan = run_scan(ScanRequest(inputs=[item]))
    assert scan.status == "completed"
    assert scan.input_hashes[item.name] == hashlib.sha256(original).hexdigest()
    item.content = "not base64!"
    scan = run_scan(ScanRequest(inputs=[item]))
    assert scan.status == "failed"
    assert scan.errors[0].code == "invalid_encoding"


def test_raw_adapter_receives_inline_input():
    registry = AdapterRegistry()
    seen = []

    def adapter(item, context):
        seen.append(item.content)
        return AdapterResult(coverage=[Coverage(source_type=item.source_type, input_name=item.name, unit="sessions", assessed=1)])

    registry.register("pcap", adapter)
    scan = run_scan(ScanRequest(inputs=[raw_input("/no/path/is/opened.pcap")]), registry)
    assert scan.status == "completed"
    assert scan.synthetic is False
    assert seen == ["raw content"]


def test_store_returns_independent_values_and_evicts_oldest():
    service = ScanService(store=ScanStore(capacity=1))
    first = service.run_scan(ScanRequest(inputs=[fixture_input()]))
    fetched = service.get_scan(first.scan_id)
    fetched.findings.clear()
    assert len(service.get_scan(first.scan_id).findings) == 1
    service.run_scan(ScanRequest(inputs=[fixture_input()]))
    assert service.get_scan(first.scan_id) is None


def test_concurrent_scans_keep_distinct_results():
    service = ScanService()
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _: service.run_scan(ScanRequest(inputs=[fixture_input()])), range(12)))
    assert len({scan.scan_id for scan in results}) == 12
    assert all(service.get_scan(scan.scan_id) is not None for scan in results)


def test_registry_rejects_accidental_override():
    registry = AdapterRegistry()
    registry.register("source", lambda item, context: None)
    with pytest.raises(ValueError, match="already registered"):
        registry.register("source", lambda item, context: None)


def test_tool_provenance_names_cannot_collide_across_inputs():
    registry = AdapterRegistry()

    def adapter(item, context):
        tool = "b/c" if item.name == "a" else "c"
        return AdapterResult(
            coverage=[Coverage(source_type=item.source_type, input_name=item.name, unit="files", assessed=1)],
            tool_versions={tool: item.name},
        )

    registry.register("source", adapter)
    scan = run_scan(ScanRequest(inputs=[
        raw_input("a", "source"), raw_input("a/b", "source"), raw_input("a%2Fb", "source"),
    ]), registry)
    assert scan.tool_versions == {
        "quantumtrace-core": "0.1.0",
        "a/b%2Fc": "a",
        "a%2Fb/c": "a/b",
        "a%252Fb/c": "a%2Fb",
    }


def test_adapter_evaluation_context_is_reproducible_and_isolated():
    from datetime import datetime, timezone

    registry = AdapterRegistry()
    seen = []
    selected_time = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)

    def adapter(item, context):
        seen.append(context.evaluated_at)
        # A badly behaved adapter must not change evaluation time for other inputs.
        context.evaluated_at = datetime(2030, 1, 1, tzinfo=timezone.utc)
        item.content = "mutated by adapter"
        return AdapterResult(coverage=[Coverage(source_type=item.source_type, input_name=item.name, unit="resources", assessed=1)])

    registry.register("cloud", adapter)
    request = ScanRequest(inputs=[raw_input("one.json", "cloud"), raw_input("two.json", "cloud")], evaluated_at=selected_time)
    scan = run_scan(request, registry)
    assert scan.status == "completed"
    assert seen == [selected_time, selected_time]
    assert scan.evaluated_at == request.evaluated_at == selected_time
    assert all(item.content == "raw content" for item in request.inputs)


@pytest.mark.parametrize("payload", [
    {"inputs": []},
    {"inputs": [raw_input().model_dump()] * 2},
    {"inputs": [raw_input().model_dump()], "evaluated_at": "2026-10-10T10:00:00"},
    {"inputs": [dict(raw_input().model_dump(), content="x" * (64 * 1024 * 1024 + 1))]},
])
def test_invalid_request_is_rejected(payload):
    with pytest.raises(ValidationError):
        ScanRequest.model_validate(payload)
