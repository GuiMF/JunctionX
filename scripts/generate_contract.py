"""Regenerate checked-in schemas and explicitly synthetic handoff examples."""

import json
from datetime import datetime, timezone
from pathlib import Path

from adapters.normalized import NormalizedFixture
from api.main import app
from core.identity import stable_asset_id, stable_finding_id
from core.models import (
    AdapterContext, AdapterResult, Coverage, Finding, Relationship,
    ScanInput, ScanRequest, ScanResult,
)
from core.service import run_scan
from export.cyclonedx import export_cyclonedx

ROOT = Path(__file__).resolve().parents[1]
EVALUATED_AT = datetime(2026, 10, 10, 12, tzinfo=timezone.utc)


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def observation(source, identity, slot, algorithm, usage, kind, *, parameters=None, owner=None, locator="example location", posture=None):
    asset = stable_asset_id(source, identity)
    return Finding(
        id=stable_finding_id(asset, usage, slot, kind), asset_id=asset,
        source_type=source, algorithm=algorithm, parameters=parameters or {},
        usage=usage, evidence_kind=kind, confidence="high", owner=owner,
        observed_at=EVALUATED_AT if source != "source" else None,
        posture_issues=posture or [],
        evidence=[{"file": f"synthetic/{source}-example", "locator": locator,
                   "detail": f"Synthetic adapter observation: {algorithm} for {usage}; not a real scan."}],
    )


def build_examples() -> dict[str, ScanRequest]:
    source = [
        observation("source", "demo:crypto.py:sign", "signing-key", "RSA", "signature", "declared", parameters={"key_bits": 1024, "hash_algorithm": "SHA-1"}, owner="payments", locator="line 12"),
        observation("source", "demo:crypto.py:token", "signing-key", "Ed25519", "signature", "declared", owner="identity", locator="line 24"),
        observation("source", "demo:crypto.py:encrypt", "data-cipher", "AES", "encryption", "declared", parameters={"key_bits": 256, "mode": "GCM"}, locator="line 36"),
        observation("source", "demo:crypto.py:unresolved", "data-cipher", "AES", "encryption", "declared", locator="line 48"),
    ]
    network = [
        observation("pcap", "demo:capture:flow-1", "selected-group", "X25519", "key_establishment", "observed", locator="frame 18; stream 1"),
        observation("pcap", "demo:capture:flow-1", "offered-hybrid-group", "X25519MLKEM768", "key_establishment", "offered", locator="frame 15; stream 1"),
        observation("pcap", "demo:capture:flow-1", "authentication", "unknown", "signature", "observed", locator="stream 1; encrypted TLS 1.3 authentication unavailable"),
    ]
    cloud = [
        observation("cloud", "demo:listener:partner-api:443", "configured-key-exchange", "ECDHE", "key_establishment", "configured", parameters={"named_group": "X25519"}, owner="partners", locator="/listeners/0/securityPolicy"),
        observation("cloud", "demo:certificate:partner-api", "certificate-signature", "RSA", "signature", "configured", parameters={"key_bits": 2048}, owner="partners", locator="/certificates/0/signatureAlgorithm", posture=["Synthetic certificate expiry issue for demonstration; not live AWS state."]),
        observation("cloud", "demo:kms:payments", "encryption-key", "RSA", "encryption", "configured", parameters={"key_bits": 2048}, owner="payments", locator="/keys/0/KeySpec"),
    ]
    relationship = Relationship(source_asset_id=cloud[0].asset_id, target_asset_id=cloud[1].asset_id,
                                kind="uses_certificate", evidence=[{"file": "synthetic/cloud-example", "locator": "/listeners/0/CertificateArn", "detail": "Explicit synthetic certificate identifier reference"}])
    requests = {}
    original_inputs = []
    fixtures_dir = ROOT / "examples" / "adapters"
    for source_type, name, findings, unit, assessed, unknown in [
        ("source", "source-example.json", source, "files", 3, 1),
        ("pcap", "network-example.json", network, "sessions", 1, 0),
        ("cloud", "cloud-example.json", cloud, "resources", 3, 0),
    ]:
        result = AdapterResult(findings=findings, coverage=[Coverage(source_type=source_type, input_name=name, unit=unit, assessed=assessed, unknown=unknown)],
                               relationships=[relationship] if source_type == "cloud" else [],
                               tool_versions={"synthetic-example-builder": "1.0.0"})
        envelope = NormalizedFixture(fixture_format="quantumtrace.normalized.v1", result=result)
        write_json(fixtures_dir / name, envelope.model_dump(mode="json"))
        original_inputs.append(ScanInput(name=name, source_type=source_type, format="normalized", content=envelope.model_dump_json()))
    requests["scan-original"] = ScanRequest(inputs=original_inputs, evaluated_at=EVALUATED_AT, synthetic=True, label="Synthetic original integration fixtures")
    modified = requests["scan-original"].model_copy(deep=True)
    modified.label = "Synthetic modified configuration; negotiation unverified"
    envelope = NormalizedFixture.model_validate_json(modified.inputs[2].content)
    envelope.result.findings[0].algorithm = "X25519MLKEM768"
    envelope.result.findings[0].parameters.named_group = "X25519MLKEM768"
    envelope.result.findings[0].evidence[0].detail = "Synthetic modified configuration offers a standardized hybrid group; observed negotiation remains unverified."
    modified.inputs[2].content = envelope.model_dump_json()
    write_json(fixtures_dir / "cloud-modified-example.json", envelope.model_dump(mode="json"))
    requests["scan-modified"] = modified
    partial = requests["scan-original"].model_copy(deep=True)
    partial.label = "Synthetic partial scan with unavailable raw scanner"
    partial.inputs.append(ScanInput(name="unimplemented.py", source_type="source", format="raw", content="print('not scanned')"))
    requests["scan-partial"] = partial
    return requests


def main():
    for model in (Finding, AdapterContext, AdapterResult, ScanInput, ScanRequest, ScanResult, NormalizedFixture):
        write_json(ROOT / "schemas" / f"{model.__name__}.schema.json", model.model_json_schema())
    write_json(ROOT / "schemas" / "openapi.json", app.openapi())
    for name, request in build_examples().items():
        write_json(ROOT / "examples" / f"{name}.request.json", request.model_dump(mode="json"))
        scan = run_scan(request)
        # Stable metadata for reproducible checked-in examples only; runtime uses UUID and current start time.
        scan.scan_id = f"example-{name}"
        scan.started_at = EVALUATED_AT
        write_json(ROOT / "examples" / f"{name}.response.json", scan.model_dump(mode="json"))
        if name == "scan-original":
            write_json(ROOT / "examples" / "scan-original.cdx.json", export_cyclonedx(scan))


if __name__ == "__main__":
    main()
