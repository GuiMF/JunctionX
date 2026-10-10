"""Shared inline cloud adapter; no local file or AWS access."""

import hashlib
import json

from adapters.cloud import (
    INPUTS, MAPPING_VERSION, _invalid_json_constant, _json_float, _json_object, _scan_cloud,
)
from adapters.normalized import input_bytes
from core.models import (
    AdapterContext, AdapterResult, Coverage, Finding, InventoryAsset,
    Relationship, ScanError, ScanInput, Snapshot,
)


def cloud_adapter(scan_input: ScanInput, context: AdapterContext) -> AdapterResult:
    content = input_bytes(scan_input)
    try:
        value = json.loads(content, object_pairs_hook=_json_object,
                           parse_constant=_invalid_json_constant, parse_float=_json_float)
        if not isinstance(value, dict):
            raise ValueError("Cloud input must be an object")
        collections = [filename for filename, collection, *_ in INPUTS if collection in value]
        if len(collections) == 1:
            contents = {collections[0]: (scan_input.name, content, "")}
        elif not collections and value and set(value) <= {row[0] for row in INPUTS}:
            contents = {filename: (scan_input.name, json.dumps(snapshot).encode(), "/" + filename)
                        for filename, snapshot in value.items()}
        else:
            raise ValueError("Unsupported cloud input shape")
    except (ValueError, RecursionError):
        return AdapterResult(
            coverage=[Coverage(source_type="cloud", input_name=scan_input.name, unit="inputs", failed=1)],
            errors=[ScanError(source_type="cloud", input_name=scan_input.name,
                              code="invalid_cloud_input", message="Expected a cloud snapshot or a filename-keyed snapshot bundle")],
            tool_versions={"cloud-adapter": MAPPING_VERSION},
        )

    report = _scan_cloud(contents, context.evaluated_at)
    assets = {asset["asset_id"]: asset for asset in report["assets"]}
    findings = report["findings"]
    for asset in assets.values():
        if asset["kind"] == "listener" and asset["configuration"].get("Protocol") == "HTTP":
            findings.append({
                "id": hashlib.sha256((asset["asset_id"] + "|http_listener").encode()).hexdigest(),
                "asset_id": asset["asset_id"], "source_type": "cloud", "algorithm": "HTTP",
                "usage": "unknown", "evidence_kind": "configured", "confidence": "high",
                "owner": asset["owner"], "evidence": list(asset["evidence"]), "parameters": {},
            })
    for finding in findings:
        asset = assets[finding["asset_id"]]
        finding["observed_at"] = asset["snapshot_at"]
        finding["owner"] = (finding["owner"] or "").strip() or None
        finding["posture_issues"] = []
        if "tls_policy" in asset:
            policy = dict(asset["tls_policy"])
            policy["classical_fallback"] = True if policy["protocols"] is not None else None
            finding["parameters"]["configured_tls_policy"] = policy
        for issue in report["posture_issues"]:
            if issue["asset_id"] == finding["asset_id"]:
                finding["posture_issues"].append(issue["code"])
                for evidence in issue["evidence"]:
                    if evidence not in finding["evidence"]:
                        finding["evidence"].append(evidence)

    resource_coverage = [item for item in report["coverage"].values() if item["unit"] == "resources"]
    coverage = [Coverage(
        source_type="cloud", input_name=scan_input.name, unit="resources",
        assessed=sum(item["inventoried"] for item in resource_coverage),
        failed=sum(item["failed"] for item in resource_coverage),
    )]
    file_failures = sum(item["file_failed"] for item in resource_coverage)
    if file_failures:
        coverage.append(Coverage(source_type="cloud", input_name=scan_input.name, unit="inputs", failed=file_failures))
    relationships = [Relationship(
        source_asset_id=relation["source_id"], target_asset_id=relation["target_id"],
        kind=relation["kind"], evidence=relation["evidence"],
    ) for relation in report["relationships"] if isinstance(relation["target_id"], str) and relation["target_id"].strip()]
    return AdapterResult(
        findings=[Finding.model_validate(finding) for finding in findings], coverage=coverage,
        errors=[ScanError(
            source_type="cloud", input_name=scan_input.name,
            code="unresolved_certificate" if error["message"] == "Unresolved certificate reference" else "invalid_cloud_input",
            message=("Unresolved certificate reference" if error["message"] == "Unresolved certificate reference"
                     else "Invalid cloud snapshot or resource") + " at " + (error["locator"] or "/"),
        ) for error in report["errors"]],
        relationships=relationships, tool_versions={"cloud-adapter": MAPPING_VERSION},
        assets=[InventoryAsset(
            **{key: asset[key] for key in ("asset_id", "kind", "parent_id", "snapshot_at", "account", "region", "configuration", "evidence")},
            source_type="cloud", owner=(asset["owner"] or "").strip() or None,
        ) for asset in assets.values()],
        snapshots=[Snapshot(source_type="cloud", input_name=scan_input.name, **snapshot)
                   for snapshot in report["snapshots"]],
    )
