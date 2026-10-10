"""Reproducible cloud handoff using original and labelled modified fixtures."""

import argparse
import copy
import json

from adapters.cloud import scan_cloud


def build_certificate_renewal_demo(*, evaluated_at="2026-10-10T12:00:00Z"):
    before = scan_cloud("cloud-posture", evaluated_at=evaluated_at)
    after = scan_cloud("tests/fixtures/cloud-renewed", evaluated_at=evaluated_at)
    if before["errors"] or after["errors"]:
        raise ValueError("Renewal demo inputs contain errors")
    old_assets = {a["asset_id"]: a for a in before["assets"]}
    new_assets = {a["asset_id"]: a for a in after["assets"]}
    if old_assets.keys() != new_assets.keys():
        raise ValueError("Renewal demo must preserve asset IDs")
    changed = [a for identifier, a in old_assets.items()
               if a["configuration"] != new_assets[identifier]["configuration"]]
    if len(changed) != 1 or changed[0]["kind"] != "certificate":
        raise ValueError("Renewal demo must change exactly one certificate")
    old = changed[0]
    new = new_assets[old["asset_id"]]
    expected = dict(old["configuration"])
    for field in ("NotBefore", "NotAfter", "ImportedAt", "SignatureAlgorithm"):
        expected[field] = new["configuration"].get(field)
    if expected != new["configuration"] or new["configuration"]["SignatureAlgorithm"] != "SHA256WITHRSA":
        raise ValueError("Renewal must preserve certificate identity and key type/size, using SHA-256")
    old_issues = [i for i in before["posture_issues"] if i["asset_id"] == old["asset_id"]]
    new_issues = [i for i in after["posture_issues"] if i["asset_id"] == old["asset_id"]]
    if new_issues:
        raise ValueError("Renewed demo certificate must be valid at the evaluation time")
    return {
        "schema_version": "1.0", "evaluated_at": before["evaluated_at"],
        "label": "Synthetic certificate reimport; no certificate was issued or changed in AWS",
        "before": old, "after": new,
        "resolved_posture_issues": old_issues, "remaining_certificate_issues": new_issues,
        "relationships": [r for r in after["relationships"] if r["kind"] == "uses_certificate"
                          and r["target_id"] == old["asset_id"]],
        "coverage": {"before": before["coverage"], "after": after["coverage"]},
        "quantum_migration": False,
        "reference": "https://docs.aws.amazon.com/acm/latest/userguide/import-certificate.html",
    }


def build_demo(*, evaluated_at="2026-10-10T12:00:00Z"):
    before = scan_cloud("cloud-posture", evaluated_at=evaluated_at)
    after = scan_cloud("tests/fixtures/cloud-modified", evaluated_at=evaluated_at)
    if before["errors"] or after["errors"]:
        raise ValueError("Demo inputs contain errors; inspect both scan reports")
    old_assets = {a["asset_id"]: a for a in before["assets"]}
    new_assets = {a["asset_id"]: a for a in after["assets"]}
    if old_assets.keys() != new_assets.keys():
        raise ValueError("Original and modified inventories have different asset IDs")
    changes = [
        {"asset_id": identifier, "before": asset["tls_policy"], "after": new_assets[identifier]["tls_policy"],
         "before_evidence": asset["evidence"], "after_evidence": new_assets[identifier]["evidence"]}
        for identifier, asset in old_assets.items()
        if "tls_policy" in asset and asset["tls_policy"] != new_assets[identifier].get("tls_policy")
    ]
    if len(changes) != 1:
        raise ValueError("Demo must change exactly one listener policy")
    listener_id = changes[0]["asset_id"]
    links = [r for r in before["relationships"] if r["kind"] == "uses_certificate" and r["source_id"] == listener_id]
    if len(links) != 1 or not links[0]["resolved"]:
        raise ValueError("Demo listener must have one resolved certificate")
    certificate_id = links[0]["target_id"]
    if old_assets[certificate_id]["configuration"] != new_assets[certificate_id]["configuration"]:
        raise ValueError("Demo certificate must remain unchanged")
    for identifier, asset in old_assets.items():
        expected = copy.deepcopy(asset["configuration"])
        if identifier == listener_id:
            expected["SslPolicy"] = changes[0]["after"]["name"]
        if identifier == old_assets[listener_id]["parent_id"]:
            for listener in expected["Listeners"]:
                if listener["ListenerArn"] == listener_id:
                    listener["SslPolicy"] = changes[0]["after"]["name"]
        if expected != new_assets[identifier]["configuration"]:
            raise ValueError("Demo must change only the listener policy; other configuration changed")
    example_ids = {listener_id, certificate_id}
    example_ids.update(a["asset_id"] for a in before["assets"]
                       if a["kind"] == "kms_key" and a["configuration"].get("AliasName")
                       in ("alias/licensing-jwt-signing", "alias/s3-object-encryption"))
    return {
        "schema_version": "1.0", "evaluated_at": before["evaluated_at"],
        "label": "Synthetic fixture comparison; no AWS resource was changed",
        "coverage": {"before": before["coverage"], "after": after["coverage"]},
        "changes": changes,
        "certificate_unchanged": True,
        "examples": {
            "assets": [a for a in before["assets"] if a["asset_id"] in example_ids],
            "findings": [f for f in before["findings"] if f["asset_id"] in example_ids],
            "relationships": links,
        },
        "observed_pq_negotiation": None,
        "limitations": ["Classical fallback remains available", "Client ML-KEM support is required",
                        "Certificate authentication remains classical", "No network negotiation was observed"],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evaluated-at", default="2026-10-10T12:00:00Z")
    parser.add_argument("--certificate-renewal", action="store_true", help="Compare the separate synthetic certificate renewal fixture")
    args = parser.parse_args()
    try:
        demo = build_certificate_renewal_demo if args.certificate_renewal else build_demo
        result = demo(evaluated_at=args.evaluated_at)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
