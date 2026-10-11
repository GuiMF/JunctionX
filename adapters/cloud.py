"""Read the supplied AWS-style snapshots; risk scoring belongs to the core."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re

from adapters.normalized import input_bytes
from core.models import (
    AdapterContext, AdapterResult, Coverage, Finding, InventoryAsset,
    Relationship, ScanError, ScanInput, Snapshot,
)


KMS_REFERENCE = "https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html"
ALB_REFERENCE = "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html"
NLB_REFERENCE = "https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html"
ACM_REFERENCE = "https://docs.aws.amazon.com/acm/latest/APIReference/API_CertificateDetail.html"
MAPPING_VERSION = "cloud-1.2"
INPUTS = (
    ("kms_key_inventory.json", "Keys", "kms_key", "KeyArn"),
    ("acm_certificates.json", "Certificates", "certificate", "CertificateArn"),
    ("load_balancer_listeners.json", "LoadBalancers", "load_balancer", "LoadBalancerArn"),
)


ECDHE_TLS12_CIPHERS = [
    "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES128-SHA256", "ECDHE-RSA-AES128-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES256-SHA384", "ECDHE-RSA-AES256-SHA384",
]
TLS12_CIPHERS = ECDHE_TLS12_CIPHERS + [
    "AES128-GCM-SHA256", "AES128-SHA256", "AES256-GCM-SHA384", "AES256-SHA256",
]
LEGACY_CIPHERS = TLS12_CIPHERS + [
    "ECDHE-ECDSA-AES128-SHA", "ECDHE-RSA-AES128-SHA",
    "ECDHE-ECDSA-AES256-SHA", "ECDHE-RSA-AES256-SHA", "AES128-SHA", "AES256-SHA",
]
FS_CIPHERS = [
    "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384",
]
TLS13_CIPHERS = ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]

# shortcut: only supplied policies and the demo policy, extend from AWS docs for new inputs.
# Cipher lists describe membership, not AWS preference order or observed selections.
POLICIES = {
    "ELBSecurityPolicy-2016-08": (["TLSv1.0", "TLSv1.1", "TLSv1.2"], False, LEGACY_CIPHERS),
    "ELBSecurityPolicy-TLS-1-1-2017-01": (["TLSv1.1", "TLSv1.2"], False, LEGACY_CIPHERS),
    "ELBSecurityPolicy-TLS-1-2-2017-01": (["TLSv1.2"], False, TLS12_CIPHERS),
    "ELBSecurityPolicy-FS-1-2-Res-2020-10": (["TLSv1.2"], False, FS_CIPHERS),
    "ELBSecurityPolicy-TLS13-1-2-2021-06": (["TLSv1.2", "TLSv1.3"], False, TLS13_CIPHERS + ECDHE_TLS12_CIPHERS),
    "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09": (["TLSv1.2", "TLSv1.3"], True, TLS13_CIPHERS + FS_CIPHERS),
}
KMS_KEY_SPECS = {
    "RSA_2048": ("RSA", 2048, None),
    "RSA_3072": ("RSA", 3072, None),
    "RSA_4096": ("RSA", 4096, None),
    "ECC_NIST_P256": ("EC", 256, "secp256r1"),
    "ECC_NIST_P384": ("EC", 384, "secp384r1"),
    "ECC_NIST_P521": ("EC", 521, "secp521r1"),
    "ECC_SECG_P256K1": ("EC", 256, "secp256k1"),
    "ECC_NIST_EDWARDS25519": ("Ed25519", 256, "ed25519"),
    **{f"HMAC_{bits}": ("HMAC", bits, None) for bits in (224, 256, 384, 512)},
    **{f"ML_DSA_{level}": (f"ML-DSA-{level}", None, None) for level in (44, 65, 87)},
    "SM2": ("SM2", 256, None),
}
CERTIFICATE_KEY_SPECS = {
    **{spec: parameters for spec, parameters in KMS_KEY_SPECS.items() if spec.startswith("RSA_")},
    "RSA_1024": ("RSA", 1024, None),
    "EC_prime256v1": ("EC", 256, "secp256r1"),
    "EC_secp384r1": ("EC", 384, "secp384r1"),
    "EC_secp521r1": ("EC", 521, "secp521r1"),
}
CERTIFICATE_SIGNATURES = {
    "SHA1WITHRSA": ("RSA", "SHA1"),
    **{f"SHA{bits}WITHRSA": ("RSA", f"SHA{bits}") for bits in (256, 384, 512)},
    **{f"SHA{bits}WITHECDSA": ("ECDSA", f"SHA{bits}") for bits in (256, 384, 512)},
    **{f"ECDSA_WITH_SHA{bits}": ("ECDSA", f"SHA{bits}") for bits in (256, 384, 512)},
}
NATIVE_RESPONSES = {"KeyMetadata": "kms_key_inventory.json", "Certificate": "acm_certificates.json"}


def _date(value):
    if not isinstance(value, str):
        raise ValueError("Expected an ISO-8601 timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")
    try:
        return result.astimezone(timezone.utc)
    except OverflowError as exc:
        raise ValueError("Timestamp is outside the supported UTC range") from exc


def _resource_date(value):
    # AWS JSON API timestamps are epoch seconds; CLI snapshots use ISO-8601.
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value, timezone.utc)
        except (ValueError, OverflowError, OSError) as exc:
            raise ValueError("Timestamp is outside the supported UTC range") from exc
    return _date(value)


def _symmetric_spec(arn, region):
    """Resolve the documented China exception only with consistent location evidence."""
    parts = arn.split(":", 5)
    partition, arn_region = parts[1], parts[3]
    if parts[2] != "kms" or (region is not None and region != arn_region):
        return "unknown", None, None
    if partition == "aws-cn" and re.fullmatch(r"cn-[a-z]+-\d+", arn_region):
        return "SM4", 128, None
    if partition == "aws-us-gov" and re.fullmatch(r"us-gov-[a-z]+-\d+", arn_region):
        return "AES", 256, "GCM"
    if partition == "aws" and re.fullmatch(r"(?:af|ap|ca|eu|il|me|mx|sa|us)-[a-z]+-\d+", arn_region):
        return "AES", 256, "GCM"
    return "unknown", None, None


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def _invalid_json_constant(value):
    raise ValueError(f"Invalid JSON constant: {value}")


def _json_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"JSON number is outside the supported range: {value}")
    return result


def _evidence(file, locator, value):
    return {"file": str(file), "locator": locator, "detail": json.dumps(value)}


def _validate_record(record, identifier):
    if not isinstance(record, dict):
        raise ValueError("Resource must be an object")
    arn = record.get(identifier)
    if not isinstance(arn, str) or not re.fullmatch(r"arn:(?:aws|aws-cn|aws-us-gov):[^:]+:[^:]+:[^:]+:.+", arn):
        raise ValueError(f"Missing or invalid {identifier}")
    if "Arn" in record and "KeyArn" in record and record["Arn"] != record["KeyArn"]:
        raise ValueError("Conflicting key ARNs")
    if "Listeners" in record and not isinstance(record["Listeners"], list):
        raise ValueError("Listeners must be a list")
    for field in ("Tags", "Certificates", "DefaultActions"):
        if field in record and (
            not isinstance(record[field], list)
            or not all(isinstance(item, dict) for item in record[field])
        ):
            raise ValueError(f"{field} must be a list of objects")
    for field in ("SigningAlgorithms", "EncryptionAlgorithms", "MacAlgorithms", "KeyAgreementAlgorithms", "InUseBy"):
        if field in record and (
            not isinstance(record[field], list)
            or not all(isinstance(item, str) for item in record[field])
        ):
            raise ValueError(f"{field} must be a list of strings")
    for certificate in record.get("Certificates", []):
        if "CertificateArn" in certificate and not isinstance(certificate["CertificateArn"], str):
            raise ValueError("CertificateArn reference must be a string")
    for field in ("KeySpec", "CustomerMasterKeySpec", "KeyUsage", "KeyState", "KeyRotationStatus", "KeyAlgorithm",
                  "SignatureAlgorithm", "Protocol", "SslPolicy", "Type"):
        if field in record and not isinstance(record[field], str):
            raise ValueError(f"{field} must be a string")
    if "SslPolicy" in record and not record["SslPolicy"].strip():
        raise ValueError("SslPolicy must not be blank")
    for field in ("NotBefore", "NotAfter", "ValidTo", "DeletionDate"):
        if field in record:
            _resource_date(record[field])
    if "NotBefore" in record and "NotAfter" in record:
        if _resource_date(record["NotBefore"]) >= _resource_date(record["NotAfter"]):
            raise ValueError("NotBefore must precede NotAfter")
    return arn


def _scan_cloud(contents, evaluation):
    report = {
        "schema_version": "1.0", "mapping_version": MAPPING_VERSION,
        "evaluated_at": evaluation.isoformat(), "assessment_status": "pending_core",
        "assets": [], "findings": [], "relationships": [], "posture_issues": [],
        "snapshots": [], "input_hashes": {}, "coverage": {}, "errors": [],
    }
    assets_by_id = {}

    def error(file, locator, message):
        report["errors"].append({"file": str(file), "locator": locator, "message": message})

    def asset(record, kind, identifier, file, locator, snapshot, parent=None):
        arn = _validate_record(record, identifier)
        if arn in assets_by_id:
            raise ValueError(f"Duplicate resource identifier: {arn}")
        owner = next((tag.get("TagValue") for tag in record.get("Tags", []) if tag.get("TagKey") == "team"), None)
        if owner is not None and not isinstance(owner, str):
            raise ValueError("Team tag value must be a string")
        item = {
            "asset_id": arn, "kind": kind, "parent_id": parent, "owner": owner,
            "snapshot_at": snapshot.get("GeneratedAt"), "account": snapshot.get("Account", arn.split(":")[4]),
            "region": snapshot.get("Region", arn.split(":")[3]), "configuration": record,
            "evidence": [_evidence(file, locator, record)],
        }
        assets_by_id[arn] = item
        report["assets"].append(item)
        if parent:
            report["relationships"].append({
                "source_id": parent, "target_id": arn, "kind": "has_listener", "resolved": True,
                "evidence": [_evidence(file, locator + "/" + identifier, arn)],
            })
        return item

    def issue(item, code, file, locator, value):
        report["posture_issues"].append({
            "asset_id": item["asset_id"], "code": code,
            "evidence": [_evidence(file, locator, value)],
        })

    def finding(item, slot, algorithm, bits, group, usage, file, locator, value, reference, mode=None):
        identity = item["asset_id"] + "|" + slot
        if locator.rsplit("/", 1)[-1] not in item["configuration"]:
            locator = locator.rsplit("/", 1)[0]
            value = item["configuration"]
        report["findings"].append({
            "schema_version": "1.0", "id": hashlib.sha256(identity.encode()).hexdigest(),
            "asset_id": item["asset_id"], "source_type": "cloud", "algorithm": algorithm,
            "parameters": {"key_bits": bits, "mode": mode, "named_group": group},
            "usage": usage, "evidence_kind": "configured", "observed_at": None,
            "owner": item["owner"], "confidence": "high" if algorithm != "unknown" else "low",
            "quantum_status": "unknown", "challenge_tier": "unknown", "classical_issues": [],
            "rule_id": MAPPING_VERSION, "rationale": "Configuration snapshot; runtime use is unverified.",
            "recommendation": None, "references": [reference],
            "evidence": [_evidence(file, locator, value)],
        })

    for filename, collection, kind, identifier in INPUTS:
        if filename not in contents:
            continue
        file, content, prefix = contents[filename]
        coverage = {"unit": "resources", "total": None, "inventoried": 0, "failed": 0, "file_failed": False}
        report["coverage"][kind] = coverage
        try:
            if isinstance(content, OSError):
                raise content
            report["input_hashes"][filename] = hashlib.sha256(content).hexdigest()
            snapshot = json.loads(content, object_pairs_hook=_json_object,
                                  parse_constant=_invalid_json_constant, parse_float=_json_float)
            if isinstance(snapshot, dict):
                shape_keys = [key for key in [*(row[1] for row in INPUTS), *NATIVE_RESPONSES]
                              if key in snapshot]
                if len(shape_keys) != 1:
                    raise ValueError("Ambiguous or unsupported cloud response")
            native = next((key for key, name in NATIVE_RESPONSES.items()
                           if name == filename and isinstance(snapshot, dict) and key in snapshot), None)
            if not isinstance(snapshot, dict) or (native is None and not isinstance(snapshot.get(collection), list)):
                raise ValueError(f"Expected an object with a {collection} list")
            if native and (collection in snapshot or not isinstance(snapshot[native], dict)):
                raise ValueError("Ambiguous or invalid native AWS response")
            for field in ("Account", "Region"):
                if field in snapshot and (not isinstance(snapshot[field], str) or not snapshot[field].strip()):
                    raise ValueError(f"{field} must be a nonempty string")
            if not native or "GeneratedAt" in snapshot:
                generated = _date(snapshot.get("GeneratedAt"))
                report["snapshots"].append({
                    "file": str(file), "locator": prefix + "/GeneratedAt", "generated_at": generated.isoformat(),
                    "age_seconds": (evaluation - generated).total_seconds(),
                })
        except (OSError, ValueError) as exc:
            coverage["file_failed"] = True
            error(file, prefix, str(exc))
            continue
        records = [snapshot[native]] if native else snapshot[collection]
        coverage["total"] = len(records)
        for index, record in enumerate(records):
            pointer = prefix + (f"/{native}" if native else f"/{collection}/{index}")
            resource_identifier = "Arn" if native == "KeyMetadata" else identifier
            try:
                item = asset(record, kind, resource_identifier, file, pointer, snapshot)
            except ValueError as exc:
                coverage["failed"] += 1
                error(file, pointer, str(exc))
                continue
            coverage["inventoried"] += 1
            if kind == "kms_key":
                usage = {"SIGN_VERIFY": "signature", "ENCRYPT_DECRYPT": "encryption",
                         "GENERATE_VERIFY_MAC": "mac", "KEY_AGREEMENT": "key_establishment"}.get(record.get("KeyUsage"), "unknown")
                spec_field = "KeySpec" if "KeySpec" in record else "CustomerMasterKeySpec"
                spec = record.get(spec_field)
                algorithm, bits, group = KMS_KEY_SPECS.get(spec, ("unknown", None, None))
                mode = None
                if spec == "SYMMETRIC_DEFAULT":
                    algorithm, bits, mode = _symmetric_spec(item["asset_id"], snapshot.get("Region"))
                if algorithm == "EC" and usage == "signature":
                    algorithm = "ECDSA"
                elif algorithm == "EC" and usage == "key_establishment":
                    algorithm = "ECDH"
                if "KeySpec" in record and "CustomerMasterKeySpec" in record and record["KeySpec"] != record["CustomerMasterKeySpec"]:
                    algorithm, bits, group, mode = "unknown", None, None, None
                finding(item, "key", algorithm, bits, group, usage, file, pointer + "/" + spec_field, spec, KMS_REFERENCE, mode)
                if algorithm == "HMAC":
                    report["findings"][-1]["parameters"]["hash_algorithm"] = f"SHA{bits}"
                if "KeySpec" in record and "CustomerMasterKeySpec" in record:
                    report["findings"][-1]["evidence"].append(_evidence(file, pointer + "/CustomerMasterKeySpec", record["CustomerMasterKeySpec"]))
                if "KeyUsage" in record:
                    report["findings"][-1]["evidence"].append(_evidence(file, pointer + "/KeyUsage", record["KeyUsage"]))
                if spec == "SYMMETRIC_DEFAULT" and "Region" in snapshot:
                    report["findings"][-1]["evidence"].append(_evidence(file, prefix + "/Region", snapshot["Region"]))
                if spec == "SYMMETRIC_DEFAULT":
                    report["findings"][-1]["evidence"].append(_evidence(file, pointer + "/" + resource_identifier, item["asset_id"]))
                for field, value, code in (
                    ("KeyRotationStatus", "DISABLED", "rotation_disabled"),
                    ("KeyState", "PendingDeletion", "pending_deletion"),
                ):
                    if record.get(field) == value:
                        issue(item, code, file, pointer + "/" + field, value)
                if "ValidTo" in record and _resource_date(record["ValidTo"]) <= evaluation:
                    issue(item, "key_material_expired", file, pointer + "/ValidTo", record["ValidTo"])
            elif kind == "certificate":
                algorithm, bits, group = CERTIFICATE_KEY_SPECS.get(record.get("KeyAlgorithm"), ("unknown", None, None))
                finding(item, "public_key", algorithm, bits, group, "unknown", file, pointer + "/KeyAlgorithm", record.get("KeyAlgorithm"), ACM_REFERENCE)
                signature = record.get("SignatureAlgorithm")
                signature_algorithm, digest = CERTIFICATE_SIGNATURES.get(signature, ("unknown", None))
                finding(item, "issuer_signature", signature_algorithm, None, None, "signature", file, pointer + "/SignatureAlgorithm", signature, ACM_REFERENCE)
                report["findings"][-1]["parameters"]["hash_algorithm"] = digest
                if signature == "SHA1WITHRSA":
                    issue(item, "sha1_certificate_signature", file, pointer + "/SignatureAlgorithm", signature)
                if "NotAfter" in record and _resource_date(record["NotAfter"]) <= evaluation:
                    issue(item, "certificate_expired", file, pointer + "/NotAfter", record["NotAfter"])
                if "NotBefore" in record and _resource_date(record["NotBefore"]) > evaluation:
                    issue(item, "certificate_not_yet_valid", file, pointer + "/NotBefore", record["NotBefore"])
            else:
                listener_coverage = report["coverage"].setdefault("listener", {"unit": "resources", "total": 0, "inventoried": 0, "failed": 0, "file_failed": False})
                for listener_index, listener in enumerate(record.get("Listeners", [])):
                    locator = pointer + f"/Listeners/{listener_index}"
                    listener_coverage["total"] += 1
                    try:
                        child = asset(listener, "listener", "ListenerArn", file, locator, snapshot, item["asset_id"])
                    except ValueError as exc:
                        listener_coverage["failed"] += 1
                        error(file, locator, str(exc))
                        continue
                    listener_coverage["inventoried"] += 1
                    if listener.get("Protocol") in ("HTTPS", "TLS"):
                        name = listener.get("SslPolicy")
                        reference = NLB_REFERENCE if record.get("Type") == "network" else ALB_REFERENCE
                        policy = POLICIES.get(name) if record.get("Type") in ("application", "network") else None
                        child["tls_policy"] = {
                            "name": name, "protocols": list(policy[0]) if policy else None,
                            "hybrid_pq_capable": policy[1] if policy else None,
                            "cipher_suites": list(policy[2]) if policy else None,
                            "hybrid_groups": ["SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768"] if policy and policy[1] else ([] if policy else None),
                            "negotiated_group": None, "reference": reference, "mapping_version": MAPPING_VERSION,
                        }
                        # Policy capabilities do not identify the negotiated algorithm.
                        finding(child, "key_establishment", "unknown", None, None, "key_establishment", file, locator + "/SslPolicy", name, reference)
                        if policy and any(protocol in policy[0] for protocol in ("TLSv1.0", "TLSv1.1")):
                            issue(child, "legacy_tls_enabled", file, locator + "/SslPolicy", name)
                    elif listener.get("Protocol") == "HTTP":
                        child["http_actions"] = []
                        for action_index, action in enumerate(listener.get("DefaultActions", [])):
                            redirect = action.get("RedirectConfig")
                            child["http_actions"].append({
                                "type": action.get("Type"),
                                "redirect_protocol": redirect.get("Protocol") if isinstance(redirect, dict) else None,
                                "evidence": [_evidence(file, locator + f"/DefaultActions/{action_index}", action)],
                            })
                            if action.get("Type") == "forward":
                                issue(child, "http_forwarding", file, locator + f"/DefaultActions/{action_index}", action)
                    for ref_index, ref in enumerate(listener.get("Certificates", [])):
                        target = ref.get("CertificateArn")
                        ref_locator = locator + f"/Certificates/{ref_index}"
                        evidence = _evidence(file, ref_locator + "/CertificateArn", target) if "CertificateArn" in ref else _evidence(file, ref_locator, ref)
                        certificate = assets_by_id.get(target) if isinstance(target, str) else None
                        resolved = certificate is not None and certificate["kind"] == "certificate"
                        report["relationships"].append({
                            "source_id": child["asset_id"], "target_id": target, "kind": "uses_certificate", "resolved": resolved,
                            "evidence": [evidence],
                        })
                        if not resolved:
                            error(file, evidence["locator"], "Unresolved certificate reference")
    report["coverage"]["cryptography"] = {
        "unit": "findings", "total": len(report["findings"]), "assessed": 0,
        "normalized": sum(f["algorithm"] != "unknown" for f in report["findings"]),
        "unknown_algorithm": sum(f["algorithm"] == "unknown" for f in report["findings"]),
    }
    policies = [item["tls_policy"] for item in report["assets"] if "tls_policy" in item]
    report["coverage"]["tls_policies"] = {
        "unit": "listeners", "total": len(policies),
        "mapped": sum(p["protocols"] is not None for p in policies),
        "unknown": sum(p["protocols"] is None for p in policies),
    }
    return report


def cloud_adapter(scan_input: ScanInput, context: AdapterContext) -> AdapterResult:
    content = input_bytes(scan_input)
    try:
        value = json.loads(content, object_pairs_hook=_json_object,
                           parse_constant=_invalid_json_constant, parse_float=_json_float)
        if not isinstance(value, dict):
            raise ValueError("Cloud input must be an object")
        collections = [filename for filename, collection, *_ in INPUTS if collection in value]
        collections.extend(filename for key, filename in NATIVE_RESPONSES.items() if key in value)
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
                              code="invalid_cloud_input", message="Expected a cloud snapshot, AWS DescribeKey/DescribeCertificate response, or filename-keyed snapshot bundle")],
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


def scan_cloud(directory="cloud-posture", *, evaluated_at=None):
    """Read local snapshots for the standalone CLI; raw API scanning never opens paths."""
    directory = Path(directory)
    evaluation = _date(evaluated_at) if evaluated_at is not None else datetime.now(timezone.utc)
    contents = {}
    for filename, *_ in INPUTS:
        file = directory / filename
        try:
            content = file.read_bytes()
        except OSError as exc:
            content = exc
        contents[filename] = (file, content, "")
    return _scan_cloud(contents, evaluation)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", default="cloud-posture")
    parser.add_argument("--evaluated-at", help="ISO-8601 timestamp with timezone")
    args = parser.parse_args()
    try:
        result = scan_cloud(args.directory, evaluated_at=args.evaluated_at)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    raise SystemExit(1 if result["errors"] else 0)
