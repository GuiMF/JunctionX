"""Deterministic CycloneDX 1.6 CBOM export with offline schema validation."""

from __future__ import annotations

from collections import defaultdict
from functools import lru_cache
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import NAMESPACE_URL, uuid5

from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource

from core.assessment import CLASSICAL_GROUPS, HASH_NAMES, HYBRID_GROUPS, KEMS, SIGNATURES

if TYPE_CHECKING:
    from core.models import ScanResult

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas" / "vendor" / "cyclonedx-1.6"
SCHEMA_URI = "http://cyclonedx.org/schema/bom-1.6.schema.json"


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _property(name: str, value: Any) -> dict[str, str]:
    # Strings stay readable. All other values, including null, use JSON encoding.
    return {"name": f"quantumtrace:{name}", "value": value if isinstance(value, str) else _json(value)}


@lru_cache(maxsize=1)
def _validator() -> Draft7Validator:
    registry = Registry()  # No retrieval callback: unregistered references cannot use the network.
    for filename in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
        schema = json.loads((SCHEMA_DIR / filename).read_text(encoding="utf-8"))
        resource = Resource.from_contents(schema)
        registry = registry.with_resource(schema["$id"], resource)
    main = json.loads((SCHEMA_DIR / "bom-1.6.schema.json").read_text(encoding="utf-8"))
    formats = FormatChecker()
    missing = {"date-time", "uri"} - formats.checkers.keys()
    if missing:
        raise RuntimeError("Install pinned format validators; missing: " + ", ".join(sorted(missing)))
    return Draft7Validator(main, registry=registry, format_checker=formats)


def validate_cyclonedx(document: dict) -> None:
    """Validate the full vendored schema and basic reference integrity, offline.

    Schema failures raise jsonschema.ValidationError. Version/reference integrity
    failures raise ValueError; the official schema cannot express these checks.
    """
    _validator().validate(document)
    if document["specVersion"] != "1.6":
        raise ValueError("This exporter requires CycloneDX specVersion 1.6")
    refs: set[str] = set()

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            if "bom-ref" in value:
                ref = value["bom-ref"]
                if ref in refs:
                    raise ValueError(f"Duplicate bom-ref: {ref}")
                refs.add(ref)
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    collect(document)
    for dependency in document.get("dependencies", []):
        for ref in [dependency["ref"], *dependency.get("dependsOn", []), *dependency.get("provides", [])]:
            if ref not in refs:
                raise ValueError(f"Unresolved dependency reference: {ref}")


def _crypto_properties(finding: dict) -> dict:
    # Use the assessment taxonomy, with exact normalized matches rather than
    # family prefixes that could bless fabricated names or obsolete drafts.
    algorithm = re.sub(r"[-_\s]", "", finding.get("algorithm") or "unknown").upper()
    parameters = finding.get("parameters") or {}
    usage = finding.get("usage", "unknown")
    protocol = {"TLS": ("tls", None), "TLS1.2": ("tls", "1.2"),
                "TLS1.3": ("tls", "1.3"), "SSH": ("ssh", None)}.get(algorithm)
    if protocol:
        properties = {"type": protocol[0]}
        if protocol[1]:
            properties["version"] = protocol[1]
        return {"assetType": "protocol", "protocolProperties": properties}

    primitive = "unknown"
    parameter_set = None
    mode = parameters.get("mode")
    mode = re.sub(r"[-_\s]", "", mode).upper() if mode else None
    aes = re.fullmatch(r"AES(?:(128|192|256))?(GCM|ECB|CBC|CTR|CCM)?", algorithm)
    if aes:
        named_bits = int(aes[1]) if aes[1] else None
        supplied_bits = parameters.get("key_bits")
        bits_conflict = named_bits is not None and supplied_bits not in {None, named_bits}
        mode_conflict = bool(aes[2] and mode and mode != aes[2])
        if bits_conflict or mode_conflict:
            # Neither conflicting claim becomes authoritative standard metadata.
            return {"assetType": "algorithm", "algorithmProperties": {"primitive": "unknown"}}
        bits = supplied_bits if supplied_bits is not None else named_bits
        parameter_set = str(bits) if bits in {128, 192, 256} else None
        mode = mode or aes[2]
        primitive = "ae" if mode in {"GCM", "CCM"} else "block-cipher"
    elif algorithm in {"HMAC"} | {"HMAC" + name for name in HASH_NAMES}:
        primitive = "mac"
    elif algorithm in {"PBKDF2", "PBKDF2HMAC", "PBKDF2HMACSHA1", "PBKDF2HMACSHA256", "PBKDF2HMACSHA512"}:
        primitive = "kdf"
    elif algorithm in KEMS:
        primitive = "kem"
        parameter_set = algorithm.removeprefix("MLKEM") or None
    elif algorithm in HYBRID_GROUPS:
        primitive = "combiner"
    elif (algorithm in {"ECDH", "ECDHE", "DH", "DHE", "X25519", "X448"} or
          (algorithm in CLASSICAL_GROUPS and usage == "key_establishment")):
        # A curve name alone (for example P-256) does not establish key
        # agreement: that same curve can also underlie a signature scheme.
        primitive = "key-agree"
    elif algorithm in SIGNATURES | {"ED25519", "ED448", "EDDSA", "ECDSA", "DSA", "RSAPSS"}:
        primitive = "signature"
        if algorithm in {"MLDSA44", "MLDSA65", "MLDSA87"}:
            parameter_set = algorithm.removeprefix("MLDSA")
    elif algorithm in {"RSA", "RSAOAEP", "ECC", "EC"}:
        if algorithm == "RSAOAEP":
            primitive = "pke"
        elif usage == "signature":
            primitive = "signature"
        elif algorithm == "RSA" and usage in {"encryption", "key_establishment"}:
            primitive = "pke"
        elif algorithm in {"ECC", "EC"} and usage == "key_establishment":
            primitive = "key-agree"
    elif algorithm in HASH_NAMES:
        primitive = "hash"

    if algorithm in {"RSA", "RSAPSS", "RSAOAEP"} and parameters.get("key_bits") is not None:
        parameter_set = str(parameters["key_bits"])
    properties: dict[str, Any] = {"primitive": primitive}
    # Parameters are never equated with a classical or quantum security level.
    if parameter_set is not None:
        properties["parameterSetIdentifier"] = parameter_set
    if mode is not None and primitive in {"block-cipher", "ae", "unknown"}:
        # Cipher modes do not describe signatures, hashes, MACs or KEMs.
        # Preserve contradictory scanner metadata in project properties only.
        mode = mode.lower()
        properties["mode"] = mode if mode in {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "unknown"} else "other"
    return {"assetType": "algorithm", "algorithmProperties": properties}


def export_cyclonedx(scan: ScanResult) -> dict:
    """Export facts and assessments without inventing asset links or safety claims.

    Finding IDs identify crypto occurrences. Asset IDs and typed relationships are
    preserved as project properties because the shared model does not declare an
    asset's CycloneDX component type. Only unambiguous explicit dependency edges
    are additionally projected into the standard dependency graph.
    """
    payload = scan.model_dump(mode="json")
    components = []
    asset_refs: dict[str, list[str]] = defaultdict(list)
    for finding in sorted(payload["findings"], key=lambda item: item["id"]):
        ref = f"quantumtrace:finding:{finding['id']}"
        asset_refs[finding["asset_id"]].append(ref)
        component = {
            "type": "cryptographic-asset",
            "bom-ref": ref,
            "name": finding.get("algorithm") or "unknown",
            "cryptoProperties": _crypto_properties(finding),
            "properties": [_property(key, value) for key, value in sorted(finding.items())],
        }
        occurrences = [
            {"location": item["file"], "additionalContext": _json({"locator": item["locator"], "detail": item["detail"], "evidence_kind": finding["evidence_kind"]})}
            for item in finding["evidence"]
        ]
        if occurrences:
            component["evidence"] = {"occurrences": occurrences}
        components.append(component)

    # Omitting a node means dependencies are unknown, not proven absent.
    edges: dict[str, set[str]] = defaultdict(set)
    for relationship in payload.get("relationships", []):
        source = asset_refs.get(relationship["source_asset_id"], [])
        target = asset_refs.get(relationship["target_asset_id"], [])
        if relationship["kind"] == "depends_on" and len(source) == len(target) == 1:
            edges[source[0]].add(target[0])

    metadata = {"properties": [_property(key, value) for key, value in sorted(payload.items()) if key != "findings"]}
    if payload.get("evaluated_at"):
        metadata["timestamp"] = payload["evaluated_at"]
    document = {
        "$schema": SCHEMA_URI,
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }
    if edges:
        document["dependencies"] = [{"ref": ref, "dependsOn": sorted(targets)} for ref, targets in sorted(edges.items())]
    # Hash the actual canonical export, after sorting components and edges.
    # Reordering input findings must not give an otherwise identical BOM a new
    # identity; all original finding fields are retained in its properties.
    document["serialNumber"] = f"urn:uuid:{uuid5(NAMESPACE_URL, 'quantumtrace:' + _json(document))}"
    validate_cyclonedx(document)
    return document
