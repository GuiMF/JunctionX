"""Stable identity helpers and conservative deduplication."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from core.models import Finding, SourceType


def _digest(parts: object) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def stable_asset_id(source_type: SourceType, identity: str) -> str:
    """identity must name a resource/occurrence, never its mutable algorithm."""
    if not identity.strip() or source_type not in {"source", "pcap", "cloud"}:
        raise ValueError("A source type and nonempty stable identity are required")
    return "asset-" + _digest([source_type, identity])[:32]


def stable_finding_id(asset_id: str, usage: str, slot: str, evidence_kind: str) -> str:
    """slot is an adapter's stable role, e.g. signing-key or tls-selected-group."""
    if not all(value.strip() for value in (asset_id, usage, slot, evidence_kind)):
        raise ValueError("All finding identity parts must be nonempty")
    return "finding-" + _digest([asset_id, usage, slot, evidence_kind])[:32]


def _facts(finding: Finding) -> tuple:
    # Offered/observed and different source types must remain distinct.
    return (
        finding.asset_id, finding.source_type, finding.algorithm,
        finding.parameters.model_dump_json(), finding.usage, finding.evidence_kind,
    )


def deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Merge repeated IDs only. Unrelated occurrences are never guessed alike.

    Different facts sharing one ID indicate an adapter identity error within a scan.
    The same ID may legitimately change facts across before/after scans.
    """
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        group = groups.setdefault(finding.id, [])
        if group and _facts(group[0]) != _facts(finding):
            raise ValueError(f"Conflicting facts for finding ID {finding.id}")
        if len({f.owner for f in [*group, finding] if f.owner}) > 1:
            raise ValueError(f"Conflicting owners for finding ID {finding.id}")
        group.append(finding)
    result = []
    for finding_id, group in sorted(groups.items()):
        # Sorting ensures reproducibility even when adapters finish in a different order.
        group.sort(key=lambda f: f.model_dump_json())
        merged = group[0].model_copy(deep=True)
        evidence = {e.model_dump_json(): e for f in group for e in f.evidence}
        merged.evidence = [evidence[key].model_copy(deep=True) for key in sorted(evidence)]
        merged.classical_issues = sorted({issue for f in group for issue in f.classical_issues})
        merged.posture_issues = sorted({issue for f in group for issue in f.posture_issues})
        merged.references = sorted({ref for f in group for ref in f.references})
        merged.owner = next((f.owner for f in group if f.owner), None)
        dates = [f.observed_at for f in group if f.observed_at is not None]
        merged.observed_at = max(dates) if dates else None
        # Do not let duplicate sightings manufacture confidence.
        rank = {"low": 0, "medium": 1, "high": 2}
        merged.confidence = min((f.confidence for f in group), key=rank.__getitem__)
        result.append(merged)
    return result
