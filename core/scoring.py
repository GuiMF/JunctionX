"""Published, asset-weighted heuristic; never a probability or NIST score."""

from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from core.models import Finding

SCORING_VERSION = "1.0.0"
TIER_WEIGHTS = {"critical": 100, "medium": 50, "resilient": 0}


def score_findings(findings: Iterable[Finding]) -> dict[str, Any]:
    assets: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        assets[finding.asset_id].append(finding)
    values: list[int] = []
    unknown_only = offered_only = with_unknowns = vulnerable = hybrid = not_applicable = 0
    classical = posture = 0
    evidence_counts: dict[str, int] = {}
    for group in assets.values():
        for kind in {f.evidence_kind for f in group}:
            evidence_counts[kind] = evidence_counts.get(kind, 0) + 1
        active = [f for f in group if f.evidence_kind != "offered"]
        if not active:
            offered_only += 1
            continue
        known = [TIER_WEIGHTS[f.challenge_tier] for f in active if f.challenge_tier in TIER_WEIGHTS and f.quantum_status not in {"unknown", "not_applicable"}]
        if known:
            values.append(max(known))
        elif all(f.quantum_status == "not_applicable" for f in active):
            not_applicable += 1
        else:
            unknown_only += 1
        if any(f.quantum_status != "not_applicable" and (f.quantum_status == "unknown" or f.challenge_tier == "unknown") for f in active):
            with_unknowns += 1
        vulnerable += any(f.quantum_status == "vulnerable" for f in active)
        hybrid += any(f.quantum_status == "hybrid" for f in active)
        classical += any(f.classical_issues for f in active)
        posture += any(f.posture_issues for f in active)
    return {
        "policy_version": SCORING_VERSION,
        "label": "Project quantum exposure heuristic (0–100; higher means more exposure)",
        "value": round(sum(values) / len(values), 2) if values else None,
        "weights": TIER_WEIGHTS.copy(),
        "denominator": "Unique assessed asset IDs with non-offered, known quantum assessments; worst tier per asset",
        "assessed_assets": len(values),
        "total_assets": len(assets),
        "unknown_assets": unknown_only,
        "assets_with_unknowns": with_unknowns,
        "offered_only_assets": offered_only,
        "not_applicable_assets": not_applicable,
        "quantum_vulnerable_assets": vulnerable,
        "hybrid_assets": hybrid,
        "classical_issue_assets": classical,
        "posture_issue_assets": posture,
        "assets_by_evidence_kind": dict(sorted(evidence_counts.items())),
        "limitations": "Inventory heuristic, not a probability, NIST metric, or application security certification. Unknown and offered-only assets are excluded, never counted as safe. Coverage units remain separate. Business criticality is not inferred.",
    }
