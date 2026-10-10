#!/usr/bin/env python3
"""Evaluate manual labels against source discovery; never execute corpus files."""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
FIXTURES = ROOT / "tests" / "fixtures" / "source"


def occurrence_key(item: dict[str, Any]) -> tuple:
    return item["file"], item["line"], item["algorithm"], item["usage"]


def parameter_match(expected: dict, actual: dict) -> bool:
    return all(actual.get("parameters", {}).get(k) == v
               for k, v in expected.get("parameters", {}).items())


def score_occurrences(expected: list[dict], actual: list[dict]) -> dict:
    """Multiset detection scoring, with separate subset-parameter scoring.

    Repeated identical keys are matched at most once each. Within a key, maximize
    complete parameter matches using a bipartite matching before pairing the rest.
    This keeps ordering from changing the parameter score for duplicates.
    """
    expected_groups, actual_groups = defaultdict(list), defaultdict(list)
    for item in expected:
        expected_groups[occurrence_key(item)].append(item)
    for item in actual:
        actual_groups[occurrence_key(item)].append(item)
    pairs, missed, extra = [], [], []
    for key in sorted(expected_groups.keys() | actual_groups.keys()):
        left, right = expected_groups[key], actual_groups[key]
        assigned: dict[int, int] = {}

        def augment(i: int, seen: set[int]) -> bool:
            for j, observation in enumerate(right):
                if j in seen or not parameter_match(left[i], observation):
                    continue
                seen.add(j)
                if j not in assigned or augment(assigned[j], seen):
                    assigned[j] = i
                    return True
            return False

        # Constrained labels first; matching still uses augmenting paths.
        for i in sorted(range(len(left)), key=lambda n: -len(left[n].get("parameters", {}))):
            augment(i, set())
        used_left = set(assigned.values())
        used_right = set(assigned)
        pairs.extend((left[i], right[j]) for j, i in assigned.items())
        remaining_left = [x for i, x in enumerate(left) if i not in used_left]
        remaining_right = [x for j, x in enumerate(right) if j not in used_right]
        common = min(len(remaining_left), len(remaining_right))
        pairs.extend(zip(remaining_left[:common], remaining_right[:common]))
        missed.extend(remaining_left[common:])
        extra.extend(remaining_right[common:])
    tp, fp, fn = len(pairs), len(extra), len(missed)
    labelled_pairs = [(e, a) for e, a in pairs if e.get("parameters")]
    checked_fields = sum(len(e["parameters"]) for e, _ in labelled_pairs)
    correct_fields = sum(a.get("parameters", {}).get(k) == v
                         for e, a in labelled_pairs for k, v in e["parameters"].items())
    mismatches = [{"expected": e, "actual_parameters": a.get("parameters", {})}
                  for e, a in labelled_pairs if not parameter_match(e, a)]
    gaps = [x for x in expected if x.get("known_gap")]
    supported = [x for x in expected if not x.get("known_gap")]
    supported_tp = sum(not e.get("known_gap") for e, _ in pairs)
    return {
        "detection": {"true_positive": tp, "false_positive": fp, "false_negative": fn,
                      "expected_occurrences": len(expected), "actual_occurrences": len(actual),
                      "precision": tp / (tp + fp) if tp + fp else None,
                      "recall": tp / (tp + fn) if tp + fn else None},
        "supported_subset": {"true_positive": supported_tp, "expected_occurrences": len(supported),
                             "recall": supported_tp / len(supported) if supported else None},
        "parameters": {"annotated_expected_occurrences": sum(bool(e.get("parameters")) for e in expected),
                       "matched_annotated_occurrences": len(labelled_pairs),
                       "correct_occurrences": len(labelled_pairs) - len(mismatches),
                       "checked_fields": checked_fields, "correct_fields": correct_fields,
                       "field_accuracy": correct_fields / checked_fields if checked_fields else None,
                       "mismatches": mismatches},
        "known_gaps": gaps, "false_negatives": missed, "false_positives": extra,
    }


def evaluate_corpus(root: Path, manifest_path: Path) -> dict:
    from adapters.source import scan_source
    from core.models import AdapterContext, ScanInput

    manifest = json.loads(manifest_path.read_text())
    if manifest["schema_version"] != 1:
        raise ValueError("Unsupported label manifest version")
    expected, actual, errors = [], [], []
    versions: dict[str, str] = {}
    assessed_files = 0
    seen_paths = set()
    for entry in manifest["files"]:
        relative = Path(entry["path"])
        if relative.is_absolute() or ".." in relative.parts or entry["path"] in seen_paths:
            raise ValueError("Manifest contains an unsafe or duplicate file path")
        seen_paths.add(entry["path"])
        raw = (root / relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise ValueError(f"Corpus content hash mismatch: {entry['path']}")
        expected.extend(dict(label, file=entry["path"]) for label in entry["expected"])
        result = scan_source(ScanInput(name=entry["path"], source_type="source", format="raw",
                                       content=raw.decode("utf-8")),
                             AdapterContext(evaluated_at=datetime(2026, 1, 1, tzinfo=timezone.utc)))
        assessed_files += sum(c.assessed for c in result.coverage)
        errors.extend(e.model_dump() for e in result.errors)
        versions.update(result.tool_versions)
        for finding in result.findings:
            evidence = finding.evidence[0]
            match = re.fullmatch(r"line:(\d+):column:(\d+)", evidence.locator)
            if match is None:
                raise ValueError("Source evidence has no exact line/column locator")
            actual.append(dict(file=evidence.file, line=int(match[1]),
                               algorithm=finding.algorithm, usage=finding.usage,
                               parameters=finding.parameters.model_dump()))
    return {"corpus": manifest["corpus"], "pinned_commit": manifest.get("commit"),
            "files": len(manifest["files"]), "assessed_files": assessed_files,
            "tool_versions": versions, "scan_errors": errors, **score_occurrences(expected, actual)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--organizer-root", type=Path,
                        help="Optional organizer sample-repos directory at the pinned commit")
    args = parser.parse_args(argv)
    try:
        reports = [evaluate_corpus(FIXTURES / "holdout", FIXTURES / "holdout-labels.json")]
        if args.organizer_root:
            reports.append(evaluate_corpus(args.organizer_root, FIXTURES / "organizer-labels.json"))
    except (OSError, ValueError) as error:
        parser.exit(2, f"Evaluation failed: {error}\n")
    print(json.dumps({"reports": reports}, indent=2))
    # Known gaps are reported as misses, not a process failure; corpus errors fail.
    return int(any(report["scan_errors"] for report in reports))


if __name__ == "__main__":
    raise SystemExit(main())
