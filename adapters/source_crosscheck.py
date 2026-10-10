"""Optional, metadata-only comparison with an externally produced CryptoScan JSON.

This report never changes findings, assessment, evidence confidence or scores.
Only exact file/line/algorithm matches with one candidate are corroborated.
"""

import json
from pathlib import Path, PurePosixPath
import re

MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_HITS = 20000
_ALGORITHMS = {re.sub(r"[-_/]", "", name).upper(): name for name in (
    "RSA", "RSA-OAEP", "RSA-PSS", "Ed25519", "ECDSA", "ECC", "DH", "DSA",
    "AES", "DES", "3DES", "ChaCha20", "MD5", "SHA-1", "SHA-224", "SHA-256",
    "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256", "SHA3-224",
    "SHA3-256", "SHA3-384", "SHA3-512", "HMAC", "PBKDF2", "ML-KEM", "ML-DSA",
)}


def _algorithm(value: object) -> str:
    if not isinstance(value, str):
        return "unknown"
    return _ALGORITHMS.get(re.sub(r"[-_/]", "", value).upper(), "unknown")


def load_report(path: Path) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("CryptoScan JSON is limited to 8 MiB")
    try:
        report = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid CryptoScan JSON") from None
    if not isinstance(report, dict):
        raise ValueError("Expected a CryptoScan JSON object")
    return report


def cross_reference(scans: list[dict], report: dict, root: Path) -> dict:
    """Compare only files submitted in these scans; never open report paths."""
    tool, hits = report.get("tool"), report.get("findings")
    if (not isinstance(tool, dict) or tool.get("name") != "CryptoScan"
            or not isinstance(tool.get("version"), str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", tool["version"])
            or len(tool["version"]) > 64 or not isinstance(hits, list) or len(hits) > MAX_HITS):
        raise ValueError("Expected CryptoScan tool name/version and at most 20000 findings")
    known_files = {name for scan in scans for name in scan["input_hashes"]}
    candidates: dict[tuple, set[str]] = {}
    for scan in scans:
        for finding in scan["findings"]:
            evidence = finding["evidence"][0]
            location = re.fullmatch(r"line:(\d+):column:(\d+)", evidence["locator"])
            if finding["source_type"] == "source" and location:
                key = (evidence["file"], int(location[1]), _algorithm(finding["algorithm"]))
                candidates.setdefault(key, set()).add(finding["id"])
    matched, unmatched, seen = [], [], set()
    ignored = duplicates = 0
    root = root.absolute()
    for hit in hits:
        if not isinstance(hit, dict):
            raise ValueError("CryptoScan findings must be objects")
        if hit.get("category") in ("Library Import", "Dependency"):
            ignored += 1
            continue
        file, line = hit.get("file"), hit.get("line")
        if not isinstance(file, str) or type(line) is not int or line < 1:
            raise ValueError("CryptoScan findings require a filename and positive integer line")
        path = PurePosixPath(file.replace("\\", "/"))
        if ".." in path.parts:
            ignored += 1
            continue
        if path.is_absolute():
            try:
                path = path.relative_to(root.as_posix())
            except ValueError:
                ignored += 1
                continue
        file = path.as_posix()
        if file not in known_files:
            ignored += 1
            continue
        algorithm = _algorithm(hit.get("algorithm"))
        key = (file, line, algorithm)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        ids = candidates.get(key, set()) if algorithm != "unknown" else set()
        entry = {"file": file, "line": line, "algorithm": algorithm}
        if len(ids) == 1:
            matched.append(dict(entry, finding_id=next(iter(ids))))
        else:
            unmatched.append(dict(entry, reason="ambiguous_occurrence" if ids else "no_exact_match"))
    order = lambda entry: (entry["file"], entry["line"], entry["algorithm"])
    return {
        "tool": {"name": "CryptoScan", "version": tool["version"]},
        "note": "Self-reported scanner version; matching is metadata corroboration, not execution or accuracy proof.",
        "matched": sorted(matched, key=order), "unmatched": sorted(unmatched, key=order),
        "ignored_hits": ignored, "duplicate_hits": duplicates,
    }
