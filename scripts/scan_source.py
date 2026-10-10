"""Scan local files offline: python -m scripts.scan_source PATH --output report.json."""

import argparse
import json
from pathlib import Path

from adapters.source import MAX_SOURCE_BYTES
from core.models import ScanInput, ScanRequest, ScanResult
from core.service import ScanService
from export.cyclonedx import export_cyclonedx

SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache"}


def scan_path(path: Path, *, synthetic: bool = False) -> dict:
    """Return explicit per-batch scans; never invent a combined repository score."""
    path = path.absolute()
    if path.is_symlink():
        raise ValueError("The scan root must not be a symbolic link")
    if not path.exists():
        raise ValueError("The scan root does not exist")
    root = path if path.is_dir() else path.parent
    paths = sorted(path.rglob("*")) if path.is_dir() else [path]
    files = []
    errors = []
    for candidate in paths:
        relative = candidate.relative_to(root)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        if candidate.is_symlink():
            errors.append({"file": relative.as_posix(), "code": "symlink_skipped"})
        elif candidate.is_file() and (not path.is_dir() or candidate.suffix.lower() in {".py", ".java", ".go"}):
            files.append(candidate)
    scans = []
    batch = []
    size = 0
    service = ScanService()

    def flush():
        nonlocal batch, size
        if batch:
            scans.append(service.run_scan(ScanRequest(
                inputs=batch, synthetic=synthetic,
                label="Synthetic source corpus" if synthetic else "Local source scan",
            )).model_dump(mode="json"))
            batch, size = [], 0

    for candidate in files:
        name = candidate.relative_to(root).as_posix()
        try:
            with candidate.open("rb") as stream:
                raw = stream.read(MAX_SOURCE_BYTES + 1)
            if len(raw) > MAX_SOURCE_BYTES:
                errors.append({"file": name, "code": "source_limit_exceeded"})
                continue
            content = raw.decode("utf-8-sig")
        except (OSError, UnicodeError):
            errors.append({"file": name, "code": "unreadable_source"})
            continue
        encoded_size = len(content.encode("utf-8"))
        if len(batch) == 16 or size + encoded_size > 16 * 1024 * 1024:
            flush()
        batch.append(ScanInput(name=name, source_type="source", format="raw", content=content))
        size += encoded_size
    flush()
    return {
        "format": "quantumtrace.source-batches.v1",
        "note": "Scores apply to individual batches; no combined repository score is computed.",
        "files_selected": len(files), "file_errors": errors, "scans": scans,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--synthetic", action="store_true", help="Label supplied examples as synthetic")
    parser.add_argument("--cryptoscan-json", type=Path, help="Compare an existing CryptoScan JSON report without executing CryptoScan")
    parser.add_argument("--cyclonedx-dir", type=Path, help="Write one validated CBOM per batch")
    args = parser.parse_args()
    try:
        result = scan_path(args.path, synthetic=args.synthetic)
        if args.cryptoscan_json:
            from adapters.source_crosscheck import cross_reference, load_report

            root = args.path if args.path.is_dir() else args.path.parent
            result["cryptoscan"] = cross_reference(result["scans"], load_report(args.cryptoscan_json), root)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if args.cyclonedx_dir:
        args.cyclonedx_dir.mkdir(parents=True, exist_ok=True)
        for i, scan in enumerate(result["scans"], 1):
            (args.cyclonedx_dir / f"batch-{i}.cdx.json").write_text(
                json.dumps(export_cyclonedx(ScanResult.model_validate(scan)), indent=2) + "\n"
            )
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    else:
        print(text, end="")
    return int(bool(result["file_errors"]) or not result["scans"] or
               any(scan["status"] != "completed" for scan in result["scans"]))


if __name__ == "__main__":
    raise SystemExit(main())
