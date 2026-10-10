"""Offline bounded source discovery; input names are evidence, never paths."""

from pathlib import PurePosixPath

from adapters.normalized import input_bytes
from adapters.source_common import RULESET_VERSION, SCANNER_VERSION, SourceParseError
from core.identity import stable_asset_id, stable_finding_id
from core.models import AdapterContext, AdapterResult, Coverage, Evidence, Finding, ScanError, ScanInput

MAX_SOURCE_BYTES = 1024 * 1024
MAX_FINDINGS = 5000


def scan_source(item: ScanInput, context: AdapterContext) -> AdapterResult:
    """Scan a single named .py/.java/.go file without importing or executing it."""
    from adapters.source_python import detect
    from adapters.source_jvm_go import detect_go, detect_java

    versions = {"quantumtrace-source": SCANNER_VERSION, "source-rules": RULESET_VERSION}

    def failure(code: str, message: str, *, unsupported: bool = False) -> AdapterResult:
        return AdapterResult(
            coverage=[Coverage(source_type="source", input_name=item.name, unit="files",
                               unsupported=int(unsupported), failed=int(not unsupported))],
            errors=[ScanError(source_type="source", input_name=item.name, code=code, message=message)],
            tool_versions=versions,
        )

    if item.source_type != "source" or item.format != "raw":
        return failure("invalid_source_input", "Source discovery requires a raw source input")
    parser = {".py": detect, ".java": detect_java, ".go": detect_go}.get(
        PurePosixPath(item.name.replace("\\", "/")).suffix.lower()
    )
    if parser is None:
        return failure("unsupported_language", "Supported file extensions: .py, .java, .go", unsupported=True)
    try:
        raw = input_bytes(item)
        if len(raw) > MAX_SOURCE_BYTES:
            return failure("source_limit_exceeded", "Source files are limited to 1 MiB each")
        source = raw.decode("utf-8-sig")
    except (UnicodeError, ValueError):
        return failure("invalid_source_encoding", "Source content must decode as UTF-8")
    try:
        detections = parser(source)
    except (SourceParseError, SyntaxError, RecursionError, ValueError):
        return failure("source_parse_error", "Source could not be processed by the bounded language parser")
    if len(detections) > MAX_FINDINGS:
        return failure("source_limit_exceeded", "Source files are limited to 5000 detected occurrences")
    findings = []
    for detection in detections:
        identity = f"{item.name}:line:{detection.line}:column:{detection.column}:{detection.slot}"
        asset_id = stable_asset_id("source", identity)
        findings.append(Finding(
            id=stable_finding_id(asset_id, detection.usage, detection.slot, "declared"),
            asset_id=asset_id, source_type="source", algorithm=detection.algorithm,
            parameters=detection.parameters, usage=detection.usage, evidence_kind="declared",
            evidence=[Evidence(
                file=item.name, locator=f"line:{detection.line}:column:{detection.column}",
                detail=(f"API {detection.api}; detector quantumtrace-source/{SCANNER_VERSION}; "
                        f"rule {RULESET_VERSION}/{detection.rule}; source declaration only; "
                        "runtime execution unverified"),
            )], confidence=detection.confidence,
        ))
    return AdapterResult(
        findings=findings,
        coverage=[Coverage(source_type="source", input_name=item.name, unit="files", assessed=1)],
        tool_versions=versions,
    )
