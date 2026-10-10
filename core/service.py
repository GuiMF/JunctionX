"""Adapter isolation, deterministic assessment and bounded local result storage."""

from collections import OrderedDict
from datetime import datetime, timezone
import hashlib
from threading import RLock
from uuid import uuid4
from urllib.parse import quote

from pydantic import ValidationError

from adapters.normalized import import_normalized, input_bytes
from adapters.registry import AdapterRegistry
from core.assessment import RULESET_VERSION, assess_finding
from core.identity import deduplicate_findings
from core.models import AdapterContext, AdapterResult, Coverage, ScanError, ScanInput, ScanRequest, ScanResult
from core.scoring import score_findings


class ScanStore:
    """FIFO bounded, thread-safe, process-local store; returned values are copies."""

    def __init__(self, capacity: int = 100) -> None:
        if capacity < 1:
            raise ValueError("Store capacity must be positive")
        self.capacity = capacity
        self._scans: OrderedDict[str, ScanResult] = OrderedDict()
        self._lock = RLock()

    def put(self, scan: ScanResult) -> None:
        with self._lock:
            self._scans[scan.scan_id] = scan.model_copy(deep=True)
            self._scans.move_to_end(scan.scan_id)
            while len(self._scans) > self.capacity:
                self._scans.popitem(last=False)

    def get(self, scan_id: str) -> ScanResult | None:
        with self._lock:
            scan = self._scans.get(scan_id)
            return scan.model_copy(deep=True) if scan is not None else None


def _validated_result(output: AdapterResult | dict, scan_input: ScanInput) -> AdapterResult:
    # Revalidate even model instances: adapter code can construct or mutate nested values.
    payload = output.model_dump() if isinstance(output, AdapterResult) else output
    result = AdapterResult.model_validate(payload)
    if any(item.source_type != scan_input.source_type for item in result.findings):
        raise ValueError("Findings must match the input source type")
    for item in [*result.coverage, *result.errors]:
        if item.source_type != scan_input.source_type or item.input_name != scan_input.name:
            raise ValueError("Coverage and errors must identify their own input")
    return result


class ScanService:
    def __init__(
        self, registry: AdapterRegistry | None = None, store: ScanStore | None = None
    ) -> None:
        self.registry = registry if registry is not None else AdapterRegistry()
        self.store = store if store is not None else ScanStore()

    def get_scan(self, scan_id: str) -> ScanResult | None:
        return self.store.get(scan_id)

    def run_scan(self, request: ScanRequest) -> ScanResult:
        request = ScanRequest.model_validate(request.model_dump())
        started_at = datetime.now(timezone.utc)
        evaluated_at = request.evaluated_at or started_at
        context = AdapterContext(evaluated_at=evaluated_at)
        findings = []
        coverage = []
        errors = []
        relationships = []
        tool_versions = {"quantumtrace-core": "0.1.0"}
        input_hashes = {}
        successful_input = False
        degraded = False

        def reject(scan_input: ScanInput, code: str, message: str, *, unsupported: bool = False) -> None:
            nonlocal degraded
            degraded = True
            errors.append(ScanError(
                source_type=scan_input.source_type, input_name=scan_input.name,
                code=code, message=message,
            ))
            # No parser result means the only defensible denominator is one input.
            coverage.append(Coverage(
                source_type=scan_input.source_type, input_name=scan_input.name,
                unit="inputs", unsupported=int(unsupported), failed=int(not unsupported),
            ))

        for scan_input in request.inputs:
            try:
                input_hashes[scan_input.name] = hashlib.sha256(input_bytes(scan_input)).hexdigest()
            except (ValueError, UnicodeError):
                reject(scan_input, "invalid_encoding", "Input content is not valid for its declared encoding")
                continue
            adapter = import_normalized if scan_input.format == "normalized" else self.registry.get(scan_input.source_type)
            if adapter is None:
                reject(
                    scan_input, "unsupported_adapter",
                    f"No raw {scan_input.source_type} scanner is registered; this input was not scanned",
                    unsupported=True,
                )
                continue
            try:
                output = adapter(scan_input.model_copy(deep=True), context.model_copy(deep=True))
            except Exception as exc:
                # Do not echo exception text: parsers may include supplied secrets in it.
                code = "invalid_normalized_fixture" if scan_input.format == "normalized" else "adapter_failed"
                reject(scan_input, code, f"Adapter could not process input ({type(exc).__name__})")
                continue
            try:
                result = _validated_result(output, scan_input)
                assessed = [assess_finding(finding) for finding in result.findings]
                # Check the new input atomically; an ID conflict cannot destroy previous inputs.
                combined = deduplicate_findings([*findings, *assessed])
            except (ValidationError, ValueError, TypeError) as exc:
                reject(scan_input, "invalid_adapter_output", f"Adapter output failed contract or identity validation ({type(exc).__name__})")
                continue
            findings = combined
            coverage.extend(result.coverage)
            errors.extend(result.errors)
            relationships.extend(result.relationships)
            for name, version in result.tool_versions.items():
                # Encode each segment independently: otherwise input "a/b"
                # with tool "c" overwrites input "a" with tool "b/c".
                tool_versions[f"{quote(scan_input.name, safe='')}/{quote(name, safe='')}"] = version
            input_degraded = bool(result.errors) or any(item.failed or item.unsupported for item in result.coverage)
            successful_input |= bool(result.findings) or any(item.assessed or item.unknown for item in result.coverage) or not input_degraded
            degraded |= input_degraded

        # Repeated explicit relationships retain all distinct evidence entries.
        relationships = list({item.model_dump_json(): item for item in relationships}.values())
        normalized = any(item.format == "normalized" for item in request.inputs)
        scan = ScanResult(
            scan_id=f"scan-{uuid4()}",
            status="partial" if degraded and successful_input else "failed" if degraded else "completed",
            started_at=started_at, evaluated_at=evaluated_at,
            ruleset_version=RULESET_VERSION, tool_versions=tool_versions,
            input_hashes=input_hashes, findings=findings, coverage=coverage,
            errors=errors, relationships=relationships, score=score_findings(findings),
            synthetic=request.synthetic or normalized,
            label=request.label or ("Normalized adapter fixtures" if normalized else None),
        )
        self.store.put(scan)
        return scan


def run_scan(request: ScanRequest, registry: AdapterRegistry | None = None) -> ScanResult:
    """Convenience entry point for Streamlit and scripts without HTTP or shared state."""
    return ScanService(registry=registry).run_scan(request)
