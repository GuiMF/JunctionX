"""Explicit adapter registration: importing this module performs no discovery."""

from threading import RLock
from typing import Protocol

from core.models import AdapterContext, AdapterResult, ScanInput


class Adapter(Protocol):
    def __call__(self, scan_input: ScanInput, context: AdapterContext) -> AdapterResult:
        """Parse supplied inline content and return facts, evidence and coverage."""
        ...


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, Adapter] = {}
        self._lock = RLock()

    def register(self, source_type: str, adapter: Adapter) -> None:
        if source_type not in {"source", "pcap", "cloud"}:
            raise ValueError("source_type must be source, pcap or cloud")
        if not callable(adapter):
            raise TypeError("adapter must be callable")
        with self._lock:
            if source_type in self._adapters:
                raise ValueError(f"An adapter is already registered for {source_type}")
            self._adapters[source_type] = adapter

    def get(self, source_type: str) -> Adapter | None:
        with self._lock:
            return self._adapters.get(source_type)
