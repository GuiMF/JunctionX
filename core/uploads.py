"""Bounded temporary storage for uploads too large for one JSON request."""

from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import RLock
from time import monotonic
from uuid import uuid4

from core.models import MAX_SCAN_BYTES, MAX_SCAN_INPUTS, MAX_UPLOAD_BATCH_BYTES, ScanInput, ScanRequest


class UploadError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(message)


@dataclass
class Upload:
    directory: TemporaryDirectory
    entries: list[dict] = field(default_factory=list)
    names: set[str] = field(default_factory=set)
    received_bytes: int = 0
    updated_at: float = field(default_factory=monotonic)

    def inputs(self):
        for index, metadata in enumerate(self.entries):
            # Only server-generated numeric filenames are ever opened.
            content = (Path(self.directory.name) / str(index)).read_bytes().decode("utf-8")
            yield ScanInput(**metadata, content=content)


class UploadStore:
    def __init__(self, *, capacity: int = 2, ttl_seconds: int = 3600):
        self.capacity = capacity
        self.ttl_seconds = ttl_seconds
        self._uploads: dict[str, Upload] = {}
        self._lock = RLock()

    def _expire(self):
        for key, upload in list(self._uploads.items()):
            if monotonic() - upload.updated_at > self.ttl_seconds:
                self._uploads.pop(key).directory.cleanup()

    def create(self) -> str:
        with self._lock:
            self._expire()
            if len(self._uploads) >= self.capacity:
                raise UploadError(429, "Two folder uploads are already pending. Finish or cancel one first.")
            key = str(uuid4())
            self._uploads[key] = Upload(TemporaryDirectory(prefix="quantumtrace-upload-"))
            return key

    def _get(self, key: str) -> Upload:
        self._expire()
        upload = self._uploads.get(key)
        if upload is None:
            raise UploadError(404, "Upload is missing or expired. Select the files and retry.")
        return upload

    def append(self, key: str, request: ScanRequest) -> dict[str, int]:
        with self._lock:
            upload = self._get(key)
            byte_count = sum(len(item.content.encode("utf-8")) for item in request.inputs)
            if byte_count > MAX_UPLOAD_BATCH_BYTES:
                raise UploadError(422, "Upload batches must be at most 64 MiB encoded.")
            if upload.received_bytes + byte_count > MAX_SCAN_BYTES:
                raise UploadError(422, "Combined inputs exceed 3 GB (3,000,000,000 encoded bytes).")
            if len(upload.entries) + len(request.inputs) > MAX_SCAN_INPUTS:
                raise UploadError(422, "Select up to 10,000 inputs per scan.")
            if upload.names.intersection(item.name for item in request.inputs):
                raise UploadError(422, "Input names must be unique across upload batches.")
            if request.evaluated_at is not None or request.label is not None or request.synthetic:
                raise UploadError(422, "Upload batches contain inputs only; scan metadata cannot vary between batches.")
            written = []
            try:
                for index, item in enumerate(request.inputs, start=len(upload.entries)):
                    path = Path(upload.directory.name) / str(index)
                    written.append(path)
                    path.write_bytes(item.content.encode("utf-8"))
            except OSError:
                for path in written:
                    path.unlink(missing_ok=True)
                raise UploadError(507, "Not enough temporary storage for this upload. Free disk space and retry.") from None
            upload.entries.extend(item.model_dump(exclude={"content"}) for item in request.inputs)
            upload.names.update(item.name for item in request.inputs)
            upload.received_bytes += byte_count
            upload.updated_at = monotonic()
            return {"received_bytes": upload.received_bytes, "input_count": len(upload.entries)}

    def take(self, key: str) -> Upload:
        with self._lock:
            upload = self._get(key)
            if not upload.entries:
                raise UploadError(422, "Add at least one input before completing an upload.")
            return self._uploads.pop(key)

    def delete(self, key: str):
        with self._lock:
            upload = self._uploads.pop(key, None)
            if upload:
                upload.directory.cleanup()

    def close(self):
        with self._lock:
            for upload in self._uploads.values():
                upload.directory.cleanup()
            self._uploads.clear()
