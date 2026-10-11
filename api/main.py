"""Run locally with: uvicorn api.main:app --host 127.0.0.1 --port 8000."""

from typing import Literal
from contextlib import asynccontextmanager
import os
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.models import ScanRequest, ScanResult
from core.service import ScanService
from core.uploads import UploadError, UploadStore
from export.cyclonedx import export_cyclonedx
from adapters.network import parse_pcap_adapter


def create_app(
    service: ScanService | None = None, *, cors_origins: list[str] | None = None
) -> FastAPI:
    uploads = UploadStore()

    @asynccontextmanager
    async def lifespan(_):
        try:
            yield
        finally:
            uploads.close()

    app = FastAPI(
        lifespan=lifespan,
        title="QuantumTrace local scan API",
        version="1.0.0",
        description=(
            "Synchronous local integration API. Results are held in bounded process memory. "
            "Normalized inputs are labelled synthetic fixtures. Raw Python/Java/Go source, "
            "cloud snapshots and PCAP inputs are supported by the default application."
        ),
    )
    default_origins = [
        "http://localhost:3000", "http://127.0.0.1:3000",
        "http://localhost:5173", "http://127.0.0.1:5173",
    ]
    if cors_origins is not None:
        origins = cors_origins
    elif "CORS_ORIGINS" in os.environ:
        origins = [origin.strip().rstrip("/") for origin in os.environ["CORS_ORIGINS"].split(",") if origin.strip()]
    else:
        origins = default_origins
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["GET", "POST", "DELETE"],
            allow_headers=["Content-Type"],
            allow_credentials=False,
        )
    if service is None:
        service = ScanService()
        service.registry.register("pcap", parse_pcap_adapter)
    app.state.scan_service = service

    @app.get("/healthz", include_in_schema=False)
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default includes the invalid input, which can be an entire
        # scan containing source code, private keys, or cloud credentials.
        # Escape lone surrogates in error paths/messages so malformed JSON text
        # still produces a validation response instead of a serialization 500.
        def safe_text(value: str) -> str:
            return value.encode("utf-8", errors="backslashreplace").decode("utf-8")

        return JSONResponse(status_code=422, content={"detail": [
            {
                "type": safe_text(error["type"]),
                "loc": [safe_text(part) if isinstance(part, str) else part for part in error["loc"]],
                "msg": safe_text(error["msg"]),
            }
            for error in exc.errors()
        ]})

    app.state.upload_store = uploads

    @app.exception_handler(UploadError)
    async def upload_error(_, exc: UploadError) -> JSONResponse:
        return JSONResponse(status_code=exc.status, content={"detail": str(exc)})

    @app.post("/api/uploads", status_code=201)
    def begin_upload() -> dict[str, str]:
        return {"upload_id": uploads.create()}

    @app.post("/api/uploads/{upload_id}/batches")
    def upload_batch(upload_id: str, request: ScanRequest) -> dict[str, int]:
        return uploads.append(upload_id, request)

    @app.delete("/api/uploads/{upload_id}", status_code=204)
    def cancel_upload(upload_id: str):
        uploads.delete(upload_id)

    @app.post("/api/uploads/{upload_id}/complete", response_model=ScanResult, status_code=201)
    def complete_upload(upload_id: str) -> ScanResult:
        upload = uploads.take(upload_id)
        try:
            return app.state.scan_service.run_inputs(upload.inputs())
        finally:
            upload.directory.cleanup()

    @app.post("/api/scans", response_model=ScanResult, status_code=201)
    def create_scan(request: ScanRequest) -> ScanResult:
        return app.state.scan_service.run_scan(request)

    def require_scan(scan_id: str) -> ScanResult:
        scan = app.state.scan_service.get_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found or evicted from local memory")
        return scan

    @app.get("/api/scans/{scan_id}", response_model=ScanResult)
    def get_scan(scan_id: str) -> ScanResult:
        return require_scan(scan_id)

    @app.get("/api/scans/{scan_id}/export")
    def get_export(
        scan_id: str,
        format: Literal["json", "cyclonedx"] = Query(default="json"),
    ) -> JSONResponse:
        return export_response(require_scan(scan_id), format)

    @app.post("/api/exports")
    def export_submitted_scan(
        scan: ScanResult,
        format: Literal["json", "cyclonedx"] = Query(default="json"),
    ) -> JSONResponse:
        """Convert a validated client-held result without process-local storage."""
        # Finding IDs become CycloneDX bom-ref values. Client-held documents
        # need this integrity check before conversion, without reflecting an
        # untrusted ID or masking unrelated exporter failures.
        finding_ids = [finding.id for finding in scan.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise HTTPException(status_code=422, detail="Finding IDs must be unique for export")
        return export_response(scan, format)

    def export_response(scan: ScanResult, format: str) -> JSONResponse:
        document = (
            export_cyclonedx(scan)
            if format == "cyclonedx"
            else scan.model_dump(mode="json")
        )
        suffix = "cdx.json" if format == "cyclonedx" else "json"
        return JSONResponse(
            content=document,
            media_type="application/vnd.cyclonedx+json" if format == "cyclonedx" else "application/json",
            headers={"Content-Disposition": f'attachment; filename="{quote(scan.scan_id, safe="")}.{suffix}"'},
        )

    return app


app = create_app()
