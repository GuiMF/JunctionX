# Local integration API v1

Start with the repository README command. Interactive contract and request examples are available at `http://127.0.0.1:8000/docs`; the OpenAPI contract is `/openapi.json`.

| Endpoint | Result |
| --- | --- |
| `POST /api/exports?format=json` or `format=cyclonedx` | Convert a submitted `ScanResult` without looking up server memory. |
| `POST /api/scans` | Run synchronously and return the complete `ScanResult` (`201`). |
| `GET /api/scans/{scan_id}` | Fetch a saved result (`200`) or `404` when absent/evicted. |
| `GET /api/scans/{scan_id}/export?format=json` | Download the project JSON. |
| `GET /api/scans/{scan_id}/export?format=cyclonedx` | Download a locally schema-validated CycloneDX 1.6 CBOM. |

`201` means a scan record was created. Inspect its `status`: `completed`, `partial`, or `failed`. An unsupported raw scanner returns a saved failed scan, not an HTTP success claim about scanning. Structurally invalid requests return `422`. Validation errors include the error type, location, and message; submitted input content and validation context are omitted to avoid echoing secrets. Unknown export formats return `422`.

For a separately served local frontend, CORS permits `http://localhost:3000`, `http://127.0.0.1:3000`, `http://localhost:5173`, and `http://127.0.0.1:5173` by default. Allowed request methods are `GET` and `POST`, with `Content-Type` headers and no credentials. To configure other origins, use `create_app(cors_origins=["http://localhost:9000"])`; pass `cors_origins=[]` to disable CORS middleware. Arbitrary origins are not allowed by default. CORS controls browser access, not authentication.

## Request

```json
{
  "inputs": [
    {
      "name": "source-fixture.json",
      "source_type": "source",
      "format": "normalized",
      "encoding": "utf-8",
      "content": "{\"fixture_format\":\"quantumtrace.normalized.v1\",\"result\":{\"findings\":[],\"coverage\":[{\"source_type\":\"source\",\"input_name\":\"source-fixture.json\",\"unit\":\"files\",\"assessed\":1}]}}"
    }
  ],
  "evaluated_at": "2026-10-10T12:00:00Z",
  "label": "Synthetic integration fixture",
  "synthetic": true
}
```

The example checks the full transport with an empty finding inventory; it does not demonstrate a scanner detecting cryptography. Use the repository fixture requests for actual assessment examples.

Inputs are inline content, never local paths or remote URLs. `name` is an identifier used for coverage and hashes; no file is opened by that name. `source_type` is `source`, `pcap`, or `cloud`; `format` is `normalized` or `raw`. For binary captures, use `encoding: "base64"`; scanners can use `adapters.normalized.input_bytes()` to decode. Base64 is validated, not guessed. SHA-256 hashes cover decoded content. Un-decodable input has an error and no hash.

Single-request limits: 1–10,000 inputs; unique names; at most 64 MiB of encoded content per input and 256 MiB combined. `evaluated_at` is optional and requires a timezone; by default it is the scan start time. Evaluation time is distinct from evidence observation time. A supplied `synthetic` flag and label persist.

## Large folder uploads (up to 3 GB)

For folders exceeding one request, upload in batches, then complete one scan:

1. `POST /api/uploads` returns `201` with an `upload_id`.
2. `POST /api/uploads/{upload_id}/batches` takes a `ScanRequest` containing inputs
   only (no custom label, evaluation time or synthetic flag). Each batch allows
   64 MiB of encoded content; each input also allows 64 MiB. The response reports
   cumulative `received_bytes` and `input_count`. Names must be unique across batches.
3. `POST /api/uploads/{upload_id}/complete` reads stored inputs one at a time,
   applies the shared assessment/scoring pipeline and returns one `ScanResult` (`201`).
   Standard GET and JSON/CycloneDX exports use that result's `scan_id`.
4. `DELETE /api/uploads/{upload_id}` discards an incomplete upload (`204`, idempotent).

The total allows **3,000,000,000 encoded content bytes (3 GB)** and 10,000 inputs.
Base64 expansion and AWS bundling count toward this total. Batch/total/count overflow,
duplicate names and empty completion return `422`; missing/expired uploads return
`404`; insufficient temporary disk space returns `507`. Batch writes are atomic.
Related AWS snapshots must stay together in a single input; the dashboard handles
this automatically. Ordinary `/api/scans` JSON requests retain the 256 MiB transport
limit so callers cannot accidentally construct a multi-gigabyte JSON string.

Uploads use server-generated temporary filenames; input names are never opened as
paths. Uploaded content is deleted after completion (including failure), cancellation
or API shutdown. Inactive uploads expire after one hour and are cleaned on the next
upload operation; at most two incomplete uploads are retained (`429` if full).
Completion remains synchronous, with a 30-minute browser timeout. Cancelling during
analysis discards the browser result; server analysis may continue until cleanup.
Results, including findings, remain in memory; the total size allowance is not a
throughput or completion-time guarantee.

## Adapter registration

The default service includes raw Python/Java/Go [source discovery](scanners.md)
and `adapters.cloud.cloud_adapter` for raw cloud snapshots.
The default API additionally registers `adapters.network.parse_pcap_adapter` for
PCAP inputs; direct `ScanService` callers can register it explicitly if needed.
Explicitly supplied registries remain empty until populated. Unregistered scanners
produce `unsupported_adapter` with one unsupported `inputs` coverage unit. Register custom adapters explicitly:

```python
from adapters.registry import AdapterRegistry
from api.main import create_app
from core.models import AdapterContext, AdapterResult, ScanInput
from core.service import ScanService

def source_adapter(item: ScanInput, context: AdapterContext) -> AdapterResult:
    # Scan item.content here, then return validated facts and per-input coverage.
    raise NotImplementedError("Implement the custom source scanner")

registry = AdapterRegistry()
registry.register("source", source_adapter)
app = create_app(ScanService(registry=registry))
```

Callable output is `AdapterResult`: `findings`, `coverage`, `errors`, `relationships`,
`tool_versions`, and optional `assets`/`snapshots`. Coverage and snapshots must
identify their own input name/source type. Findings and inventory assets must
match the input source type and carry nonempty evidence. Scan and input models
reject extra fields. Duplicate registration is rejected to avoid replacing a scanner.

Cloud raw content accepts a single AWS-style snapshot or a JSON object keyed by
`kms_key_inventory.json`, `acm_certificates.json`, and
`load_balancer_listeners.json`, whose values are the snapshot objects. Submit all
three together to resolve certificate links in the same adapter invocation. These
are raw metadata exports, not `quantumtrace.normalized.v1` fixtures. See
[the cloud guide](scanners.md) for a runnable API example.

Every adapter receives an `AdapterContext` containing the scan's timezone-aware `evaluated_at`. Use this value for expiry and other time-dependent posture checks rather than reading the wall clock. The service gives each invocation independent copies of its input and context; mutations cannot change another adapter's evaluation time or the request.

The core validates each input independently, assesses findings using its own rules, and checks identity conflicts before committing that input's results. Parser failures, malformed output and conflicting IDs reject that input while retaining earlier successful results. Existing failed/unsupported counts and errors make the scan partial if there is any successful work. Empty, successfully checked inputs can complete without findings; no findings does not itself mean safety.

Tool versions are namespaced as `input-name/tool-name`, with each segment independently URL-percent-encoded so slashes and percent signs in names cannot silently overwrite another input's provenance. Coverage units stay separate. With no parser output, a failure uses one `inputs` unit instead of inventing a file/session/resource count. Exception messages expose the exception class, not raw parser text which could contain input secrets.

## Normalized fixtures

`normalized` imports require the explicit wrapper below. Plain scanner JSON or arbitrary source text is rejected.

```json
{
  "fixture_format": "quantumtrace.normalized.v1",
  "result": {
    "findings": [],
    "coverage": [
      {"source_type": "source", "input_name": "source-fixture.json", "unit": "files", "assessed": 1}
    ],
    "errors": [],
    "relationships": [],
    "tool_versions": {"fixture-author": "1.0"}
  }
}
```

A scan containing any normalized fixture is always marked `synthetic: true`, even if the caller leaves the flag false. Its default label is `Normalized adapter fixtures`. The importer supplies its version; assessment ignores claimed quantum safety and reassesses the imported facts. Normalized imports prove contract integration, not scanner accuracy.

## Direct Python use and storage

```python
from core.models import ScanRequest
from core.service import run_scan

scan = run_scan(ScanRequest.model_validate(request_dict), registry=registry)
result_for_ui = scan.model_dump(mode="json")
```

For retrieval, reuse one `ScanService` instance. The default `ScanStore` retains the newest 100 scans with thread-safe reads/writes and returns copies. Oldest records are evicted. It is process-local, disappears at restart, and is not shared across multiple Uvicorn workers. Keep one local worker. There is no persistence, job queue, timeout enforcement, authentication, or production deployment configuration in this MVP. Bind to `127.0.0.1` for the local demo. Scanner implementations should bound their own execution time and output size.

Implementation references: [FastAPI response models](https://fastapi.tiangolo.com/tutorial/response-model/) and [FastAPI TestClient testing](https://fastapi.tiangolo.com/tutorial/testing/).
