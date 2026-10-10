# Local integration API v1

Start with the repository README command. Interactive contract and request examples are available at `http://127.0.0.1:8000/docs`; the OpenAPI contract is `/openapi.json`.

| Endpoint | Result |
| --- | --- |
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

Limits: 1–16 inputs; unique names; at most 8 MiB of encoded content per input and 16 MiB combined. `evaluated_at` is optional and requires a timezone; by default it is the scan start time. Evaluation time is distinct from evidence observation time. A supplied `synthetic` flag and label persist.

## Scanner owner handoff

Raw scanning is **not implemented in this workstream**. Unregistered scanners produce `unsupported_adapter` with one unsupported `inputs` coverage unit. Register each teammate's callable explicitly:

```python
from adapters.registry import AdapterRegistry
from api.main import create_app
from core.models import AdapterContext, AdapterResult, ScanInput
from core.service import ScanService

def source_adapter(item: ScanInput, context: AdapterContext) -> AdapterResult:
    # Scan item.content here, then return validated facts and per-input coverage.
    raise NotImplementedError("Connect the source owner's scanner")

registry = AdapterRegistry()
registry.register("source", source_adapter)
app = create_app(ScanService(registry=registry))
```

Callable output is `AdapterResult`: `findings`, `coverage`, `errors`, `relationships`, and `tool_versions`. Coverage must have at least one entry and identify the same input name/source type. Findings must match the input source type and carry nonempty evidence. Scan and input models reject extra fields. Duplicate registration is rejected to avoid accidentally replacing a scanner.

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
