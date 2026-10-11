# Vercel services deployment

Import the repository as **one Vercel project**, with the project root set to the
repository root, not `web/`. The root `vercel.json` declares two services:

| Service | Implementation | Public routes |
| --- | --- | --- |
| `app` | FastAPI in `Dockerfile.vercel`, including TShark | `/api/*`, `/healthz` |
| `web` | Vite/React static dashboard in `web/` | All remaining paths |

Rewrites preserve the path: `/api/scans` reaches FastAPI's `/api/scans` route.
API `/docs`, `/redoc` and `/openapi.json` are not exposed by this route table.
`/healthz` returns `{"status":"ok"}`.

The browser calls same-origin `/api` URLs. **There are no internal bindings**:
the frontend has no server function that calls the backend, and the backend
does not call the frontend. Bindings are runtime-only function values, unavailable
to browser JavaScript or a Vite build. Do not put a binding in a `VITE_*` variable.

Leave `VITE_API_BASE_URL` unset or empty in Vercel. Remove any previous Render or
localhost override before rebuilding. No CORS override is needed for same-origin
requests. The override remains available for standalone local development.

## Local verification

With Docker running and a current Vercel CLI, run from the repository root:

```sh
vercel dev -L --listen 3015
```

`-L` tests without linking a cloud project. Without `-L`, `vercel dev` uses the
linked project's settings. Open `http://localhost:3015`, scan a small synthetic
file and export the result. Check `/healthz` too.

The container runs one Uvicorn worker as an unprivileged user on `PORT`, default
80, matching Vercel's convention. TShark parses saved captures without live capture
privileges. The Docker context contains only backend code, dependencies and schemas.
Standalone `npm run dev` in `web/` proxies `/api` to `http://127.0.0.1:8000`.

## CI deployment checks

The `deployment-smoke` GitHub Actions job builds this same Dockerfile, starts
the image, and checks the health route, source and cloud scanning, a real PCAP
through TShark, uploads, and JSON/CBOM exports over HTTP. The frontend checks
also verify same-origin API routing. These checks catch packaging and local
workflow regressions; the Vercel preview check verifies the cloud build.

## Outstanding hosted-backend constraints

This configuration packages and routes the services; it does not change storage:

- Stored scans and upload sessions belong to one process. Vercel can send later
  requests to a different instance or scale an idle instance down after 30 seconds
  in preview or 5 minutes in production. The dashboard exports via
  `POST /api/exports`, submitting its active result for stateless conversion, so
  those exports survive backend instance changes. GET-by-ID retrieval and
  multi-request uploads still require shared storage.
- The UI allows 64 MiB batches and 3 GB selections, but Vercel documents a 4.5 MB
  function request/response payload limit. Large uploads need direct object
  storage uploads and a revised API. Stateless export requests and generated
  CBOM responses must also stay within the payload limit.
- Synchronous scans face function execution limits. Long scans need durable jobs.
- The API has no authentication or user isolation. Use synthetic data for demos.

Container functions also have these constraints. One worker per container does
not prevent multiple Vercel instances. Local smoke tests do not verify cloud
persistence or large uploads.

References: [Services](https://vercel.com/docs/services),
[bindings](https://vercel.com/docs/services/bindings),
[containers](https://vercel.com/docs/functions/runtimes/container),
[function limits](https://vercel.com/docs/functions/limitations).
