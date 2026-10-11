# QuantumTrace dashboard

To set up and start both services, run `py start.py` (Windows) or
`python3 start.py` (macOS/Linux) from the repository root. See the
[root setup instructions](../README.md#run-locally).

To start only the dashboard from this directory:

```sh
npm ci
npm run dev
```

Vite prints the local URL, normally `http://localhost:5173`. Run `npm test` for
frontend regression checks and `npm run build` for TypeScript and production build
validation. Use Node.js 22+.

The dashboard starts with an empty inventory. Open **Import data**, select supported files, and click **Scan selected files** to submit
raw inputs to the scan API. Small selections use `POST /api/scans`; folders above
64 MiB use batched uploads for up to 3 GB combined. Related AWS snapshots are
bundled together.
Completed, partial, and failed scans show their own findings, coverage, scores,
input errors, and export IDs. Exports are enabled once a scan result is available.

Start the API with `./scripts/run-local.sh` from the repository root. Scans and
live JSON/CBOM exports share `VITE_API_BASE_URL` (default
`http://127.0.0.1:8000`). For example:

```sh
VITE_API_BASE_URL=http://127.0.0.1:8001 npm run dev
```

Restart Vite after changing the setting and supply it at build time for production
builds. An empty value uses same-origin `/api` routes when served behind a proxy.
The API permits localhost/127.0.0.1 frontend ports 3000 and 5173 by default; other
frontend origins need [CORS configuration](../docs/api.md).

Frontend tests include mounted React interactions for scanning, errors, cancellation
races, and exports. They run without a backend. The cross-stack test additionally
requires the repository Python dependencies; run it with
`PYTHON=../.venv/bin/python npm run test:integration` from this directory (or set
`PYTHON` to another installed environment).

API types in `src/types/generated.ts` come from the Python models. From the repo
root, run `.venv/bin/python -m scripts.generate_contract` after changing models or
demo inputs. `src/types/ui.ts` contains presentation-only types.

See the [root README](../README.md) for backend startup, scans and project guides.
