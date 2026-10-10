# QuantumTrace dashboard

From this directory:

```sh
npm ci
npm run dev
```

Vite prints the local URL, normally `http://localhost:5173`. Run `npm test` for
frontend regression checks and `npm run build` for TypeScript and production build
validation. Use Node.js 22+.

The dashboard starts in demo mode with backend-generated fixtures from
`../examples/`. Open **Import data**, select supported files, and click **Scan selected files** to submit
raw inputs to `POST /api/scans`. Related AWS snapshots are bundled together.
Completed, partial, and failed scans show their own findings, coverage, scores,
input errors, and export IDs. **Load demo dataset** in the import dialog restores
the offline demo; migration remains
a labeled synthetic comparison.

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

Frontend tests include mounted React interactions for scanning, errors, reset
races, and exports. They run without a backend. The cross-stack test additionally
requires the repository Python dependencies; run it with
`PYTHON=../.venv/bin/python npm run test:integration` from this directory (or set
`PYTHON` to another installed environment).

API types in `src/types/generated.ts` come from the Python models. From the repo
root, run `.venv/bin/python -m scripts.generate_contract` after changing models or
demo inputs. `src/types/ui.ts` contains presentation-only types.

See the [root README](../README.md) for backend startup, scans and project guides.
