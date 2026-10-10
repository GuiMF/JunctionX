# QuantumTrace dashboard

From this directory:

```sh
npm ci
npm run dev
```

Vite prints the local URL, normally `http://localhost:5173`. Run `npm test` for
frontend regression checks and `npm run build` for TypeScript and production build
validation. Use Node.js 22+.

The dashboard displays backend-generated fixtures imported from `../examples/`.
File selection is local only; live scan submission is not connected yet. JSON and
CBOM downloads work for the demo without a running API. Live CBOM retrieval uses
`http://127.0.0.1:8000`.

API types in `src/types/generated.ts` come from the Python models. From the repo
root, run `.venv/bin/python -m scripts.generate_contract` after changing models or
demo inputs. `src/types/ui.ts` contains presentation-only types.

See the [root README](../README.md) for backend startup, scans and project guides.
