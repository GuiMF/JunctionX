"""Exercise a running local API and save reviewable artifacts."""

import argparse
from contextlib import ExitStack
import json
from pathlib import Path
from urllib.request import Request, urlopen

from export.cyclonedx import validate_cyclonedx

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--in-process", action="store_true", help="Exercise the HTTP app without opening a socket")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")

    stack = ExitStack()
    client = None
    if args.in_process:
        from fastapi.testclient import TestClient
        from api.main import create_app
        client = stack.enter_context(TestClient(create_app()))

    def call(path, payload=None):
        if client is not None:
            response = client.post(path, json=payload) if payload is not None else client.get(path)
            response.raise_for_status()
            return response.json()
        data = json.dumps(payload).encode() if payload is not None else None
        request = Request(base + path, data=data, headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=30) as response:
            return json.load(response)

    original = call("/api/scans", json.loads((ROOT / "examples/scan-original.request.json").read_text()))
    scan_path = f"/api/scans/{original['scan_id']}"
    assert call(scan_path) == original
    assert call(scan_path + "/export?format=json") == original
    cbom = call(scan_path + "/export?format=cyclonedx")
    validate_cyclonedx(cbom)
    modified = call("/api/scans", json.loads((ROOT / "examples/scan-modified.request.json").read_text()))
    partial = call("/api/scans", json.loads((ROOT / "examples/scan-partial.request.json").read_text()))
    before = {f["id"]: f for f in original["findings"]}
    after = {f["id"]: f for f in modified["findings"]}
    assert before.keys() == after.keys()
    changed = [key for key in before if before[key] != after[key]]
    assert len(changed) == 1 and after[changed[0]]["evidence_kind"] == "configured"
    assert partial["status"] == "partial" and len(partial["findings"]) == len(original["findings"])
    summary = {"transport": "in-process ASGI" if args.in_process else "live HTTP", "synthetic": True, "status": original["status"], "findings": len(original["findings"]),
               "score": original["score"], "cyclonedx_valid": True,
               "modified_configured_findings": len(changed), "partial_scan_status": partial["status"],
               "retained_findings_after_failure": len(partial["findings"])}
    directory = ROOT / "reports"
    directory.mkdir(exist_ok=True)
    for name, data in [("scan.json", original), ("scan.cdx.json", cbom), ("scan-modified.json", modified), ("scan-partial.json", partial), ("demo-summary.json", summary)]:
        (directory / name).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    print(f"Reports saved to {directory}")
    stack.close()


if __name__ == "__main__":
    main()
