"""Exercise the packaged API over HTTP, including real TShark and disk uploads.

Only standard-library dependencies are needed on the CI host. All submitted data
is synthetic; this does not test platform payload limits or multi-instance storage.
"""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import struct
import time
from urllib.error import URLError
from urllib.request import Request, urlopen


def synthetic_capture() -> bytes:
    """One Ethernet/IPv4/TCP packet with a TLS 1.2 RSA/AES-128 ServerHello.

    No real traffic or external packet library is needed. Checksums are zero;
    TShark's normal saved-capture dissection does not validate them by default.
    """
    hello = b"\x03\x03" + bytes(range(32)) + b"\x00\x00\x2f\x00\x00\x00"
    handshake = b"\x02" + len(hello).to_bytes(3, "big") + hello
    tls = b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake
    tcp = struct.pack("!HHIIBBHHH", 443, 50000, 1, 1, 0x50, 0x18, 65535, 0, 0) + tls
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])) + tcp
    ethernet = bytes.fromhex("0200000000020200000000010800") + ip
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    return header + struct.pack("<IIII", 1, 0, len(ethernet), len(ethernet)) + ethernet


def request(base: str, path: str, body=None, *, method=None, expected=200, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    req = Request(base + path, data=data, method=method,
                  headers={"Content-Type": "application/json"} if data else {})
    with urlopen(req, timeout=timeout) as response:
        assert response.status == expected, (path, response.status)
        raw = response.read()
        return json.loads(raw) if raw else None


def wait_for_health(base: str) -> None:
    deadline = time.monotonic() + 60
    while True:
        try:
            assert request(base, "/healthz", timeout=2) == {"status": "ok"}
            break
        except (URLError, TimeoutError, ConnectionError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.5)


def smoke(base: str) -> None:
    wait_for_health(base)
    root = Path(__file__).resolve().parents[1]
    cloud = {name: json.loads((root / "cloud-posture" / name).read_text()) for name in (
        "kms_key_inventory.json", "acm_certificates.json", "load_balancer_listeners.json")}
    source = {"name": "smoke.py", "source_type": "source", "format": "raw", "content":
              'import hashlib\nhashlib.sha1(b"synthetic smoke input")\n'}
    inputs = [source,
              {"name": "smoke-cloud.json", "source_type": "cloud", "format": "raw", "content": json.dumps(cloud)},
              {"name": "smoke.pcap", "source_type": "pcap", "format": "raw", "encoding": "base64",
               "content": base64.b64encode(synthetic_capture()).decode()}]
    scan = request(base, "/api/scans", {"inputs": inputs, "synthetic": True}, expected=201)
    assert scan["status"] == "completed", scan["errors"]
    assert scan["errors"] == [], scan["errors"]
    findings = scan["findings"]
    assert {f["source_type"] for f in findings} == {"source", "cloud", "pcap"}
    assert any(f["source_type"] == "source" and f["algorithm"] == "SHA-1" and f["challenge_tier"] == "medium" for f in findings)
    network = [f for f in findings if f["source_type"] == "pcap"]
    assert {(f["algorithm"], f["challenge_tier"]) for f in network} == {("RSA", "critical"), ("AES", "medium")}, network
    assert any(c["source_type"] == "pcap" and c["assessed"] == 1 and c["failed"] == 0 for c in scan["coverage"])
    scan_path = "/api/scans/" + scan["scan_id"]
    assert request(base, scan_path) == scan
    assert request(base, scan_path + "/export?format=json") == scan
    cbom = request(base, scan_path + "/export?format=cyclonedx")
    assert cbom["bomFormat"] == "CycloneDX" and cbom["specVersion"] == "1.6"
    assert len(cbom["components"]) == len(findings)
    print("PASS health, source/cloud/real-PCAP scanning, retrieval and JSON/CycloneDX exports")

    # This ID was never stored; browser exports must survive a different instance.
    client_scan = {**scan, "scan_id": "smoke-without-server-state"}
    assert request(base, "/api/exports?format=json", client_scan) == client_scan
    stateless_cbom = request(base, "/api/exports?format=cyclonedx", client_scan)
    assert stateless_cbom["bomFormat"] == "CycloneDX" and stateless_cbom["specVersion"] == "1.6"
    assert len(stateless_cbom["components"]) == len(findings)
    print("PASS stateless JSON/CycloneDX exports without a stored scan")

    upload = request(base, "/api/uploads", {}, expected=201)["upload_id"]
    upload_path = "/api/uploads/" + upload
    try:
        request(base, upload_path + "/batches", {"inputs": [source]})
        uploaded = request(base, upload_path + "/complete", {}, expected=201)
        assert uploaded["status"] == "completed" and len(uploaded["findings"]) == 1
        assert request(base, "/api/scans/" + uploaded["scan_id"] + "/export?format=json") == uploaded
    finally:
        request(base, upload_path, method="DELETE", expected=204)
    print("PASS temporary upload storage, completion, export and cleanup")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    smoke(args.base_url.rstrip("/"))


if __name__ == "__main__":
    main()
