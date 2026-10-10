"""Scan a saved capture through the same assessment pipeline as the API."""

import argparse
import base64
import json
from pathlib import Path

from adapters.network import parse_pcap_adapter
from core.models import ScanInput, ScanRequest
from core.service import ScanService


def scan_capture(path: Path):
    service = ScanService()
    service.registry.register("pcap", parse_pcap_adapter)
    return service.run_scan(ScanRequest(inputs=[ScanInput(
        name=path.name, source_type="pcap", format="raw", encoding="base64",
        content=base64.b64encode(path.read_bytes()).decode("ascii"),
    )]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap_file", type=Path)
    args = parser.parse_args()
    try:
        result = scan_capture(args.pcap_file)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result.model_dump(mode="json"), indent=2))
    return int(result.status != "completed")


if __name__ == "__main__":
    raise SystemExit(main())
