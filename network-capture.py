import argparse
import json
import sys
import base64
from datetime import datetime, timezone

from core.models import ScanInput, AdapterContext
from adapters.network import parse_pcap_adapter

def main():
    parser = argparse.ArgumentParser(description="QuantumTrace Network Capture CLI")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    args = parser.parse_args()

    try:
        with open(args.pcap_file, "rb") as f:
            raw_bytes = f.read()
    except Exception as e:
        print(f"Failed to read file {args.pcap_file}: {e}")
        sys.exit(1)

    scan_input = ScanInput(
        name=args.pcap_file,
        source_type="pcap",
        format="raw",
        content=base64.b64encode(raw_bytes).decode('ascii'),
        encoding="base64"
    )
    context = AdapterContext(evaluated_at=datetime.now(timezone.utc))

    print(f"Analyzing {args.pcap_file} using Network Adapter...\n")

    result = parse_pcap_adapter(scan_input, context)

    print("--- FINDINGS GERADOS (HANDOFF HOUR 3) ---")
    for finding in result.findings:
        print(json.dumps(finding.model_dump(mode="json"), indent=2))
        print("---------------------------------------")
    
    assessed = sum(c.assessed for c in result.coverage)
    unknown = sum(c.unknown for c in result.coverage)
    unsupported = sum(c.unsupported for c in result.coverage)
    failed = sum(c.failed for c in result.coverage)

    print("\n--- METRICS ---")
    print(f"Assessed Sessions:    {assessed}")
    print(f"Unknown Sessions:     {unknown}")
    print(f"Unsupported Sessions: {unsupported}")
    print(f"Failed Sessions:      {failed}")

    if result.errors:
        print("\n--- ERRORS ---")
        for err in result.errors:
            print(json.dumps(err.model_dump(mode="json"), indent=2))
            print("---------------------------------------")

if __name__ == "__main__":
    main()