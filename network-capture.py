import argparse
import json
from dataclasses import asdict
import sys

from shared import ScanInput, AdapterContext
from adapters.network import parse_pcap_adapter

def main():
    parser = argparse.ArgumentParser(description="QuantumTrace Network Capture CLI")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    args = parser.parse_args()

    # Prepare input for the adapter
    scan_input = ScanInput(path=args.pcap_file)
    context = AdapterContext()

    print(f"Analyzing {args.pcap_file} using Network Adapter...\n")

    # Call the adapter
    result = parse_pcap_adapter(scan_input, context)

    # Print results
    print("--- FINDINGS GERADOS (HANDOFF HOUR 3) ---")
    for finding in result.findings:
        print(json.dumps(asdict(finding), indent=2))
        print("---------------------------------------")
    
    print("\n--- METRICS ---")
    print(f"Assessed Sessions:    {result.assessed_sessions}")
    print(f"Unknown Sessions:     {result.unknown_sessions}")
    print(f"Unsupported Sessions: {result.unsupported_sessions}")
    print(f"Failed Sessions:      {result.failed_sessions}")

    if result.errors:
        print("\n--- ERRORS ---")
        for err in result.errors:
            print(json.dumps(err, indent=2))
            print("---------------------------------------")

if __name__ == "__main__":
    main()