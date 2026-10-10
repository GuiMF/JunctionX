import os
import tempfile
import pyshark
from datetime import datetime, timezone
import traceback

from shared import (
    ScanInput,
    AdapterContext,
    AdapterResult,
    Finding,
    stable_asset_id,
    stable_finding_id
)

CIPHER_REGISTRY = {
    "0x002f": [
        {"algorithm": "RSA", "usage": "key_establishment"},
        {"algorithm": "AES", "usage": "encryption", "key_bits": 128, "mode": "CBC"}
    ],
    "0x1301": [
        {"algorithm": "AES", "usage": "encryption", "key_bits": 128, "mode": "GCM"}
    ],
    "0x1302": [
        {"algorithm": "AES", "usage": "encryption", "key_bits": 256, "mode": "GCM"}
    ]
}

GROUP_REGISTRY = {
    "4588": {"algorithm": "X25519MLKEM768", "usage": "key_establishment"},
    "29": {"algorithm": "X25519", "usage": "key_establishment"}
}

def parse_pcap_adapter(scan_input: ScanInput, context: AdapterContext) -> AdapterResult:
    result = AdapterResult()
    temp_file_path = None
    file_path = scan_input.path

    if scan_input.inline_content:
        fd, temp_file_path = tempfile.mkstemp(suffix=".pcap")
        with os.fdopen(fd, 'wb') as f:
            f.write(scan_input.inline_content)
        file_path = temp_file_path

    capture_identity = file_path or "inline-capture"

    try:
        capture = pyshark.FileCapture(file_path, keep_packets=False)
    except Exception as e:
        result.errors.append({"error": "Failed to open capture", "details": str(e)})
        return result

    try:
        for packet in capture:
            try:
                # Handle IPv4 / IPv6 explicitly
                ip_src, ip_dst = None, None
                if hasattr(packet, 'ipv6'):
                    ip_src, ip_dst = packet.ipv6.src, packet.ipv6.dst
                elif hasattr(packet, 'ip'):
                    ip_src, ip_dst = packet.ip.src, packet.ip.dst
                
                if not ip_src or not ip_dst:
                    continue  # Not IP traffic, skip safely without swallowing AttributeError
                
                if not hasattr(packet, 'tcp'):
                    continue
                
                tcp_stream = packet.tcp.stream
                
                if 'TLS' in packet and hasattr(packet.tls, 'handshake_type'):
                    handshake_type = packet.tls.handshake_type
                    
                    # 1 = ClientHello, 2 = ServerHello, etc.
                    # We focus on ServerHello for completed selection (not HelloRetryRequest which is usually a variation of ServerHello with a specific random)
                    if handshake_type == "2":
                        selecao = packet.tls.handshake_ciphersuite
                        frame_number = packet.number
                        
                        # Explicit timezone aware timestamp
                        ts = float(packet.sniff_timestamp)
                        dt = datetime.fromtimestamp(ts, timezone.utc)
                        capture_time = dt.isoformat()
                        
                        flow_key = f"tcp-stream-{tcp_stream}-{ip_src}-{ip_dst}"
                        asset_id = stable_asset_id(capture_identity, flow_key)
                        
                        primitives = CIPHER_REGISTRY.get(selecao)
                        if primitives:
                            for prim in primitives:
                                role = f"ciphersuite-{prim['usage']}"
                                finding_id = stable_finding_id(role, selecao, "observed")
                                
                                finding = Finding(
                                    id=finding_id,
                                    asset_id=asset_id,
                                    source_type="pcap",
                                    algorithm=prim["algorithm"],
                                    usage=prim["usage"],
                                    evidence_kind="observed",
                                    evidence=[{
                                        "file": capture_identity,
                                        "locator": f"frame:{frame_number}",
                                        "detail": f"ServerHello selected cipher suite {selecao}"
                                    }],
                                    confidence="high",
                                    observed_at=capture_time,
                                    key_bits=prim.get("key_bits"),
                                    mode=prim.get("mode")
                                )
                                result.findings.append(finding)
                            result.assessed_sessions += 1
                        else:
                            result.unknown_sessions += 1
                        
                        # TLS 1.3 Key Share processing
                        if hasattr(packet.tls, 'handshake_extensions_key_share_group'):
                            group = packet.tls.handshake_extensions_key_share_group
                            group_info = GROUP_REGISTRY.get(group)
                            if group_info:
                                role = "keyshare-key_establishment"
                                finding_id = stable_finding_id(role, group, "observed")
                                
                                finding = Finding(
                                    id=finding_id,
                                    asset_id=asset_id,
                                    source_type="pcap",
                                    algorithm=group_info["algorithm"],
                                    usage=group_info["usage"],
                                    evidence_kind="observed",
                                    evidence=[{
                                        "file": capture_identity,
                                        "locator": f"frame:{frame_number}",
                                        "detail": f"ServerHello selected key share group {group}"
                                    }],
                                    confidence="high",
                                    observed_at=capture_time
                                )
                                result.findings.append(finding)
                    else:
                        # e.g., ClientHello or others. 
                        # Tracking as unsupported for this scope if we don't assess them fully.
                        # (We only emit findings for completed selections for now).
                        if handshake_type == "1":
                            result.unsupported_sessions += 1
                        
            except AttributeError as ae:
                # Capture parse failures cleanly instead of swallowing
                result.failed_sessions += 1
                result.errors.append({
                    "error": "AttributeError in packet parsing",
                    "frame": packet.number if hasattr(packet, 'number') else "unknown",
                    "details": str(ae),
                    "traceback": traceback.format_exc()
                })
            except Exception as e:
                result.failed_sessions += 1
                result.errors.append({
                    "error": "Unexpected error in packet parsing",
                    "frame": packet.number if hasattr(packet, 'number') else "unknown",
                    "details": str(e),
                    "traceback": traceback.format_exc()
                })
    finally:
        # P2: Put capture cleanup in finally so non-AttributeError failures close the TShark subprocess
        try:
            capture.close()
        except:
            pass
            
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except:
                pass

    return result
