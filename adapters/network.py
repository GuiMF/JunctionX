import os
import tempfile
import pyshark
import hashlib
from datetime import datetime, timezone
import traceback

from core.models import (
    ScanInput,
    AdapterContext,
    AdapterResult,
    Finding,
    Parameters,
    Coverage,
    ScanError,
    Evidence
)
from core.identity import stable_asset_id, stable_finding_id
from adapters.normalized import input_bytes

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

HRR_RANDOM = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"

def parse_pcap_adapter(scan_input: ScanInput, context: AdapterContext) -> AdapterResult:
    findings = []
    errors = []
    coverage = []
    try:
        raw_bytes = input_bytes(scan_input)
    except Exception as e:
        errors.append(ScanError(
            source_type="pcap",
            input_name=scan_input.name,
            code="decode_error",
            message=f"Failed to decode input bytes: {e}"
        ))
        coverage.append(Coverage(
            source_type="pcap",
            input_name=scan_input.name,
            unit="sessions",
            failed=1
        ))
        return AdapterResult(findings=findings, coverage=coverage, errors=errors)

    capture_hash = hashlib.sha256(raw_bytes).hexdigest()
    
    fd, temp_file_path = tempfile.mkstemp(suffix=".pcap")
    with os.fdopen(fd, 'wb') as f:
        f.write(raw_bytes)

    # Disjoint stream state tracking
    # states: "assessed", "unknown", "unsupported", "failed"
    stream_states: dict[int, str] = {}
    
    try:
        capture = pyshark.FileCapture(temp_file_path, keep_packets=False)
    except Exception as e:
        errors.append(ScanError(
            source_type="pcap",
            input_name=scan_input.name,
            code="capture_error",
            message=f"Failed to open capture: {e}"
        ))
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        coverage.append(Coverage(
            source_type="pcap",
            input_name=scan_input.name,
            unit="sessions",
            failed=1
        ))
        return AdapterResult(findings=findings, coverage=coverage, errors=errors)

    try:
        for packet in capture:
            tcp_stream = None
            try:
                ip_src, ip_dst = None, None
                if hasattr(packet, 'ipv6'):
                    ip_src, ip_dst = packet.ipv6.src, packet.ipv6.dst
                elif hasattr(packet, 'ip'):
                    ip_src, ip_dst = packet.ip.src, packet.ip.dst
                
                if not ip_src or not ip_dst:
                    continue  # Not IP
                
                if not hasattr(packet, 'tcp'):
                    continue
                
                tcp_stream = int(packet.tcp.stream)
                
                if 'TLS' in packet and hasattr(packet.tls, 'handshake_type'):
                    handshake_type = packet.tls.handshake_type
                    
                    if handshake_type == "2":
                        # Check HelloRetryRequest
                        random_bytes = ""
                        if hasattr(packet.tls, 'handshake_random'):
                            random_bytes = packet.tls.handshake_random.replace(":", "").lower()
                        
                        if random_bytes == HRR_RANDOM:
                            # It's HRR, mark unsupported/retry and don't emit selected group
                            if stream_states.get(tcp_stream) not in ("assessed", "failed"):
                                stream_states[tcp_stream] = "unsupported"
                            continue
                            
                        # Actual ServerHello
                        selecao = packet.tls.handshake_ciphersuite
                        frame_number = packet.number
                        
                        ts = float(packet.sniff_timestamp)
                        dt = datetime.fromtimestamp(ts, timezone.utc)
                        
                        flow_key = f"tcp-stream-{tcp_stream}-{ip_src}-{ip_dst}"
                        asset_id = stable_asset_id("pcap", f"{capture_hash}|{flow_key}")
                        
                        primitives = CIPHER_REGISTRY.get(selecao)
                        if primitives:
                            for prim in primitives:
                                role = f"ciphersuite-{prim['usage']}"
                                finding_id = stable_finding_id(asset_id, prim['usage'], role, "observed")
                                
                                params = Parameters()
                                if "key_bits" in prim:
                                    params.key_bits = prim["key_bits"]
                                if "mode" in prim:
                                    params.mode = prim["mode"]
                                
                                finding = Finding(
                                    id=finding_id,
                                    asset_id=asset_id,
                                    source_type="pcap",
                                    algorithm=prim["algorithm"],
                                    parameters=params,
                                    usage=prim["usage"],
                                    evidence_kind="observed",
                                    evidence=[Evidence(
                                        file=scan_input.name,
                                        locator=f"frame:{frame_number}",
                                        detail=f"ServerHello selected cipher suite {selecao}"
                                    )],
                                    confidence="high",
                                    observed_at=dt
                                )
                                findings.append(finding)
                            
                            # Successful assessment upgrades stream state
                            stream_states[tcp_stream] = "assessed"
                        else:
                            # If we don't know the cipher, and it hasn't failed/assessed yet
                            if stream_states.get(tcp_stream) not in ("assessed", "failed"):
                                stream_states[tcp_stream] = "unknown"
                        
                        if hasattr(packet.tls, 'handshake_extensions_key_share_group'):
                            group = packet.tls.handshake_extensions_key_share_group
                            group_info = GROUP_REGISTRY.get(group)
                            if group_info:
                                role = "keyshare-key_establishment"
                                finding_id = stable_finding_id(asset_id, group_info["usage"], role, "observed")
                                
                                finding = Finding(
                                    id=finding_id,
                                    asset_id=asset_id,
                                    source_type="pcap",
                                    algorithm=group_info["algorithm"],
                                    usage=group_info["usage"],
                                    evidence_kind="observed",
                                    evidence=[Evidence(
                                        file=scan_input.name,
                                        locator=f"frame:{frame_number}",
                                        detail=f"ServerHello selected key share group {group}"
                                    )],
                                    confidence="high",
                                    observed_at=dt
                                )
                                findings.append(finding)
                                stream_states[tcp_stream] = "assessed"
                            else:
                                if stream_states.get(tcp_stream) not in ("assessed", "failed"):
                                    stream_states[tcp_stream] = "unknown"
                    
                    elif handshake_type == "1": # ClientHello
                        if tcp_stream not in stream_states:
                            stream_states[tcp_stream] = "unsupported"
                        
            except AttributeError as ae:
                key = tcp_stream if tcp_stream is not None else f"pkt_{id(packet)}"
                stream_states[key] = "failed"
                errors.append(ScanError(
                    source_type="pcap",
                    input_name=scan_input.name,
                    code="attribute_error",
                    message=f"AttributeError at frame {getattr(packet, 'number', 'unknown')}: {ae}"
                ))
            except Exception as e:
                key = tcp_stream if tcp_stream is not None else f"pkt_{id(packet)}"
                stream_states[key] = "failed"
                errors.append(ScanError(
                    source_type="pcap",
                    input_name=scan_input.name,
                    code="parse_error",
                    message=f"Error at frame {getattr(packet, 'number', 'unknown')}: {e}"
                ))
    finally:
        try:
            capture.close()
        except:
            pass
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except:
                pass

    # Aggregate session buckets
    assessed = sum(1 for s in stream_states.values() if s == "assessed")
    unknown = sum(1 for s in stream_states.values() if s == "unknown")
    unsupported = sum(1 for s in stream_states.values() if s == "unsupported")
    failed = sum(1 for s in stream_states.values() if s == "failed")
    
    coverage.append(Coverage(
        source_type="pcap",
        input_name=scan_input.name,
        unit="sessions",
        assessed=assessed,
        unknown=unknown,
        unsupported=unsupported,
        failed=failed
    ))
    
    import importlib.metadata
    try:
        pyshark_ver = importlib.metadata.version("pyshark")
    except Exception:
        pyshark_ver = "unknown"
    
    return AdapterResult(
        findings=findings,
        coverage=coverage,
        errors=errors,
        tool_versions={"pyshark": pyshark_ver}
    )
