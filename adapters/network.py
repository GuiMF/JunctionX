import os
import tempfile
import pyshark
import hashlib
from datetime import datetime, timezone

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

# RFC 5289: the selected TLS 1.2 suite identifies these algorithm families,
# but does not establish the curve, certificate key size, or signature hash.
for suite, signature, bits in (
    ("0xc02b", "ECDSA", 128), ("0xc02c", "ECDSA", 256),
    ("0xc02f", "RSA", 128), ("0xc030", "RSA", 256),
):
    CIPHER_REGISTRY[suite] = [
        {"algorithm": "ECDHE", "usage": "key_establishment"},
        {"algorithm": signature, "usage": "signature"},
        {"algorithm": "AES", "usage": "encryption", "key_bits": bits, "mode": "GCM"},
    ]


class _TLSFields:
    """TShark nests QUIC TLS fields inside the QUIC layer in PDML output."""

    def __init__(self, layer, prefix=""):
        self.layer = layer
        self.prefix = prefix

    def __getattr__(self, name):
        return getattr(self.layer, self.prefix + name)


def _tls_layers(packet):
    for layer in packet.layers:
        if layer.layer_name == "tls":
            yield _TLSFields(layer)
        elif layer.layer_name == "quic":
            yield _TLSFields(layer, "tls_")

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
    stream_states: dict[str, str] = {}
    
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
            stream_key = None
            try:
                ip_src, ip_dst = None, None
                if hasattr(packet, 'ipv6'):
                    ip_src, ip_dst = packet.ipv6.src, packet.ipv6.dst
                elif hasattr(packet, 'ip'):
                    ip_src, ip_dst = packet.ip.src, packet.ip.dst
                
                if not ip_src or not ip_dst:
                    continue  # Not IP
                
                if hasattr(packet, 'tcp'):
                    stream_key = f"tcp-stream-{int(packet.tcp.stream)}"
                elif hasattr(packet, 'quic') and hasattr(packet, 'udp'):
                    connection = getattr(packet.quic, 'connection_number', None)
                    stream_key = (
                        f"quic-connection-{connection}" if connection is not None
                        else f"quic-udp-stream-{packet.udp.stream}"
                    )
                else:
                    continue
                
                if stream_key not in stream_states:
                    stream_states[stream_key] = "unsupported"
                
                for tls in _tls_layers(packet):
                    if not hasattr(tls, 'handshake_type'):
                        continue
                    handshake_type = tls.handshake_type
                    
                    if handshake_type == "2":
                        # Check HelloRetryRequest
                        random_bytes = ""
                        if hasattr(tls, 'handshake_random'):
                            random_bytes = tls.handshake_random.replace(":", "").lower()
                        
                        if random_bytes == HRR_RANDOM:
                            # It's HRR, mark unsupported/retry and don't emit selected group
                            if stream_states.get(stream_key) not in ("assessed", "failed"):
                                stream_states[stream_key] = "unsupported"
                            continue
                            
                        # Actual ServerHello
                        selecao = tls.handshake_ciphersuite
                        frame_number = packet.number
                        
                        ts = float(packet.sniff_timestamp)
                        dt = datetime.fromtimestamp(ts, timezone.utc)
                        
                        flow_key = f"{stream_key}-{ip_src}-{ip_dst}"
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
                            stream_states[stream_key] = "assessed"
                        else:
                            # If we don't know the cipher, and it hasn't failed/assessed yet
                            if stream_states.get(stream_key) not in ("assessed", "failed"):
                                stream_states[stream_key] = "unknown"
                        
                        if hasattr(tls, 'handshake_extensions_key_share_group'):
                            group = tls.handshake_extensions_key_share_group
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
                                stream_states[stream_key] = "assessed"
                            else:
                                role = "keyshare-key_establishment"
                                finding_id = stable_finding_id(asset_id, "key_establishment", role, "observed")
                                finding = Finding(
                                    id=finding_id,
                                    asset_id=asset_id,
                                    source_type="pcap",
                                    algorithm="unknown",
                                    usage="key_establishment",
                                    evidence_kind="observed",
                                    evidence=[Evidence(
                                        file=scan_input.name,
                                        locator=f"frame:{frame_number}",
                                        detail=f"ServerHello selected unknown key share group {group}"
                                    )],
                                    confidence="high",
                                    observed_at=dt
                                )
                                findings.append(finding)
                                if stream_states.get(stream_key) not in ("assessed", "failed"):
                                    stream_states[stream_key] = "unknown"
                    
                    elif handshake_type == "1": # ClientHello
                        pass
                        
            except AttributeError as ae:
                key = stream_key if stream_key is not None else f"pkt_{id(packet)}"
                stream_states[key] = "failed"
                errors.append(ScanError(
                    source_type="pcap",
                    input_name=scan_input.name,
                    code="attribute_error",
                    message=f"AttributeError at frame {getattr(packet, 'number', 'unknown')}: {ae}"
                ))
            except Exception as e:
                key = stream_key if stream_key is not None else f"pkt_{id(packet)}"
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
