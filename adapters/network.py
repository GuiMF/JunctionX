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
from adapters.network_ssh import SSH_FIELDS, SSH_SIGNALS

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

# RFC 5288 (RSA/DHE AES-GCM), RFC 7905 (ChaCha20-Poly1305), and
# RFC 8446 Appendix B.4 (TLS 1.3). Suite hashes are PRF/HKDF hashes,
# not evidence of the signature hash, so they are deliberately not propagated.
for suite, exchange, signature, bits in (
    ("0x009c", "RSA", None, 128), ("0x009d", "RSA", None, 256),
    ("0x009e", "DHE", "RSA", 128), ("0x009f", "DHE", "RSA", 256),
):
    CIPHER_REGISTRY[suite] = [
        {"algorithm": exchange, "usage": "key_establishment"},
        *([{"algorithm": signature, "usage": "signature"}] if signature else []),
        {"algorithm": "AES", "usage": "encryption", "key_bits": bits, "mode": "GCM"},
    ]
for suite, exchange, signature in (
    ("0x1303", None, None), ("0xcca8", "ECDHE", "RSA"),
    ("0xcca9", "ECDHE", "ECDSA"), ("0xccaa", "DHE", "RSA"),
):
    CIPHER_REGISTRY[suite] = [
        *([{"algorithm": exchange, "usage": "key_establishment"}] if exchange else []),
        *([{"algorithm": signature, "usage": "signature"}] if signature else []),
        {"algorithm": "ChaCha20-Poly1305", "usage": "encryption", "key_bits": 256},
    ]
for suite, mode in (("0x1304", "CCM"), ("0x1305", "CCM-8")):
    CIPHER_REGISTRY[suite] = [
        {"algorithm": "AES", "usage": "encryption", "key_bits": 128, "mode": mode},
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
# RFC 8446 section 4.2.7 and RFC 7919. These are selected key-exchange
# groups, not certificate curves. Do not infer a certificate or signature.
for number, name in ((23, "secp256r1"), (24, "secp384r1"), (25, "secp521r1")):
    GROUP_REGISTRY[str(number)] = {
        "algorithm": "ECDHE", "usage": "key_establishment", "named_group": name,
    }
GROUP_REGISTRY["30"] = {"algorithm": "X448", "usage": "key_establishment", "named_group": "X448"}
for number, bits in enumerate((2048, 3072, 4096, 6144, 8192), start=256):
    GROUP_REGISTRY[str(number)] = {
        "algorithm": "DHE", "usage": "key_establishment",
        "named_group": f"ffdhe{bits}", "key_bits": bits,
    }


def _field_values(layer, name):
    """Read every PDML occurrence, rather than only PyShark's first value."""
    field = getattr(layer, name, None)
    if field is None:
        return []
    fields = getattr(field, "all_fields", None)
    if isinstance(fields, list):
        return [str(value.get_default_value()) for value in fields]
    return [str(field)]


def _registry_key(value, *, cipher=False):
    try:
        number = int(value, 16 if value.lower().startswith("0x") else 10)
    except ValueError:
        return value
    return f"0x{number:04x}" if cipher else str(number)


def _grease(value):
    """RFC 8701 reserved placeholders advertise no cryptographic capability."""
    try:
        number = int(value, 16 if value.lower().startswith("0x") else 10)
    except ValueError:
        return False
    return number & 0x0f0f == 0x0a0a and number >> 8 == number & 0xff

HRR_RANDOM = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"

def parse_pcap_adapter(scan_input: ScanInput, context: AdapterContext) -> AdapterResult:
    findings = []
    by_id = {}
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
                
                # A capture-local stream identifies both directions, including QUIC
                # migrations. Offers and selections must share the same asset.
                asset_id = stable_asset_id("pcap", f"{capture_hash}|{stream_key}")

                def emit(primitive, role, kind, detail):
                    finding_id = stable_finding_id(asset_id, primitive['usage'], role, kind)
                    evidence = Evidence(file=scan_input.name, locator=f"frame:{packet.number}", detail=detail)
                    if finding_id in by_id:
                        if evidence not in by_id[finding_id].evidence:
                            by_id[finding_id].evidence.append(evidence)
                        return
                    finding = Finding(
                        id=finding_id, asset_id=asset_id, source_type="pcap",
                        algorithm=primitive['algorithm'], usage=primitive['usage'],
                        parameters=Parameters(**{key: primitive[key] for key in
                            ("key_bits", "mode", "named_group", "hash_algorithm") if key in primitive}),
                        evidence_kind=kind, evidence=[evidence], confidence="high",
                        observed_at=datetime.fromtimestamp(float(packet.sniff_timestamp), timezone.utc),
                    )
                    by_id[finding_id] = finding
                    findings.append(finding)

                for ssh in (layer for layer in packet.layers if layer.layer_name == "ssh"):
                    if stream_states[stream_key] == "unsupported":
                        stream_states[stream_key] = "unknown"
                    if "20" not in _field_values(ssh, "message_code"):
                        continue
                    for field, registry, usage in SSH_FIELDS:
                        for values in _field_values(ssh, field):
                            for name in dict.fromkeys(values.split(",")):
                                name = name.strip()
                                if not name or name in SSH_SIGNALS:
                                    continue
                                primitive = registry.get(name, {"algorithm": "unknown", "usage": usage})
                                emit(primitive, f"ssh-{field}-{name}", "offered",
                                     f"SSH KEXINIT from {ip_src} advertises {field}: {name}; selection is unverified")

                for tls in _tls_layers(packet):
                    # Recognized TLS without visible negotiation is incomplete,
                    # rather than an unsupported protocol.
                    if stream_states[stream_key] == "unsupported":
                        stream_states[stream_key] = "unknown"
                    hello_types = [value for value in _field_values(tls, 'handshake_type') if value in {"1", "2"}]
                    # Flattened PDML fields cannot safely associate multiple hellos.
                    if len(hello_types) != 1:
                        continue
                    offered = hello_types[0] == "1"
                    kind = "offered" if offered else "observed"
                    label = "ClientHello offers" if offered else "ServerHello selected"
                    random_bytes = str(getattr(tls, 'handshake_random', '')).replace(":", "").lower()
                    if not offered and random_bytes == HRR_RANDOM:
                        continue  # Retry requests do not prove a completed selection.
                    suites = _field_values(tls, 'handshake_ciphersuite')
                    groups = _field_values(tls, 'handshake_extensions_key_share_group')
                    if not offered and (len(suites) != 1 or len(groups) > 1):
                        continue
                    for value in dict.fromkeys(suites):
                        suite = _registry_key(value, cipher=True)
                        if offered and (_grease(suite) or suite in {"0x00ff", "0x5600"}):
                            continue  # GREASE and SCSV values are not cryptographic offers.
                        primitives = CIPHER_REGISTRY.get(suite)
                        for primitive in primitives or [{"algorithm": "unknown", "usage": "unknown"}]:
                            emit(primitive, f"ciphersuite-{suite}-{primitive['usage']}", kind,
                                 f"{label} {'unknown ' if not primitives else ''}cipher suite {suite}")
                        if primitives and not offered and stream_states[stream_key] != "failed":
                            stream_states[stream_key] = "assessed"
                    group_entries = [(value, "keyshare", "key share group") for value in dict.fromkeys(groups)]
                    if offered:
                        group_entries.extend((value, "supported-group", "supported group") for value in
                            dict.fromkeys(_field_values(tls, 'handshake_extensions_supported_group')))
                    for value, role, description in group_entries:
                        group = _registry_key(value)
                        if offered and _grease(group):
                            continue
                        primitive = GROUP_REGISTRY.get(group)
                        emit(primitive or {"algorithm": "unknown", "usage": "key_establishment"},
                             f"{role}-{group}-key_establishment", kind,
                             f"{label} {'unknown ' if not primitive else ''}{description} {group}")
                        if primitive and not offered and stream_states[stream_key] != "failed":
                            stream_states[stream_key] = "assessed"

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
        tool_versions={"pyshark": pyshark_ver, "quantumtrace-network": "0.2.0"}
    )
