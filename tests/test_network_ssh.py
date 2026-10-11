"""SSH lists are capabilities, including when both peers advertise them."""
from types import SimpleNamespace as NS

from core.assessment import assess_finding
from core.scoring import score_findings
from tests.test_network_handshakes import packet, scan


def test_ssh_kexinit_offers_preserve_parameters_and_directions(monkeypatch):
    ssh = NS(layer_name='ssh', message_code='20',
             kex_algorithms='curve25519-sha256,diffie-hellman-group14-sha1,ext-info-c,kex-strict-c-v00@openssh.com',
             server_host_key_algorithms='ssh-rsa,rsa-sha2-512,ssh-ed25519',
             encryption_algorithms_client_to_server='aes128-cbc,chacha20-poly1305@openssh.com',
             encryption_algorithms_server_to_client='aes256-gcm@openssh.com',
             mac_algorithms_client_to_server='hmac-sha2-256-etm@openssh.com',
             mac_algorithms_server_to_client='future-mac@example.test')
    client = packet(layers=[ssh])
    server = packet(layers=[ssh], frame='2')
    server.ip.src, server.ip.dst = client.ip.dst, client.ip.src
    result = scan(monkeypatch, [client, server])
    assert not result.errors
    assert result.coverage[0].unknown == 1
    assert result.coverage[0].unsupported == 0
    assert len(result.findings) == 10
    assert all(f.evidence_kind == 'offered' and len(f.evidence) == 2 for f in result.findings)
    rsa = [f for f in result.findings if f.algorithm == 'RSA']
    assert {f.parameters.hash_algorithm for f in rsa} == {'SHA-1', 'SHA-512'}
    assert all(f.parameters.key_bits is None for f in rsa)
    dhe = next(f for f in result.findings if f.algorithm == 'DHE')
    assert dhe.parameters.key_bits == 2048
    assert dhe.parameters.named_group is None  # SSH group14 is not TLS ffdhe2048.
    aes = [f for f in result.findings if f.algorithm == 'AES']
    assert {(f.parameters.key_bits, f.parameters.mode) for f in aes} == {(128, 'CBC'), (256, 'GCM')}
    unknown = next(f for f in result.findings if f.algorithm == 'unknown')
    assert 'future-mac@example.test' in unknown.evidence[0].detail
    score = score_findings(assess_finding(f) for f in result.findings)
    assert score['value'] is None
    assert score['offered_only_assets'] == 1


def test_ssh_banner_or_other_message_never_infers_crypto(monkeypatch):
    result = scan(monkeypatch, [packet(layers=[NS(layer_name='ssh',
        message_code='21', kex_algorithms='curve25519-sha256')])])
    assert not result.errors
    assert not result.findings
    assert result.coverage[0].unknown == 1


def test_real_tshark_decodes_synthetic_ssh_and_repeated_tls_offers():
    """Exercise the actual PDML field names and repeated-field representation."""
    import base64
    import shutil
    import struct
    import pytest
    from adapters.network import parse_pcap_adapter
    from tests.test_adapter import TestNetworkAdapter

    if not shutil.which('tshark'):
        pytest.skip('TShark is required for the real capture integration test')

    pcap = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    sequence = {}

    def append(payload, port, reverse=False):
        src, dst = (b'\xc0\x00\x02\x01', b'\xc0\x00\x02\x02')
        sport, dport = 40000 + port, port
        if reverse:
            src, dst, sport, dport = dst, src, dport, sport
        key = port, reverse
        seq = sequence.get(key, 1000)
        sequence[key] = seq + len(payload)
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 0x50, 0x18, 65535, 0, 0)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40 + len(payload), 0, 0, 64, 6, 0, src, dst)
        frame = b'\x00' * 12 + b'\x08\x00' + ip + tcp + payload
        pcap.extend(struct.pack('<IIII', 1700000000, 0, len(frame), len(frame)) + frame)

    def ssh_kex():
        names = [b'curve25519-sha256,diffie-hellman-group14-sha1', b'ssh-rsa,ssh-ed25519',
                 b'aes128-cbc', b'aes256-ctr', b'hmac-sha1', b'hmac-sha2-256',
                 b'none', b'none', b'', b'']
        body = b'\x14' + b'\x00' * 16
        body += b''.join(struct.pack('!I', len(name)) + name for name in names)
        body += b'\x00' * 5
        padding = 8 - ((len(body) + 5) % 8)
        if padding < 4:
            padding += 8
        return struct.pack('!IB', len(body) + 1 + padding, padding) + body + b'\x00' * padding

    for reverse in (False, True):
        append(b'SSH-2.0-SyntheticTest\r\n', 22, reverse)
        append(ssh_kex(), 22, reverse)

    def tls_record(kind, body):
        handshake = bytes([kind]) + len(body).to_bytes(3, 'big') + body
        return b'\x16\x03\x03' + len(handshake).to_bytes(2, 'big') + handshake

    append(tls_record(1, b'\x03\x03' + b'\x01' * 32 + b'\x00\x00\x04\xc0\x2b\xc0\x2f\x01\x00\x00\x00'), 443)
    append(tls_record(2, b'\x03\x03' + b'\x02' * 32 + b'\x00\xc0\x2f\x00\x00\x00'), 443, True)
    helper = TestNetworkAdapter()
    item = helper.get_dummy_input().model_copy(update={'content': base64.b64encode(pcap).decode()})
    result = parse_pcap_adapter(item, helper.get_dummy_context())
    assert not result.errors
    assert (result.coverage[0].assessed, result.coverage[0].unknown, result.coverage[0].unsupported) == (1, 1, 0)
    ssh = [f for f in result.findings if f.evidence[0].detail.startswith('SSH')]
    assert len(ssh) == 8
    assert all(f.evidence_kind == 'offered' and len(f.evidence) == 2 for f in ssh)
    tls = [f for f in result.findings if not f.evidence[0].detail.startswith('SSH')]
    assert len({f.asset_id for f in tls}) == 1
    assert len([f for f in tls if f.evidence_kind == 'offered']) == 6
    assert len([f for f in tls if f.evidence_kind == 'observed']) == 3
