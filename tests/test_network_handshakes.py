"""Selected TLS algorithms must survive transport and layer-layout differences."""
from types import SimpleNamespace as NS
from unittest.mock import MagicMock

import pytest

from adapters.network import HRR_RANDOM, parse_pcap_adapter
from tests.test_adapter import TestNetworkAdapter as _InputFactory


def layer(transport='tcp', suite='0xc02b', kind='2', group=None, random='00'):
    prefix = 'tls_' if transport == 'quic' else ''
    fields = {'handshake_type': kind, 'handshake_ciphersuite': suite,
              'handshake_random': random}
    if group is not None:
        fields['handshake_extensions_key_share_group'] = group
    return NS(layer_name='quic' if transport == 'quic' else 'tls',
              **{prefix + key: value for key, value in fields.items()})


def packet(transport='tcp', stream='1', layers=None, frame='1'):
    layers = layers if layers is not None else [layer(transport)]
    p = NS(ip=NS(src='192.0.2.1', dst='192.0.2.2'), layers=layers,
           number=frame, sniff_timestamp='1672531200.0')
    if transport == 'tcp':
        p.tcp = NS(stream=stream)
    else:
        p.udp = NS(stream=stream)
        if transport == 'quic':
            p.quic = NS(connection_number=stream)
    return p


def scan(monkeypatch, packets):
    capture = MagicMock()
    capture.__iter__.return_value = packets
    monkeypatch.setattr('adapters.network.pyshark.FileCapture', lambda *a, **kw: capture)
    helper = _InputFactory()
    return parse_pcap_adapter(helper.get_dummy_input(), helper.get_dummy_context())


@pytest.mark.parametrize('suite,signature,bits', [
    ('0xc02b', 'ECDSA', 128), ('0xc02c', 'ECDSA', 256),
    ('0xc02f', 'RSA', 128), ('0xc030', 'RSA', 256),
])
def test_tls12_selected_families(monkeypatch, suite, signature, bits):
    result = scan(monkeypatch, [packet(layers=[layer(suite=suite)])])
    assert not result.errors
    assert result.coverage[0].assessed == 1
    assert {(f.algorithm, f.usage) for f in result.findings} == {
        ('ECDHE', 'key_establishment'), (signature, 'signature'), ('AES', 'encryption')}
    aes = next(f for f in result.findings if f.algorithm == 'AES')
    assert (aes.parameters.key_bits, aes.parameters.mode) == (bits, 'GCM')
    assert all(f.parameters.named_group is None for f in result.findings)
    assert all(f.parameters.hash_algorithm is None for f in result.findings)


@pytest.mark.parametrize('nested', [True, False])
def test_quic_server_hello_and_tcp_have_distinct_sessions(monkeypatch, nested):
    tls = layer('quic' if nested else 'tcp', suite='0x1301', group='4588')
    result = scan(monkeypatch, [packet(), packet('quic', layers=[tls], frame='2')])
    assert not result.errors
    assert result.coverage[0].assessed == 2
    assert len({f.asset_id for f in result.findings}) == 2
    quic = [f for f in result.findings if f.evidence[0].locator == 'frame:2']
    assert {f.algorithm for f in quic} == {'AES', 'X25519MLKEM768'}
    assert not any(f.usage == 'signature' for f in quic)


def test_quic_coalesced_layers_and_udp_fallback(monkeypatch):
    p = packet('quic', layers=[NS(layer_name='quic'),
                              layer('quic', suite='0x1301', group='29')])
    del p.quic.connection_number
    result = scan(monkeypatch, [p])
    assert not result.errors
    assert result.coverage[0].assessed == 1
    assert {f.algorithm for f in result.findings} == {'AES', 'X25519'}


def test_offers_are_distinct_from_retries_and_plain_udp(monkeypatch):
    result = scan(monkeypatch, [
        packet('quic', '1', [layer('quic', kind='1')]),
        packet('quic', '2', [layer('quic', random=HRR_RANDOM)]),
        packet('udp', '3', []),
    ])
    assert not result.errors
    assert result.findings
    assert all(f.evidence_kind == 'offered' for f in result.findings)
    assert all(f.evidence[0].locator == 'frame:1' for f in result.findings)
    assert result.coverage[0].unknown == 2
    assert result.coverage[0].unsupported == 0


def test_unknown_selected_values_remain_visible_in_coverage(monkeypatch):
    result = scan(monkeypatch, [packet('quic', layers=[layer('quic', suite='0xffff')])])
    assert not result.errors
    assert len(result.findings) == 1
    assert result.findings[0].algorithm == 'unknown'
    assert '0xffff' in result.findings[0].evidence[0].detail
    assert result.coverage[0].unknown == 1


def repeated(*values):
    from pyshark.packet.fields import LayerField, LayerFieldsContainer
    container = LayerFieldsContainer(LayerField(show=values[0]))
    for value in values[1:]:
        container.add_field(LayerField(show=value))
    return container


def test_all_client_offers_are_visible_but_excluded_from_score(monkeypatch):
    from core.assessment import assess_finding
    from core.scoring import score_findings
    hello = layer(kind='1', suite=repeated('0x1301', '0x1302', '0x0a0a', '0x00ff', '0x5600'),
                  group=repeated('29', '4588', '0x1a1a'))
    result = scan(monkeypatch, [packet(layers=[hello])])
    assert not result.errors
    assert len(result.findings) == 4
    assert len({f.id for f in result.findings}) == 4
    assert result.coverage[0].unknown == 1
    score = score_findings(assess_finding(f) for f in result.findings)
    assert score['value'] is None
    assert score['offered_only_assets'] == 1


def test_offers_and_selected_values_share_bidirectional_asset(monkeypatch):
    client = packet(layers=[layer(kind='1', suite='0x1301', group='4588')])
    server = packet(layers=[layer(suite='0x1301', group='29')], frame='2')
    server.ip.src, server.ip.dst = client.ip.dst, client.ip.src
    result = scan(monkeypatch, [client, server, server])
    assert len({f.asset_id for f in result.findings}) == 1
    assert len(result.findings) == 4
    assert result.coverage[0].assessed == 1
    observed = {f.algorithm for f in result.findings if f.evidence_kind == 'observed'}
    assert observed == {'AES', 'X25519'}


@pytest.mark.parametrize('group,algorithm,name,bits', [
    ('23', 'ECDHE', 'secp256r1', None), ('24', 'ECDHE', 'secp384r1', None),
    ('25', 'ECDHE', 'secp521r1', None), ('30', 'X448', 'X448', None),
    ('0x0100', 'DHE', 'ffdhe2048', 2048), ('260', 'DHE', 'ffdhe8192', 8192),
])
def test_additional_selected_groups(monkeypatch, group, algorithm, name, bits):
    result = scan(monkeypatch, [packet(layers=[layer(suite='0x1301', group=group)])])
    finding = next(f for f in result.findings if f.usage == 'key_establishment')
    assert (finding.algorithm, finding.parameters.named_group, finding.parameters.key_bits) == (algorithm, name, bits)


@pytest.mark.parametrize('suite,algorithm,mode', [
    ('0x1303', 'ChaCha20-Poly1305', None), ('0x1304', 'AES', 'CCM'),
    ('0x1305', 'AES', 'CCM-8'), ('0xcca8', 'ChaCha20-Poly1305', None),
    ('0xcca9', 'ChaCha20-Poly1305', None), ('0xccaa', 'ChaCha20-Poly1305', None),
    ('0x009c', 'AES', 'GCM'), ('0x009d', 'AES', 'GCM'),
    ('0x009e', 'AES', 'GCM'), ('0x009f', 'AES', 'GCM'),
])
def test_additional_selected_suites(monkeypatch, suite, algorithm, mode):
    result = scan(monkeypatch, [packet(layers=[layer(suite=suite)])])
    assert not result.errors
    cipher = next(f for f in result.findings if f.usage == 'encryption')
    assert (cipher.algorithm, cipher.parameters.mode) == (algorithm, mode)
    if suite.startswith('0x13'):
        assert len(result.findings) == 1  # TLS 1.3 suite says nothing about authentication.


@pytest.mark.parametrize('hello', [
    layer(kind=repeated('1', '2')),
    layer(suite=repeated('0x1301', '0x1302')),
    NS(layer_name='tls'),
    layer(random=HRR_RANDOM, group='4588'),
])
def test_incomplete_ambiguous_or_retry_tls_is_unknown(monkeypatch, hello):
    result = scan(monkeypatch, [packet(layers=[hello])])
    assert not result.errors
    assert not result.findings
    assert result.coverage[0].unknown == 1


def test_non_tls_tcp_remains_unsupported(monkeypatch):
    result = scan(monkeypatch, [packet(layers=[])])
    assert not result.findings
    assert result.coverage[0].unsupported == 1


def test_supported_groups_are_offers_not_selected_shares(monkeypatch):
    client = layer(kind='1', suite='0x1301', group='29')
    client.handshake_extensions_supported_group = repeated('0x001d', '0x11ec', '0x2a2a')
    server = layer(suite='0x1301', group='29')
    server.handshake_extensions_supported_group = repeated('0x11ec')
    result = scan(monkeypatch, [packet(layers=[client]), packet(layers=[server], frame='2')])
    hybrid = [f for f in result.findings if f.algorithm == 'X25519MLKEM768']
    assert len(hybrid) == 1 and hybrid[0].evidence_kind == 'offered'
    assert 'supported group' in hybrid[0].evidence[0].detail
    assert not any(f.algorithm == 'unknown' for f in result.findings)


def test_failed_stream_is_not_upgraded_by_later_selected_groups(monkeypatch):
    broken = packet()
    broken.sniff_timestamp = 'invalid'
    good = packet(layers=[layer(suite='0x1301', group='29')], frame='2')
    result = scan(monkeypatch, [broken, good])
    assert result.errors
    assert result.coverage[0].failed == 1
    assert result.coverage[0].assessed == 0


def test_repeated_selection_merges_evidence_but_rekey_retains_each_suite(monkeypatch):
    result = scan(monkeypatch, [
        packet(layers=[layer(suite='0x1301')], frame='1'),
        packet(layers=[layer(suite='0x1301')], frame='2'),
        packet(layers=[layer(suite='0x1302')], frame='3'),
    ])
    assert not result.errors
    assert len(result.findings) == 2
    aes128 = next(f for f in result.findings if f.parameters.key_bits == 128)
    assert {e.locator for e in aes128.evidence} == {'frame:1', 'frame:2'}
