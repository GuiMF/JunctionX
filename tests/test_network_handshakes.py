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


def test_offers_retries_and_plain_udp_do_not_emit_findings(monkeypatch):
    result = scan(monkeypatch, [
        packet('quic', '1', [layer('quic', kind='1')]),
        packet('quic', '2', [layer('quic', random=HRR_RANDOM)]),
        packet('udp', '3', []),
    ])
    assert not result.errors
    assert not result.findings
    assert result.coverage[0].unsupported == 2


def test_unknown_selected_values_remain_visible_in_coverage(monkeypatch):
    result = scan(monkeypatch, [packet('quic', layers=[layer('quic', suite='0xffff')])])
    assert not result.errors
    assert not result.findings
    assert result.coverage[0].unknown == 1
