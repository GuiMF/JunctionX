import unittest
from unittest.mock import patch, MagicMock, PropertyMock
from datetime import datetime, timezone
import base64

from core.models import ScanInput, AdapterContext
from adapters.network import parse_pcap_adapter

class TestNetworkAdapter(unittest.TestCase):

    def get_dummy_input(self):
        return ScanInput(
            name="dummy.pcap",
            source_type="pcap",
            format="raw",
            content=base64.b64encode(b"dummy pcap bytes").decode(),
            encoding="base64"
        )

    def get_dummy_context(self):
        return AdapterContext(evaluated_at=datetime.now(timezone.utc))

    @patch('adapters.network.pyshark.FileCapture')
    def test_adapter_with_mocked_pcap(self, mock_capture_cls):
        mock_packet = MagicMock()
        mock_packet.ip.src = "192.168.1.1"
        mock_packet.ip.dst = "192.168.1.2"
        mock_packet.tcp.stream = "1"
        mock_packet.__contains__.return_value = True
        
        mock_packet.tls.handshake_type = "2" # ServerHello
        mock_packet.tls.handshake_ciphersuite = "0x002f"
        mock_packet.tls.handshake_random = "dummyrandom"
        mock_packet.tls.layer_name = "tls"
        mock_packet.layers = [mock_packet.tls]
        mock_packet.number = 100
        mock_packet.sniff_timestamp = "1672531200.0"
        del mock_packet.tls.handshake_extensions_key_share_group
        
        mock_capture_instance = MagicMock()
        mock_capture_instance.__iter__.return_value = [mock_packet]
        mock_capture_cls.return_value = mock_capture_instance
        
        result = parse_pcap_adapter(self.get_dummy_input(), self.get_dummy_context())
        
        self.assertEqual(len(result.coverage), 1)
        self.assertEqual(result.coverage[0].assessed, 1)
        self.assertEqual(result.coverage[0].failed, 0)
        self.assertEqual(len(result.findings), 2)
        
        algs = [f.algorithm for f in result.findings]
        self.assertIn("RSA", algs)
        self.assertIn("AES", algs)

    @patch('adapters.network.pyshark.FileCapture')
    def test_adapter_handles_attribute_error(self, mock_capture_cls):
        class BrokenLayer:
            @property
            def src(self):
                raise AttributeError("simulated missing src attr")
                
        class BrokenPacket:
            def __init__(self):
                self.number = 42
                self.ip = BrokenLayer()
                
            @property
            def ipv6(self):
                raise AttributeError("not ipv6")

        mock_capture_instance = MagicMock()
        mock_capture_instance.__iter__.return_value = [BrokenPacket()]
        mock_capture_cls.return_value = mock_capture_instance
        
        result = parse_pcap_adapter(self.get_dummy_input(), self.get_dummy_context())
        
        self.assertEqual(len(result.coverage), 1)
        self.assertEqual(result.coverage[0].failed, 1)
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.errors[0].code, "attribute_error")

if __name__ == '__main__':
    unittest.main()
