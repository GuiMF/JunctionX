import unittest
from unittest.mock import patch, MagicMock
from shared import ScanInput, AdapterContext
from adapters.network import parse_pcap_adapter

class TestNetworkAdapter(unittest.TestCase):

    @patch('adapters.network.pyshark.FileCapture')
    def test_adapter_with_mocked_pcap(self, mock_capture_cls):
        # Setup mock packet (ServerHello with supported cipher suite)
        mock_packet = MagicMock()
        mock_packet.ip.src = "192.168.1.1"
        mock_packet.ip.dst = "192.168.1.2"
        mock_packet.tcp.stream = "1"
        mock_packet.__contains__.return_value = True # 'TLS' in packet
        
        # TLS specifics
        mock_packet.tls.handshake_type = "2" # ServerHello
        mock_packet.tls.handshake_ciphersuite = "0x002f" # TLS_RSA_WITH_AES_128_CBC_SHA
        mock_packet.number = 100
        mock_packet.sniff_timestamp = "1672531200.0" # Some epoch time
        
        # Configure the FileCapture instance to return our mock packet
        mock_capture_instance = MagicMock()
        mock_capture_instance.__iter__.return_value = [mock_packet]
        mock_capture_cls.return_value = mock_capture_instance
        
        # Execute adapter
        scan_input = ScanInput(path="dummy.pcap")
        context = AdapterContext()
        result = parse_pcap_adapter(scan_input, context)
        
        # Assertions
        self.assertEqual(result.assessed_sessions, 1)
        self.assertEqual(result.failed_sessions, 0)
        self.assertEqual(len(result.findings), 2)
        
        # Verify normalization of cipher suites
        algs = [f.algorithm for f in result.findings]
        self.assertIn("RSA", algs)
        self.assertIn("AES", algs)

    @patch('adapters.network.pyshark.FileCapture')
    def test_adapter_handles_attribute_error(self, mock_capture_cls):
        # Setup mock packet that raises AttributeError when accessing ip
        mock_packet = MagicMock()
        # Mocking hasattr to True but then it raises an error when accessed, 
        # or we just let it fail on something else.
        type(mock_packet).ip = property(lambda self: getattr(self, 'missing_attr'))
        
        mock_capture_instance = MagicMock()
        mock_capture_instance.__iter__.return_value = [mock_packet]
        mock_capture_cls.return_value = mock_capture_instance
        
        # Execute adapter
        scan_input = ScanInput(path="dummy.pcap")
        context = AdapterContext()
        result = parse_pcap_adapter(scan_input, context)
        
        # Assertions
        self.assertEqual(result.failed_sessions, 1)
        self.assertEqual(len(result.errors), 1)
        self.assertIn("AttributeError", result.errors[0]['error'])

if __name__ == '__main__':
    unittest.main()
