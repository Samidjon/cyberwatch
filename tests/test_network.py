import unittest

from cyberwatch.network import _parse_arp_table, scan_common_tcp_ports


class NetworkSafetyTests(unittest.TestCase):
    def test_arp_parser_keeps_only_entries_in_selected_lan(self):
        output = (
            "Interface: 192.168.1.5 --- 0x8\n"
            "  Internet Address      Physical Address      Type\n"
            "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic\n"
            "  10.0.0.1              11-22-33-44-55-66     dynamic\n"
        )
        self.assertEqual(
            _parse_arp_table(output, "192.168.1.0/24"),
            {"192.168.1.1": "AA:BB:CC:DD:EE:FF"},
        )

    def test_port_checker_rejects_public_target(self):
        with self.assertRaises(ValueError):
            scan_common_tcp_ports("8.8.8.8", "192.168.1.0/24")

    def test_port_checker_rejects_oversized_network(self):
        with self.assertRaises(ValueError):
            scan_common_tcp_ports("10.0.0.3", "10.0.0.0/16")


if __name__ == "__main__":
    unittest.main()
