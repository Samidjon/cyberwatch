import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cyberwatch import storage


class StorageNetworkScopeTests(unittest.TestCase):
    def test_same_ip_can_be_tracked_on_separate_local_networks(self):
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "cyberwatch-test.db"
            with patch.object(storage, "DB_PATH", database_path):
                store = storage.Store()
                store.record_discovery(
                    [{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "host-a"}],
                    "192.168.1.0/24",
                )
                store.record_discovery(
                    [{"ip": "192.168.1.10", "mac": "11:22:33:44:55:66", "hostname": "host-b"}],
                    "10.0.0.0/24",
                )
                lan_a = store.get_devices(network="192.168.1.0/24")
                lan_b = store.get_devices(network="10.0.0.0/24")
                self.assertEqual(len(lan_a), 1)
                self.assertEqual(len(lan_b), 1)
                self.assertEqual(lan_a[0]["hostname"], "host-a")
                self.assertEqual(lan_b[0]["hostname"], "host-b")


if __name__ == "__main__":
    unittest.main()
