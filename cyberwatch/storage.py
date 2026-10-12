import csv
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
DB_PATH = DATA_DIR / "cyberwatch.db"


def now_text():
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")


class Store:
    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(DB_PATH, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _init_db(self):
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS devices (
                network TEXT NOT NULL, ip TEXT NOT NULL, mac TEXT NOT NULL DEFAULT '', hostname TEXT NOT NULL DEFAULT '',
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, online INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (network, ip)
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
                level TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '', message TEXT NOT NULL
            )""")

    def add_event(self, level, ip, message):
        with self.connect() as db:
            db.execute("INSERT INTO events(timestamp, level, ip, message) VALUES (?, ?, ?, ?)",
                       (now_text(), level, ip or "", message))

    def get_events(self, limit=300):
        with self.connect() as db:
            rows = db.execute("SELECT timestamp, level, ip, message FROM events ORDER BY id DESC LIMIT ?",
                              (int(limit),)).fetchall()
            return [dict(row) for row in rows]

    def get_devices(self, network=None):
        with self.connect() as db:
            if network:
                rows = db.execute(
                    "SELECT network, ip, mac, hostname, first_seen, last_seen, online FROM devices WHERE network=? ORDER BY online DESC, ip",
                    (network,),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT network, ip, mac, hostname, first_seen, last_seen, online FROM devices ORDER BY online DESC, ip"
                ).fetchall()
            return [dict(row) for row in rows]

    def record_discovery(self, devices, network):
        timestamp = now_text()
        current = {device["ip"]: device for device in devices}
        with self.connect() as db:
            old_rows = db.execute("SELECT * FROM devices WHERE network=?", (network,)).fetchall()
            old = {row["ip"]: dict(row) for row in old_rows}
            for ip, device in current.items():
                existing = old.get(ip)
                if existing is None:
                    db.execute("INSERT INTO devices(network, ip, mac, hostname, first_seen, last_seen, online) VALUES (?, ?, ?, ?, ?, ?, 1)",
                               (network, ip, device.get("mac", ""), device.get("hostname", ""), timestamp, timestamp))
                    self._insert_event(db, "INFO", ip, f"New device discovered: {device.get('hostname') or 'Unknown'}")
                else:
                    old_mac = (existing.get("mac") or "").lower().replace("-", ":")
                    new_mac = (device.get("mac") or "").lower().replace("-", ":")
                    if old_mac and new_mac and old_mac != new_mac:
                        self._insert_event(db, "REVIEW", ip, f"MAC address changed: {existing['mac']} → {device['mac']}")
                    if not existing["online"]:
                        self._insert_event(db, "INFO", ip, "Device is back online")
                    db.execute("UPDATE devices SET mac=?, hostname=?, last_seen=?, online=1 WHERE ip=? AND network=?",
                               (device.get("mac", "") or existing.get("mac", ""),
                                device.get("hostname", "") or existing.get("hostname", ""), timestamp, ip, network))

            # Do not infer the entire LAN is offline when only this computer was returned:
            # firewalls often block ICMP, so a scan can have incomplete visibility.
            if len(current) > 1:
                for ip, existing in old.items():
                    if ip not in current and existing["online"]:
                        db.execute("UPDATE devices SET online=0 WHERE ip=? AND network=?", (ip, network))
                        self._insert_event(db, "INFO", ip, "Device not seen in the latest scan")

    @staticmethod
    def _insert_event(db, level, ip, message):
        db.execute("INSERT INTO events(timestamp, level, ip, message) VALUES (?, ?, ?, ?)",
                   (now_text(), level, ip or "", message))

    def export_events_csv(self, destination):
        rows = self.get_events(limit=10000)
        with open(destination, "w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=["timestamp", "level", "ip", "message"])
            writer.writeheader()
            writer.writerows(rows)
        return len(rows)

    def log_port_results(self, ip, results):
        for row in results:
            if row["state"] == "OPEN":
                level = "REVIEW" if row.get("review") else "INFO"
                suffix = " — review whether this service should be exposed" if row.get("review") else ""
                self.add_event(level, ip, f"Open TCP port {row['port']} ({row['service']}){suffix}")
