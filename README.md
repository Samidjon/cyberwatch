# CyberWatch — Local Network Monitor

A Windows-friendly defensive desktop tool built with Python and PySide6.

## Features
- Detect private IPv4 interfaces and let the user choose one.
- Scan a bounded local LAN (at most 254 other addresses) for responding hosts using ICMP ping and the local ARP cache.
- Display online/offline history, IP, MAC address when available, hostname and last-seen time.
- Log new devices, devices returning online, device MAC changes and devices not seen during a successful scan.
- Optional periodic monitoring (minimum interval 30 seconds; default 60 seconds).
- Check a fixed list of 11 common TCP ports on one selected host within the selected private LAN.
- Mark selected open services for review without claiming that the host is malicious.
- Export event history to CSV.
- Store device inventory and events locally in SQLite at `data/cyberwatch.db`.


## Interface refresh
The refreshed UI uses a high-contrast light theme with a cool blue accent palette, clearer online/offline colors, larger rows and more comfortable spacing. It adds:
- **Refresh network adapters** to re-detect Wi-Fi and Ethernet interfaces without restarting the app.
- **Device search** for IP address, hostname and MAC address; filtering does not change the saved inventory.
- **Event search** for timestamp, level, IP or message; CSV export still exports the full stored event log.
- **Context-aware actions**: Open IP and Check Ports stay disabled until a suitable device is selected. Selection is preserved while the table refreshes when possible.
- More readable progress, status badges and metric cards.

## Install and run (Windows)
```powershell
cd "$HOME\Desktop\cyberwatch"
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

## Use
1. Select the private LAN interface in the left sidebar.
2. Click **SCAN LOCAL NETWORK**.
3. Select one of the discovered devices.
4. Click **SCAN PORTS ON SELECTED** to check the fixed common TCP port list.
5. Turn on **Enable periodic monitoring** to repeat discovery at the chosen interval.
6. Use **EVENT LOG** to inspect changes and **EXPORT CSV** to save the event history.

## Scope and safety
- Use only on networks you own or have explicit permission to monitor.
- Only private IPv4 LANs are accepted. Networks larger than /24 are narrowed to the /24 containing the local interface address.
- Port checking connects only to a fixed list of common TCP ports on one selected host in the selected private subnet.
- The tool does not exploit vulnerabilities, scan public IP ranges, fingerprint operating systems, or run arbitrary shell commands.
- ICMP can be blocked by devices or firewalls. A host not shown as online may still be present on the network.
- ARP cache results depend on the operating system and recent scan activity; MAC/hostname data can be missing.

## Limitations
This is a learning project, not an enterprise IDS/SIEM. It does not inspect packet payloads, decrypt traffic, or guarantee detection of every device or threat.
## Fix: port scan results remain visible
The selected-device details panel now retains the most recent port-check results for each IP during the current application session. This fixes a UI refresh bug where updating the event/device tables immediately replaced the scan output with the basic device metadata. The panel displays the scan timestamp, open ports, reviewed ports, and tested-port scope.
