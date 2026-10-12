import concurrent.futures
import ipaddress
import os
import re
import socket
import subprocess

import psutil

PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS (TCP)",
    80: "HTTP", 139: "NetBIOS", 443: "HTTPS", 445: "SMB", 3389: "RDP", 8080: "HTTP-alt",
}
REVIEW_PORTS = {23, 445, 3389}


def _interface_mac(interface):
    link_family = getattr(psutil, "AF_LINK", None)
    if link_family is None:
        return ""
    for address in psutil.net_if_addrs().get(interface, []):
        if address.family == link_family:
            value = (address.address or "").strip()
            if value and value.lower() not in {"00:00:00:00:00:00", "00-00-00-00-00-00"}:
                return value.replace("-", ":").upper()
    return ""


def get_local_networks():
    """Return local private IPv4 interfaces. Networks wider than /24 are bounded to /24."""
    networks, seen = [], set()
    for interface, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family != socket.AF_INET or not address.address or not address.netmask:
                continue
            ip = address.address
            if ip.startswith(("127.", "169.254.")):
                continue
            try:
                ip_obj = ipaddress.ip_address(ip)
                iface_network = ipaddress.ip_network(f"{ip}/{address.netmask}", strict=False)
                if not ip_obj.is_private:
                    continue
                scan_network = iface_network
                oversized = scan_network.num_addresses > 256
                if oversized:
                    scan_network = ipaddress.ip_network(f"{ip}/24", strict=False)
                key = (interface, ip, str(scan_network))
                if key in seen:
                    continue
                seen.add(key)
                networks.append({
                    "interface": interface, "ip": ip, "netmask": address.netmask,
                    "network": str(scan_network), "mac": _interface_mac(interface),
                    "note": "Range limited to this address's local /24 for safety" if oversized else "",
                })
            except ValueError:
                continue
    return networks


def _ping_once(ip):
    if os.name == "nt":
        command, timeout = ["ping", "-n", "1", "-w", "450", str(ip)], 1.5
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    else:
        command, timeout, creationflags = ["ping", "-c", "1", "-W", "1", str(ip)], 1.7, 0
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=timeout, check=False, creationflags=creationflags)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _parse_arp_table(output, local_network):
    found = {}
    network = ipaddress.ip_network(local_network, strict=False)
    pattern = re.compile(
        r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\s+(\w+)\s*$"
    )
    for line in output.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        ip, mac, _entry_type = match.groups()
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if ip_obj in network:
            found[ip] = mac.replace("-", ":").upper()
    return found


def _read_arp_table(local_network):
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                                errors="replace", timeout=4, check=False, creationflags=flags)
        if result.returncode == 0:
            return _parse_arp_table(result.stdout, local_network)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return {}


def _resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError, TimeoutError):
        return ""


def discover_devices(network_info, progress_callback=None):
    """Discover responding hosts in one private IPv4 LAN, with a hard /24 limit."""
    ip = ipaddress.ip_address(network_info["ip"])
    if not isinstance(ip, ipaddress.IPv4Address) or not ip.is_private:
        raise ValueError("Only private IPv4 LAN interfaces can be scanned.")
    network = ipaddress.ip_network(network_info["network"], strict=False)
    if ip not in network or network.num_addresses > 256 or not network.is_private:
        raise ValueError("Invalid or oversized LAN range. Choose a private local /24 or smaller.")

    hosts = [str(host) for host in network.hosts() if str(host) != str(ip)]
    reachable = set()
    def report(done, total):
        if progress_callback:
            progress_callback(done, total)

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        future_to_ip = {executor.submit(_ping_once, target): target for target in hosts}
        total = len(future_to_ip)
        done = 0
        for future in concurrent.futures.as_completed(future_to_ip):
            try:
                if future.result():
                    reachable.add(future_to_ip[future])
            except Exception:
                pass
            done += 1
            if done % 3 == 0 or done == total:
                report(done, max(total, 1))

    arp_macs = _read_arp_table(str(network))
    found_ips = reachable | set(arp_macs)
    found_ips.add(str(ip))

    # Reverse DNS is optional; resolve concurrently to avoid long UI waits on slow DNS.
    remote_ips = [target for target in found_ips if target != str(ip)]
    hostnames = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        future_map = {executor.submit(_resolve_hostname, target): target for target in remote_ips}
        for future in concurrent.futures.as_completed(future_map):
            try:
                hostnames[future_map[future]] = future.result()
            except Exception:
                hostnames[future_map[future]] = ""

    devices = []
    for target in sorted(found_ips, key=lambda value: int(ipaddress.ip_address(value))):
        if ipaddress.ip_address(target) not in network:
            continue
        local = target == str(ip)
        devices.append({
            "ip": target,
            "mac": network_info.get("mac", "") if local else arp_macs.get(target, ""),
            "hostname": socket.gethostname() if local else hostnames.get(target, ""),
            "is_local": local,
        })
    return devices


def scan_common_tcp_ports(target_ip, allowed_network, progress_callback=None):
    """Connect-scan a fixed, small list of TCP ports on one host in the selected private LAN."""
    try:
        address = ipaddress.ip_address(target_ip)
        network = ipaddress.ip_network(allowed_network, strict=False)
    except ValueError as exc:
        raise ValueError("Invalid target IP or local network.") from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("Only IPv4 targets are supported.")
    if address not in network or not network.is_private or network.num_addresses > 256:
        raise ValueError("Port checks are restricted to the selected private LAN.")

    def check(port, service):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.35)
        try:
            result = sock.connect_ex((str(address), int(port)))
            return {"port": port, "service": service, "state": "OPEN" if result == 0 else "closed",
                    "review": result == 0 and port in REVIEW_PORTS}
        finally:
            sock.close()

    results, ports = [], list(PORTS.items())
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        future_map = {executor.submit(check, port, service): (port, service) for port, service in ports}
        done = 0
        for future in concurrent.futures.as_completed(future_map):
            port, service = future_map[future]
            try:
                results.append(future.result())
            except OSError:
                results.append({"port": port, "service": service, "state": "unknown", "review": False})
            done += 1
            if progress_callback:
                progress_callback(done, len(ports))
    return sorted(results, key=lambda row: row["port"])
