import socket
import psutil
import platform
import subprocess
import re
import httpx

def interfaces():
    result = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    for name, addresses in addrs.items():
        ipv4 = ""
        ipv6 = ""
        mac = ""
        for addr in addresses:
            fam_name = getattr(addr.family, "name", "")
            fam_val = int(addr.family) if hasattr(addr.family, "value") or isinstance(addr.family, int) else None

            is_v4 = (fam_name == "AF_INET") or (fam_val == socket.AF_INET) or (addr.family == socket.AF_INET)
            is_v6 = (fam_name == "AF_INET6") or (fam_val == getattr(socket, "AF_INET6", 23)) or (addr.family == getattr(socket, "AF_INET6", 23))
            is_link = (fam_name in ("AF_LINK", "AF_PACKET")) or (fam_val == getattr(psutil, "AF_LINK", -1)) or (addr.family == getattr(psutil, "AF_LINK", -1))

            if is_v4 and not ipv4:
                ipv4 = addr.address
            elif is_v6 and not ipv6:
                ipv6 = addr.address.split("%")[0]
            elif is_link and not mac:
                mac = addr.address

        st = stats.get(name)
        speed = f"{st.speed} Mbps" if (st and st.speed > 0) else "-"
        result.append({
            "name": name,
            "status": "UP" if (st and st.isup) else "DOWN",
            "ipv4": ipv4 or "-",
            "ipv6": ipv6 or "-",
            "mac": mac or "-",
            "mtu": st.mtu if st else "-",
            "speed": speed
        })
    return result

def default_gateway():
    system = platform.system().lower()
    try:
        if system == "windows":
            # Primary: route print 0.0.0.0
            out = subprocess.check_output(["route", "print", "0.0.0.0"], text=True, errors="replace")
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gw = parts[2]
                    if gw != "0.0.0.0" and not gw.startswith("On-link"):
                        return gw
            # Fallback to ipconfig
            out = subprocess.check_output(["ipconfig"], text=True, errors="replace")
            for line in out.splitlines():
                if "DEFAULT GATEWAY" in line.upper():
                    val = line.split(":", 1)[-1].strip()
                    if val and not val.startswith("fe80"):
                        return val
        else:
            out = subprocess.check_output(["ip", "route"], text=True, errors="replace")
            for line in out.splitlines():
                if line.startswith("default"):
                    return line.split()[2]
    except Exception:
        pass
    return "-"

def local_ips():
    values = []
    for item in interfaces():
        if item["ipv4"] != "-":
            values.append((item["name"], item["ipv4"], item["mac"]))
    return values

def public_dns_resolve(host):
    try:
        return socket.gethostbyname_ex(host)
    except Exception as exc:
        return None, str(exc)

def public_ip_info(timeout=4.0):
    """Fetches public WAN IP and GeoIP details."""
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get("http://ip-api.com/json")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "ip": data.get("query", "-"),
                        "isp": data.get("isp", "-"),
                        "org": data.get("org", "-") or data.get("as", "-"),
                        "country": f"{data.get('country', '-')} ({data.get('countryCode', '')})",
                        "city": data.get("city", "-"),
                        "region": data.get("regionName", "-"),
                        "timezone": data.get("timezone", "-"),
                        "status": "success"
                    }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}
    return {"status": "error", "error": "Unable to reach GeoIP service"}

def parse_arp_table():
    """Parses system ARP table into structured records."""
    system = platform.system().lower()
    records = []
    try:
        if system == "windows":
            out = subprocess.check_output(["arp", "-a"], text=True, errors="replace")
            current_iface = "-"
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.lower().startswith("interface:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        current_iface = parts[1]
                    continue
                parts = line.split()
                if len(parts) >= 3 and "." in parts[0] and ("-" in parts[1] or ":" in parts[1]):
                    records.append({
                        "interface": current_iface,
                        "ip": parts[0],
                        "mac": parts[1].upper(),
                        "type": parts[2].lower()
                    })
        else:
            out = subprocess.check_output(["ip", "neigh"], text=True, errors="replace")
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    records.append({
                        "interface": parts[2] if "dev" in parts else "-",
                        "ip": parts[0],
                        "mac": parts[4].upper() if len(parts) > 4 else "-",
                        "type": parts[-1].lower()
                    })
    except Exception:
        pass
    return records

def parse_routing_table():
    """Parses active IPv4 routing table entries."""
    system = platform.system().lower()
    routes = []
    try:
        if system == "windows":
            out = subprocess.check_output(["route", "print"], text=True, errors="replace")
            in_ipv4 = False
            for line in out.splitlines():
                if "IPv4 Route Table" in line or "Active Routes:" in line:
                    in_ipv4 = True
                    continue
                if "Persistent Routes:" in line or "IPv6 Route Table" in line:
                    in_ipv4 = False
                    continue
                if in_ipv4:
                    parts = line.strip().split()
                    if len(parts) >= 5 and "." in parts[0] and "." in parts[1]:
                        routes.append({
                            "destination": parts[0],
                            "netmask": parts[1],
                            "gateway": parts[2],
                            "interface": parts[3],
                            "metric": parts[4]
                        })
        else:
            out = subprocess.check_output(["ip", "route"], text=True, errors="replace")
            for line in out.splitlines():
                parts = line.strip().split()
                if parts:
                    routes.append({
                        "destination": parts[0],
                        "netmask": "-",
                        "gateway": parts[2] if "via" in parts else "-",
                        "interface": parts[parts.index("dev")+1] if "dev" in parts else "-",
                        "metric": parts[parts.index("metric")+1] if "metric" in parts else "-"
                    })
    except Exception:
        pass
    return routes

def wifi_details():
    """Extracts parsed Wi-Fi details."""
    system = platform.system().lower()
    info = {}
    try:
        if system == "windows":
            out = subprocess.check_output(["netsh", "wlan", "show", "interfaces"], text=True, errors="replace")
            for line in out.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    k = k.strip()
                    v = v.strip()
                    if k:
                        info[k] = v
        else:
            out = subprocess.check_output(["iwconfig"], text=True, errors="replace")
            info["raw"] = out.strip()
    except Exception as exc:
        info["error"] = str(exc)
    return info
