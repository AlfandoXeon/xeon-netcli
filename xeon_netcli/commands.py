import concurrent.futures
import ipaddress
import os
import platform
import random
import re
import socket
import subprocess
import time

import httpx
import psutil
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel
from rich.table import Table
from rich import box

from .network import (
    interfaces, default_gateway, public_dns_resolve,
    public_ip_info, parse_arp_table, parse_routing_table, wifi_details
)
from .ui import (
    CONSOLE, header, section, success, warning, error, info,
    kv_table, simple_table, badge, PRIMARY, SECONDARY, ACCENT
)

# COMMON SERVICES DATABASE (FULL UPPERCASE)
COMMON_PORTS = {
    20: ("FTP-DATA", "FILE TRANSFER PROTOCOL (DATA)"),
    21: ("FTP", "FILE TRANSFER PROTOCOL (CONTROL)"),
    22: ("SSH", "SECURE SHELL / SFTP"),
    23: ("TELNET", "UNENCRYPTED TEXT COMMUNICATIONS"),
    25: ("SMTP", "SIMPLE MAIL TRANSFER PROTOCOL"),
    53: ("DNS", "DOMAIN NAME SYSTEM"),
    67: ("DHCP-SRV", "DHCP SERVER"),
    68: ("DHCP-CLI", "DHCP CLIENT"),
    80: ("HTTP", "HYPERTEXT TRANSFER PROTOCOL"),
    110: ("POP3", "POST OFFICE PROTOCOL V3"),
    123: ("NTP", "NETWORK TIME PROTOCOL"),
    143: ("IMAP", "INTERNET MESSAGE ACCESS PROTOCOL"),
    161: ("SNMP", "SIMPLE NETWORK MANAGEMENT PROTOCOL"),
    443: ("HTTPS", "HTTP SECURE (TLS/SSL)"),
    445: ("SMB", "SERVER MESSAGE BLOCK / WINDOWS SHARE"),
    993: ("IMAPS", "IMAP OVER TLS/SSL"),
    995: ("POP3S", "POP3 OVER TLS/SSL"),
    1433: ("MSSQL", "MICROSOFT SQL SERVER"),
    1521: ("ORACLE", "ORACLE DATABASE LISTENER"),
    3306: ("MYSQL", "MYSQL / MARIADB DATABASE"),
    3389: ("RDP", "REMOTE DESKTOP PROTOCOL"),
    5432: ("POSTGRES", "POSTGRESQL DATABASE"),
    6379: ("REDIS", "REDIS IN-MEMORY DATA STORE"),
    8080: ("HTTP-ALT", "ALTERNATIVE HTTP WEB PROXY"),
    8443: ("HTTPS-ALT", "ALTERNATIVE HTTPS WEB PORT"),
    27017: ("MONGODB", "MONGODB DATABASE SERVER")
}

def cmd_info():
    """DISPLAYS COMPREHENSIVE HOST AND NETWORK INFORMATION."""
    section("SYSTEM & NETWORK OVERVIEW", symbol="::")
    with CONSOLE.status("[bold cyan]GATHERING SYSTEM INFORMATION...[/]"):
        gw = default_gateway()
        wan_data = public_ip_info(timeout=2.5)
        wan_str = wan_data.get("ip", "OFFLINE / UNAVAILABLE") if wan_data.get("status") == "success" else "OFFLINE"
        isp_str = wan_data.get("isp", "-") if wan_data.get("status") == "success" else "-"
        loc_str = f"{wan_data.get('city', '')}, {wan_data.get('country', '')}" if wan_data.get("status") == "success" else "-"

        all_ifaces = interfaces()
        up_ifaces = [x for x in all_ifaces if x["status"] == "UP" and x["ipv4"] != "-"]
        primary_ip = up_ifaces[0]["ipv4"] if up_ifaces else "-"

        mem = psutil.virtual_memory()
        cpu_usage = f"{psutil.cpu_percent(interval=0.1)}%"
        ram_usage = f"{mem.percent}% ({mem.used // (1024**2):,} MB / {mem.total // (1024**2):,} MB)"

    rows = [
        ("APPLICATION", "XEON-NETCLI V1.1.0"),
        ("HOSTNAME", socket.gethostname().upper()),
        ("OPERATING SYSTEM", platform.platform().upper()),
        ("PYTHON VERSION", platform.python_version()),
        ("CPU USAGE", cpu_usage),
        ("MEMORY (RAM)", ram_usage),
        ("PRIMARY LAN IP", primary_ip),
        ("DEFAULT GATEWAY", gw),
        ("PUBLIC WAN IP", wan_str.upper()),
        ("ISP PROVIDER", isp_str.upper()),
        ("GEO LOCATION", loc_str.upper()),
        ("ACTIVE INTERFACES", f"{len(up_ifaces)} UP / {len(all_ifaces)} TOTAL")
    ]
    kv_table("SYSTEM & NETWORK IDENTITY", rows, symbol="[#]")

def cmd_interface():
    """LISTS ALL DETECTED NETWORK ADAPTERS WITH REAL IPV4/IPV6 AND MAC ADDRESSES."""
    section("NETWORK INTERFACES", symbol="::")
    with CONSOLE.status("[bold cyan]QUERYING NETWORK ADAPTERS...[/]"):
        ifaces = interfaces()

    table = Table(
        title="[bold bright_cyan]:: NETWORK ADAPTERS & HARDWARE STATE ::[/]",
        border_style="bright_blue",
        box=box.ROUNDED,
        header_style="bold bright_white on blue"
    )
    table.add_column("INTERFACE NAME", style="bold bright_cyan", min_width=18)
    table.add_column("STATUS", justify="center")
    table.add_column("IPV4 ADDRESS", style="bold bright_white")
    table.add_column("MAC ADDRESS", style="bright_yellow")
    table.add_column("MTU", justify="center", style="dim white")
    table.add_column("LINK SPEED", justify="center", style="bright_green")

    for x in ifaces:
        if x["status"] == "UP":
            st = "[bold green]● UP[/]"
        else:
            st = "[bold red]○ DOWN[/]"
        table.add_row(
            str(x["name"]).upper(),
            st,
            str(x["ipv4"]).upper(),
            str(x["mac"]).upper(),
            str(x["mtu"]).upper(),
            str(x["speed"]).upper()
        )
    CONSOLE.print(table)

def cmd_public_ip():
    """DISPLAYS PUBLIC WAN IP ADDRESS AND GEOIP ROUTING DATA."""
    section("PUBLIC WAN & GEOIP LOOKUP", symbol="::")
    with CONSOLE.status("[bold cyan]QUERYING GEOIP SERVICES...[/]"):
        data = public_ip_info(timeout=5.0)

    if data.get("status") == "success":
        rows = [
            ("EXTERNAL PUBLIC IP", data.get("ip", "-")),
            ("INTERNET SERVICE PROVIDER", data.get("isp", "-")),
            ("AUTONOMOUS SYSTEM (AS)", data.get("org", "-")),
            ("COUNTRY & CODE", data.get("country", "-")),
            ("CITY / PROVINCE", f"{data.get('city', '-')}, {data.get('region', '-')}"),
            ("TIMEZONE", data.get("timezone", "-")),
        ]
        kv_table("PUBLIC CONNECTION DETAILS", rows, symbol="[#]")
        success("PUBLIC WAN DATA RESOLVED SUCCESSFULLY.")
    else:
        error(f"FAILED TO FETCH PUBLIC IP: {data.get('error', 'NETWORK TIMEOUT')}")

def cmd_ip(address):
    """ANALYZES AN IP ADDRESS IN DEPTH."""
    section(f"IP ANALYZER: {address.upper()}", symbol="::")
    try:
        obj = ipaddress.ip_address(address)
    except ValueError:
        error(f"'{address}' IS NOT A VALID IPV4 OR IPV6 ADDRESS.")
        return

    rows = [
        ("ADDRESS", str(obj)),
        ("IP VERSION", f"IPV{obj.version}"),
        ("CLASSIFICATION", "PRIVATE (LAN)" if obj.is_private else "PUBLIC (INTERNET)"),
        ("IS LOOPBACK", "YES (LOCAL HOST)" if obj.is_loopback else "NO"),
        ("IS MULTICAST", "YES" if obj.is_multicast else "NO"),
        ("IS GLOBAL ROUTABLE", "YES" if obj.is_global else "NO"),
        ("IS RESERVED", "YES" if obj.is_reserved else "NO"),
        ("INTEGER VALUE", str(int(obj))),
        ("HEXADECIMAL", str(hex(int(obj))).upper()),
    ]
    if obj.version == 4:
        binary_str = format(int(obj), "032b")
        dotted_bin = f"{binary_str[0:8]}.{binary_str[8:16]}.{binary_str[16:24]}.{binary_str[24:32]}"
        rows.append(("BINARY REPRESENTATION", dotted_bin))

        first_octet = int(str(obj).split(".")[0])
        if first_octet <= 126:
            ip_class = "CLASS A (DEFAULT MASK /8)"
        elif first_octet == 127:
            ip_class = "CLASS A (LOOPBACK BLOCK 127.0.0.0/8)"
        elif first_octet <= 191:
            ip_class = "CLASS B (DEFAULT MASK /16)"
        elif first_octet <= 223:
            ip_class = "CLASS C (DEFAULT MASK /24)"
        elif first_octet <= 239:
            ip_class = "CLASS D (MULTICAST 224.0.0.0/4)"
        else:
            ip_class = "CLASS E (EXPERIMENTAL 240.0.0.0/4)"
        rows.append(("TRADITIONAL CLASS", ip_class))

    kv_table(f"IP ANALYSIS DETAILS ({obj})", rows, symbol="[#]")

def cmd_subnet(network):
    """PERFORMS COMPREHENSIVE IPV4/IPV6 SUBNET CALCULATION."""
    section(f"SUBNET CALCULATOR: {network.upper()}", symbol="::")
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        error(f"INVALID NETWORK NOTATION '{network}'. USE CIDR FORMAT, E.G. 192.168.1.0/24")
        return

    hosts = list(net.hosts())
    first = str(hosts[0]) if hosts else "-"
    last = str(hosts[-1]) if hosts else "-"
    usable = max(net.num_addresses - (2 if net.version == 4 and net.prefixlen < 31 else 0), 0)

    rows = [
        ("NETWORK ADDRESS", str(net.network_address)),
        ("BROADCAST ADDRESS", str(getattr(net, "broadcast_address", "-"))),
        ("SUBNET MASK", str(getattr(net, "netmask", "-"))),
        ("WILDCARD MASK", str(getattr(net, "hostmask", "-"))),
        ("CIDR PREFIX", f"/{net.prefixlen}"),
        ("TOTAL ADDRESSES", f"{net.num_addresses:,}"),
        ("USABLE HOST CAPACITY", f"{usable:,} HOSTS"),
        ("FIRST USABLE HOST", first),
        ("LAST USABLE HOST", last),
        ("IP VERSION", f"IPV{net.version}")
    ]

    if net.version == 4:
        mask_int = int(net.netmask)
        mask_bin = format(mask_int, "032b")
        dotted_mask_bin = f"{mask_bin[0:8]}.{mask_bin[8:16]}.{mask_bin[16:24]}.{mask_bin[24:32]}"
        rows.append(("BINARY SUBNET MASK", dotted_mask_bin))

    kv_table("SUBNET CALCULATION RESULTS", rows, symbol="[#]")

def cmd_vlsm(network, requirements):
    """CALCULATES VARIABLE LENGTH SUBNET MASKING (VLSM)."""
    section(f"VLSM SUBNETTING: {network.upper()}", symbol="::")
    try:
        base = ipaddress.ip_network(network, strict=False)
        if base.version != 4:
            error("VLSM MODULE CURRENTLY SUPPORTS IPV4 NETWORKS.")
            return

        req = sorted([(int(x), i + 1) for i, x in enumerate(requirements)], reverse=True)
        cursor = int(base.network_address)
        end = int(base.broadcast_address)
        rows = []

        for hosts, idx in req:
            needed = hosts + 2
            bits = max(0, (needed - 1).bit_length())
            size = 2 ** bits
            prefix = 32 - bits
            start = cursor
            finish = cursor + size - 1
            if finish > end:
                error("REQUIREMENTS EXCEED THE AVAILABLE ADDRESS SPACE OF THE BASE NETWORK!")
                return
            subnet = ipaddress.ip_network((start, prefix))
            usable = max(size - 2, 0)
            shosts = list(subnet.hosts())
            first_h = str(shosts[0]) if shosts else "-"
            last_h = str(shosts[-1]) if shosts else "-"

            rows.append((
                f"SUBNET #{idx}",
                f"{hosts} HOSTS",
                str(subnet),
                str(subnet.netmask),
                f"{usable} HOSTS",
                f"{first_h} - {last_h}",
                str(subnet.broadcast_address)
            ))
            cursor = finish + 1

        table = Table(
            title="[bold bright_cyan]:: VLSM ALLOCATION PLAN ::[/]",
            border_style="bright_blue",
            box=box.ROUNDED,
            header_style="bold bright_white on blue"
        )
        for col in ["TIER", "NEEDED", "ALLOCATED CIDR", "NETMASK", "USABLE HOSTS", "HOST RANGE", "BROADCAST"]:
            table.add_column(col, style="bright_white")
        for row in rows:
            table.add_row(*[str(r).upper() for r in row])
        CONSOLE.print(table)
        success("VLSM SUBNETS ALLOCATED WITH OPTIMAL ZERO-WASTE BOUNDARIES.")
    except Exception as exc:
        error(f"VLSM CALCULATION ERROR: {exc}")

def _ping_command(host, count):
    if platform.system().lower() == "windows":
        return ["ping", "-n", str(count), host]
    return ["ping", "-c", str(count), host]

def cmd_ping(host, count=4):
    """EXECUTES AN ICMP PING TEST WITH LATENCY METRICS."""
    section(f"PING ANALYZER: {host.upper()}", symbol="::")
    try:
        with CONSOLE.status(f"[bold cyan]TRANSMITTING {count} ICMP ECHO REQUESTS TO {host.upper()}...[/]"):
            start = time.perf_counter()
            proc = subprocess.run(
                _ping_command(host, count),
                capture_output=True,
                text=True,
                errors="replace",
                timeout=max(10, count * 3)
            )
            elapsed = (time.perf_counter() - start) * 1000

        text = (proc.stdout + proc.stderr).lower()
        received = text.count("ttl=") if "ttl=" in text else max(0, count if proc.returncode == 0 else 0)
        loss = ((count - received) / count) * 100 if count else 100

        if loss == 0:
            loss_badge = "[bold green]0% (OPTIMAL)[/]"
            status_badge = "[bold green]ONLINE / REACHABLE[/]"
        elif loss < 50:
            loss_badge = f"[bold yellow]{loss:.0f}% (DEGRADED)[/]"
            status_badge = "[bold yellow]UNSTABLE[/]"
        else:
            loss_badge = f"[bold red]{loss:.0f}% (CRITICAL LOSS)[/]"
            status_badge = "[bold red]OFFLINE / UNREACHABLE[/]"

        times = re.findall(r"time[=<](\d+)ms", text)
        if times:
            int_times = [int(t) for t in times]
            min_rtt = f"{min(int_times)} MS"
            avg_rtt = f"{sum(int_times) / len(int_times):.1f} MS"
            max_rtt = f"{max(int_times)} MS"
        else:
            min_rtt = avg_rtt = max_rtt = f"{elapsed / count:.1f} MS (EST)"

        rows = [
            ("TARGET HOST", host.upper()),
            ("PACKETS TRANSMITTED", count),
            ("PACKETS RECEIVED", received),
            ("PACKET LOSS", loss_badge),
            ("STATUS", status_badge),
            ("MIN ROUND-TRIP", min_rtt),
            ("AVG ROUND-TRIP", avg_rtt),
            ("MAX ROUND-TRIP", max_rtt),
            ("TOTAL TEST DURATION", f"{elapsed:.1f} MS")
        ]
        kv_table(f"PING DIAGNOSTIC: {host.upper()}", rows, symbol="[#]")
    except Exception as exc:
        error(f"PING EXECUTION FAILED: {exc}")

def cmd_traceroute(host, max_hops=15):
    """TRACES THE NETWORK HOPS TO A REMOTE HOST."""
    section(f"TRACEROUTE PATH INSPECTOR: {host.upper()}", symbol="::")
    system = platform.system().lower()
    cmd = ["tracert", "-d", "-h", str(max_hops), host] if system == "windows" else ["traceroute", "-n", "-m", str(max_hops), host]

    table = Table(
        title=f"[bold bright_cyan]:: ROUTE TRACE TO {host.upper()} (MAX {max_hops} HOPS) ::[/]",
        border_style="bright_blue",
        box=box.ROUNDED,
        header_style="bold bright_white on blue"
    )
    table.add_column("HOP", justify="center", style="bold bright_cyan", width=6)
    table.add_column("RTT 1", justify="center", style="bright_yellow")
    table.add_column("RTT 2", justify="center", style="bright_yellow")
    table.add_column("RTT 3", justify="center", style="bright_yellow")
    table.add_column("ROUTER / GATEWAY IP", style="bold bright_white")

    with CONSOLE.status(f"[bold cyan]TRACING PACKET ROUTE TO {host.upper()}...[/]"):
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                match = re.match(r"^\s*(\d+)\s+([<\d\*\s\w]+ms|\*)\s+([<\d\*\s\w]+ms|\*)\s+([<\d\*\s\w]+ms|\*)\s+([a-fA-F0-9\.:]+|\*)", line)
                if match:
                    hop, r1, r2, r3, ip = match.groups()
                    table.add_row(hop.upper(), r1.strip().upper(), r2.strip().upper(), r3.strip().upper(), ip.strip().upper())
            proc.wait(timeout=30)
            CONSOLE.print(table)
            success("TRACEROUTE COMPLETED.")
        except Exception as exc:
            error(f"TRACEROUTE FAILED: {exc}")

def cmd_dns(host, record="A"):
    """QUERIES DNS RECORDS FOR A DOMAIN."""
    section(f"DNS RESOLVER: {host.upper()}", symbol="::")
    try:
        with CONSOLE.status(f"[bold cyan]QUERYING DNS RECORDS FOR {host.upper()}...[/]"):
            infos = socket.getaddrinfo(host, None)
            addresses = sorted(set(x[4][0] for x in infos))
        rows = [(record.upper(), ip.upper()) for ip in addresses]
        simple_table(f"DNS RECORDS FOR {host.upper()}", ["RECORD TYPE", "RESOLVED IP ADDRESS"], rows, symbol="[#]")
        success(f"RESOLVED {len(addresses)} ADDRESS(ES) FOR {host.upper()}")
    except Exception as exc:
        error(f"DNS LOOKUP FAILED: {exc}")

def cmd_route():
    """DISPLAYS THE ACTIVE ROUTING TABLE IN A STRUCTURED TABLE."""
    section("SYSTEM ROUTING TABLE", symbol="::")
    routes = parse_routing_table()
    if not routes:
        warning("UNABLE TO PARSE ROUTES OR NO ACTIVE IPV4 ROUTES FOUND.")
        return

    table = Table(
        title="[bold bright_cyan]:: IPV4 ACTIVE ROUTING TABLE ::[/]",
        border_style="bright_blue",
        box=box.ROUNDED,
        header_style="bold bright_white on blue"
    )
    table.add_column("DESTINATION", style="bold bright_cyan")
    table.add_column("NETMASK", style="dim white")
    table.add_column("GATEWAY", style="bold bright_green")
    table.add_column("INTERFACE IP", style="bright_white")
    table.add_column("METRIC", justify="center", style="bright_yellow")

    for r in routes[:35]:
        table.add_row(r["destination"].upper(), r["netmask"].upper(), r["gateway"].upper(), r["interface"].upper(), str(r["metric"]).upper())
    CONSOLE.print(table)

def cmd_arp():
    """DISPLAYS THE SYSTEM ARP TABLE CLEANLY."""
    section("ADDRESS RESOLUTION PROTOCOL (ARP) TABLE", symbol="::")
    records = parse_arp_table()
    if not records:
        warning("NO ENTRIES IN LOCAL ARP CACHE.")
        return

    table = Table(
        title="[bold bright_cyan]:: LOCAL ARP CACHE ::[/]",
        border_style="bright_blue",
        box=box.ROUNDED,
        header_style="bold bright_white on blue"
    )
    table.add_column("INTERFACE", style="dim white")
    table.add_column("INTERNET ADDRESS (IP)", style="bold bright_cyan")
    table.add_column("PHYSICAL ADDRESS (MAC)", style="bold bright_yellow")
    table.add_column("TYPE", justify="center")

    for r in records:
        type_style = "[bold cyan]DYNAMIC[/]" if r["type"] == "dynamic" else "[dim]STATIC[/]"
        table.add_row(r["interface"].upper(), r["ip"].upper(), r["mac"].upper(), type_style)
    CONSOLE.print(table)

def cmd_connections(limit=40):
    """MONITORS ACTIVE TCP CONNECTIONS AND ASSOCIATED PROCESSES."""
    section("ACTIVE TCP CONNECTIONS", symbol="::")
    rows = []
    try:
        with CONSOLE.status("[bold cyan]INSPECTING ACTIVE SOCKETS...[/]"):
            for c in psutil.net_connections(kind="tcp"):
                local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
                remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
                status = c.status
                pid = str(c.pid or "-")
                pname = "-"
                if c.pid:
                    try:
                        pname = psutil.Process(c.pid).name()
                    except Exception:
                        pass
                rows.append((local, remote, status, pid, pname))

        rows = rows[:limit]
        table = Table(
            title=f"[bold bright_cyan]:: TCP SOCKETS (SHOWING {len(rows)} ACTIVE) ::[/]",
            border_style="bright_blue",
            box=box.ROUNDED,
            header_style="bold bright_white on blue"
        )
        table.add_column("LOCAL SOCKET", style="bold bright_cyan")
        table.add_column("REMOTE SOCKET", style="bright_white")
        table.add_column("STATE", justify="center")
        table.add_column("PID", justify="center", style="dim white")
        table.add_column("PROCESS NAME", style="bold bright_yellow")

        for loc, rem, st, pid, pnm in rows:
            st_style = f"[bold green]{st.upper()}[/]" if st == "ESTABLISHED" else (f"[bold cyan]{st.upper()}[/]" if st == "LISTEN" else f"[dim]{st.upper()}[/]")
            table.add_row(loc.upper(), rem.upper(), st_style, pid.upper(), pnm.upper())
        CONSOLE.print(table)
    except Exception as exc:
        error(f"FAILED RETRIEVING TCP SOCKETS: {exc}")

def cmd_port(host, port, timeout=2.0):
    """TESTS A SINGLE TCP PORT."""
    section(f"TCP PORT CHECK: {host.upper()}:{port}", symbol="::")
    try:
        port = int(port)
        svc_name, svc_desc = COMMON_PORTS.get(port, ("UNKNOWN", "CUSTOM SERVICE"))
        with CONSOLE.status(f"[bold cyan]PROBING {host.upper()}:{port}...[/]"):
            start = time.perf_counter()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            ms = (time.perf_counter() - start) * 1000

        status = "[bold green]OPEN / LISTENING[/]" if result == 0 else "[bold red]CLOSED / FILTERED[/]"
        rows = [
            ("TARGET HOST", host.upper()),
            ("PORT NUMBER", str(port)),
            ("KNOWN SERVICE", f"{svc_name} ({svc_desc})".upper()),
            ("PORT STATUS", status),
            ("SOCKET LATENCY", f"{ms:.2f} MS")
        ]
        kv_table(f"PORT DIAGNOSTIC ({host.upper()}:{port})", rows, symbol="[#]")
    except Exception as exc:
        error(f"PORT CHECK ERROR: {exc}")

def cmd_port_scan(host, ports=None):
    """SCANS POPULAR OR SPECIFIED PORTS CONCURRENTLY WITH A PROGRESS INDICATOR."""
    section(f"MULTI-PORT SCANNER: {host.upper()}", symbol="::")
    if ports is None:
        target_ports = sorted(COMMON_PORTS.keys())
    else:
        target_ports = sorted(list(set(ports)))

    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=CONSOLE
    ) as progress:
        task = progress.add_task(f"[bold cyan]SCANNING {len(target_ports)} PORTS ON {host.upper()}...", total=len(target_ports))

        def check(p):
            start = time.perf_counter()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.2)
                res = s.connect_ex((host, p))
                s.close()
                elapsed = (time.perf_counter() - start) * 1000
                return p, (res == 0), elapsed
            except Exception:
                return p, False, 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {executor.submit(check, p): p for p in target_ports}
            for future in concurrent.futures.as_completed(future_to_port):
                p, is_open, rtt = future.result()
                results.append((p, is_open, rtt))
                progress.advance(task)

    results.sort(key=lambda x: x[0])
    table = Table(
        title=f"[bold bright_cyan]:: PORT SCAN RESULTS FOR {host.upper()} ::[/]",
        border_style="bright_blue",
        box=box.ROUNDED,
        header_style="bold bright_white on blue"
    )
    table.add_column("PORT", justify="center", style="bold bright_cyan")
    table.add_column("SERVICE", style="bright_yellow")
    table.add_column("STATE", justify="center")
    table.add_column("LATENCY", justify="right", style="dim white")
    table.add_column("DESCRIPTION", style="dim white")

    open_count = 0
    for p, is_open, rtt in results:
        svc_name, svc_desc = COMMON_PORTS.get(p, ("UNKNOWN", "CUSTOM PORT"))
        if is_open:
            open_count += 1
            st_text = "[bold green]OPEN[/]"
            rtt_text = f"[bold green]{rtt:.1f} MS[/]"
        else:
            st_text = "[dim red]CLOSED[/]"
            rtt_text = "-"
        table.add_row(str(p), svc_name.upper(), st_text, rtt_text, svc_desc.upper())

    CONSOLE.print(table)
    if open_count > 0:
        success(f"SCAN COMPLETE: FOUND {open_count} OPEN PORT(S) ON {host.upper()}.")
    else:
        warning(f"SCAN COMPLETE: ALL {len(target_ports)} SCANNED PORTS ARE CLOSED OR FILTERED.")

def cmd_http(url):
    """PERFORMS HTTP/HTTPS DIAGNOSTICS WITH RESPONSE INSPECTION."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    section(f"HTTP/HTTPS DIAGNOSTICS: {url.upper()}", symbol="::")
    try:
        with CONSOLE.status(f"[bold cyan]CONNECTING TO {url}...[/]"):
            start = time.perf_counter()
            with httpx.Client(follow_redirects=True, timeout=10) as client:
                response = client.get(url)
            total = (time.perf_counter() - start) * 1000

        status_style = "bold green" if response.status_code < 400 else "bold red"
        status_display = f"[{status_style}]{response.status_code} {response.reason_phrase.upper()}[/]"

        rows = [
            ("TARGET URL", url.upper()),
            ("STATUS CODE", status_display),
            ("FINAL DESTINATION", str(response.url).upper()),
            ("PROTOCOL VERSION", str(response.http_version).upper()),
            ("CONTENT-TYPE", str(response.headers.get("content-type", "-")).upper()),
            ("CONTENT-LENGTH", f"{len(response.content):,} BYTES"),
            ("SERVER SOFTWARE", str(response.headers.get("server", "-")).upper()),
            ("RESPONSE LATENCY", f"{total:.1f} MS")
        ]
        kv_table("HTTP RESPONSE SUMMARY", rows, symbol="[#]")
        success(f"RECEIVED HTTP {response.status_code} IN {total:.1f} MS.")
    except Exception as exc:
        error(f"HTTP REQUEST FAILED: {exc}")

def cmd_diagnose(host="google.com"):
    """RUNS A COMPLETE END-TO-END NETWORK HEALTH CHECK."""
    section(f"FULL NETWORK DIAGNOSTIC: TARGET {host.upper()}", symbol="::")
    checks = []

    with CONSOLE.status("[bold cyan]TESTING LOCAL NETWORK ADAPTERS...[/]"):
        ifaces = interfaces()
        up = [x for x in ifaces if x["status"] == "UP" and x["ipv4"] != "-"]
        checks.append(("LOCAL NETWORK INTERFACE (LAN)", bool(up), "ACTIVE NETWORK INTERFACE WITH IP ASSIGNED"))

    with CONSOLE.status("[bold cyan]TESTING DEFAULT GATEWAY CONNECTIVITY...[/]"):
        gw = default_gateway()
        checks.append(("DEFAULT GATEWAY REACHABLE", gw != "-", f"GATEWAY DETECTED: {gw}"))

    with CONSOLE.status(f"[bold cyan]TESTING DNS RESOLUTION FOR {host.upper()}...[/]"):
        try:
            socket.gethostbyname(host)
            dns_ok = True
        except Exception:
            dns_ok = False
        checks.append(("DNS NAME RESOLUTION", dns_ok, f"RESOLVED TARGET HOSTNAME '{host.upper()}'"))

    with CONSOLE.status(f"[bold cyan]TESTING ICMP ECHO TO {host.upper()}...[/]"):
        try:
            proc = subprocess.run(_ping_command(host, 1), capture_output=True, timeout=5)
            icmp_ok = (proc.returncode == 0)
        except Exception:
            icmp_ok = False
        checks.append(("ICMP INTERNET REACHABILITY", icmp_ok, "PING ECHO REPLY RECEIVED"))

    table = Table(
        title="[bold bright_cyan]:: DIAGNOSTIC HEALTH MATRIX ::[/]",
        border_style="bright_blue",
        box=box.ROUNDED,
        header_style="bold bright_white on blue"
    )
    table.add_column("CHECK CATEGORY", style="bold bright_cyan")
    table.add_column("STATUS", justify="center")
    table.add_column("DETAILS / OBSERVATION", style="bright_white")

    all_pass = True
    for name, ok, desc in checks:
        if ok:
            st = "[bold green][OK] PASS[/]"
        else:
            st = "[bold red][FAIL] FAIL[/]"
            all_pass = False
        table.add_row(name.upper(), st, desc.upper())

    CONSOLE.print(table)
    if all_pass:
        success("ALL DIAGNOSTIC LAYERS PASSED! INTERNET AND LAN CONNECTIVITY ARE HEALTHY.")
    else:
        warning("ONE OR MORE DIAGNOSTIC CHECKS FAILED. CHECK CABLE/WI-FI OR GATEWAY SETTINGS.")

def cmd_wifi():
    """DISPLAYS WIRELESS ADAPTER STATUS AND SIGNAL METRICS."""
    section("WIRELESS (WI-FI) TELEMETRY", symbol="::")
    info_dict = wifi_details()
    if "error" in info_dict:
        error(f"WI-FI DIAGNOSTICS UNAVAILABLE: {info_dict['error']}")
        return

    if not info_dict:
        warning("NO ACTIVE WI-FI ADAPTERS DETECTED ON THIS SYSTEM.")
        return

    rows = []
    for k, v in info_dict.items():
        if k.lower() == "signal":
            try:
                pct = int(v.replace("%", "").strip())
                bar_filled = int(pct / 10)
                bar = "█" * bar_filled + "░" * (10 - bar_filled)
                rows.append(("SIGNAL STRENGTH", f"[bold green]{bar} {pct}%[/]"))
                continue
            except Exception:
                pass
        rows.append((k.upper(), str(v).upper()))

    kv_table("WI-FI INTERFACE STATUS", rows, symbol="[#]")

def cmd_monitor(interval=1.0):
    """MONITORS LIVE NETWORK BANDWIDTH THROUGHPUT WITH DYNAMIC UNITS."""
    section("LIVE NETWORK BANDWIDTH MONITOR (CTRL+C TO STOP)", symbol="::")
    try:
        old = psutil.net_io_counters()
        start_time = time.time()
        CONSOLE.print("[bold dim]TRACKING BANDWIDTH METRICS... PRESS CTRL+C TO STOP.[/]\n")

        while True:
            time.sleep(interval)
            new = psutil.net_io_counters()
            rx_rate = (new.bytes_recv - old.bytes_recv) / interval
            tx_rate = (new.bytes_sent - old.bytes_sent) / interval

            def fmt(b):
                if b >= 1024 * 1024:
                    return f"{b / (1024 * 1024):>6.2f} MB/S"
                elif b >= 1024:
                    return f"{b / 1024:>6.1f} KB/S"
                return f"{b:>6.0f} B/S "

            timestamp = time.strftime("%H:%M:%S")
            CONSOLE.print(
                f"[dim]{timestamp}[/]  "
                f"[bold cyan]▼ RX:[/] [bold bright_white]{fmt(rx_rate)}[/]   "
                f"[bold magenta]▲ TX:[/] [bold bright_white]{fmt(tx_rate)}[/]   "
                f"[dim]PKTS IN:[/] [bright_green]{new.packets_recv:,}[/]   "
                f"[dim]PKTS OUT:[/] [bright_yellow]{new.packets_sent:,}[/]"
            )
            old = new
    except KeyboardInterrupt:
        CONSOLE.print()
        warning("BANDWIDTH MONITOR STOPPED BY USER.")

def cmd_protocol(port_or_name):
    """LOOKS UP PORT OR SERVICE IN REFERENCE DATABASE."""
    section(f"PROTOCOL DIRECTORY: {str(port_or_name).upper()}", symbol="::")
    found = []

    try:
        p = int(port_or_name)
        if p in COMMON_PORTS:
            name, desc = COMMON_PORTS[p]
            found.append((str(p), name, desc))
    except ValueError:
        query = str(port_or_name).upper()
        for p, (name, desc) in COMMON_PORTS.items():
            if query in name.upper() or query in desc.upper():
                found.append((str(p), name, desc))

    if found:
        simple_table(
            f"PROTOCOL MATCHES FOR '{str(port_or_name).upper()}'",
            ["PORT", "PROTOCOL / SERVICE", "PURPOSE / DESCRIPTION"],
            found,
            symbol="[#]"
        )
    else:
        warning(f"NO PROTOCOL ENTRIES FOUND MATCHING '{str(port_or_name).upper()}'.")

def cmd_cidr_table():
    """RENDERS A COMPREHENSIVE CIDR REFERENCE TABLE FOR SUBNETTING STUDENTS."""
    section("CIDR SUBNET MASK CHEAT SHEET (/0 - /32)", symbol="::")
    table = Table(
        title="[bold bright_cyan]:: IPV4 CIDR PREFIX & CAPACITY REFERENCE ::[/]",
        border_style="bright_blue",
        box=box.ROUNDED,
        header_style="bold bright_white on blue"
    )
    table.add_column("CIDR", justify="center", style="bold bright_cyan")
    table.add_column("SUBNET MASK", style="bright_white")
    table.add_column("WILDCARD MASK", style="dim white")
    table.add_column("TOTAL IPS", justify="right", style="bright_yellow")
    table.add_column("USABLE HOSTS", justify="right", style="bold bright_green")
    table.add_column("CLASS / COMMON USAGE", style="dim cyan")

    common_usages = {
        "/32": "SINGLE HOST / LOOPBACK ROUTE",
        "/30": "POINT-TO-POINT ROUTER LINK",
        "/29": "SMALL SUBNET (6 USABLE)",
        "/28": "SMALL OFFICE (14 USABLE)",
        "/24": "STANDARD CLASS C LAN (254 USABLE)",
        "/16": "STANDARD CLASS B ENTERPRISE (65,534 USABLE)",
        "/8": "STANDARD CLASS A ISP BLOCK (16M USABLE)"
    }

    for prefix in range(0, 33):
        net = ipaddress.IPv4Network(f"0.0.0.0/{prefix}")
        cidr = f"/{prefix}"
        total = net.num_addresses
        usable = max(total - (2 if prefix < 31 else 0), 0)
        note = common_usages.get(cidr, "-")
        table.add_row(
            cidr,
            str(net.netmask),
            str(net.hostmask),
            f"{total:,}",
            f"{usable:,}",
            note.upper()
        )
    CONSOLE.print(table)

def cmd_learn(topic="OSI"):
    """INTERACTIVE EDUCATIONAL GUIDE FOR NETWORKING MODELS AND PROTOCOLS."""
    topic = topic.upper()
    section(f"NETWORKING STUDY LAB: {topic}", symbol="::")

    if topic in ("OSI", "ALL"):
        osi_table = Table(
            title="[bold bright_cyan]:: OSI 7-LAYER REFERENCE MODEL ::[/]",
            border_style="bright_blue",
            box=box.ROUNDED,
            header_style="bold bright_white on blue"
        )
        osi_table.add_column("LAYER", justify="center", style="bold bright_cyan", width=10)
        osi_table.add_column("NAME", style="bold bright_yellow", width=16)
        osi_table.add_column("DATA UNIT (PDU)", style="bright_green", width=16)
        osi_table.add_column("PROTOCOLS & HARDWARE", style="bright_white")

        layers = [
            ("LAYER 7", "APPLICATION", "DATA", "HTTP, HTTPS, DNS, DHCP, FTP, SSH, SMTP"),
            ("LAYER 6", "PRESENTATION", "DATA", "SSL/TLS, ASCII, JPEG, MPEG, ENCRYPTION"),
            ("LAYER 5", "SESSION", "DATA", "RPC, NETBIOS, SOCKETS, SESSION PERSISTENCE"),
            ("LAYER 4", "TRANSPORT", "SEGMENTS (TCP) / DATAGRAMS (UDP)", "TCP, UDP, PORTS, FLOW CONTROL, HANDSHAKE"),
            ("LAYER 3", "NETWORK", "PACKETS", "IPV4, IPV6, ICMP, ROUTERS, IP ROUTING"),
            ("LAYER 2", "DATA LINK", "FRAMES", "ETHERNET, SWITCHES, MAC ADDRESSES, ARP, VLAN"),
            ("LAYER 1", "PHYSICAL", "BITS", "CABLES (CAT6/FIBER), HUBS, RADIO WAVES, NIC PHY")
        ]
        for l, n, pdu, pr in layers:
            osi_table.add_row(l, n, pdu, pr)
        CONSOLE.print(osi_table)
        CONSOLE.print()

    if topic in ("TCP", "ALL"):
        tcp_table = Table(
            title="[bold bright_cyan]:: TCP 3-WAY HANDSHAKE (CONNECTION ESTABLISHMENT) ::[/]",
            border_style="bright_blue",
            box=box.ROUNDED,
            header_style="bold bright_white on blue"
        )
        tcp_table.add_column("STEP", justify="center", style="bold bright_cyan")
        tcp_table.add_column("PACKET FLAG", style="bold bright_yellow")
        tcp_table.add_column("SENDER -> RECEIVER", style="bright_white")
        tcp_table.add_column("ACTION / EXPLANATION", style="dim white")

        tcp_steps = [
            ("STEP 1", "SYN", "CLIENT  ───>  SERVER", "CLIENT CHOOSES INITIAL SEQUENCE NUMBER (ISN) AND ASKS TO CONNECT."),
            ("STEP 2", "SYN + ACK", "SERVER  ───>  CLIENT", "SERVER ACKNOWLEDGES CLIENT'S ISN AND SENDS ITS OWN SYN SEQUENCE."),
            ("STEP 3", "ACK", "CLIENT  ───>  SERVER", "CLIENT ACKNOWLEDGES SERVER'S SYN. TCP CONNECTION IS ESTABLISHED.")
        ]
        for s, f, d, a in tcp_steps:
            tcp_table.add_row(s, f, d, a)
        CONSOLE.print(tcp_table)
        CONSOLE.print()

    if topic in ("CLASSES", "ALL"):
        class_table = Table(
            title="[bold bright_cyan]:: IPV4 ADDRESS CLASSES ARCHITECTURE ::[/]",
            border_style="bright_blue",
            box=box.ROUNDED,
            header_style="bold bright_white on blue"
        )
        class_table.add_column("CLASS", justify="center", style="bold bright_cyan")
        class_table.add_column("LEADING BITS", style="dim white")
        class_table.add_column("OCTET RANGE", style="bold bright_white")
        class_table.add_column("DEFAULT MASK", style="bright_yellow")
        class_table.add_column("PRIVATE RFC 1918 RANGE", style="bright_green")

        class_rows = [
            ("CLASS A", "0...", "1.0.0.0 - 126.255.255.255", "255.0.0.0 (/8)", "10.0.0.0/8"),
            ("CLASS B", "10...", "128.0.0.0 - 191.255.255.255", "255.255.0.0 (/16)", "172.16.0.0/12"),
            ("CLASS C", "110...", "192.0.0.0 - 223.255.255.255", "255.255.255.0 (/24)", "192.168.0.0/16"),
            ("CLASS D", "1110...", "224.0.0.0 - 239.255.255.255", "N/A (MULTICAST)", "224.0.0.0/4"),
            ("CLASS E", "1111...", "240.0.0.0 - 255.255.255.255", "N/A (EXPERIMENTAL)", "RESERVED")
        ]
        for cr in class_rows:
            class_table.add_row(*cr)
        CONSOLE.print(class_table)

    if topic not in ("OSI", "TCP", "CLASSES", "ALL"):
        error("AVAILABLE LEARNING TOPICS: OSI, TCP, CLASSES, ALL")

def cmd_quiz():
    """RUNS AN INTERACTIVE NETWORKING AND SUBNETTING QUIZ FOR STUDENTS."""
    section("STUDENT NETWORKING QUIZ LAB", symbol="::")
    questions = [
        {
            "question": "WHAT IS THE NETWORK ADDRESS FOR THE HOST 192.168.1.77 WITH SUBNET MASK 255.255.255.240 (/28)?",
            "options": ["192.168.1.64", "192.168.1.72", "192.168.1.80", "192.168.1.0"],
            "answer": "192.168.1.64",
            "explanation": "BLOCK SIZE FOR /28 IS 16 (256-240). MULTIPLES OF 16: 0, 16, 32, 48, 64, 80. 77 FALLS BETWEEN 64 AND 80, SO NETWORK IS 192.168.1.64."
        },
        {
            "question": "HOW MANY USABLE HOST ADDRESSES ARE AVAILABLE IN A /26 SUBNET?",
            "options": ["62", "64", "126", "30"],
            "answer": "62",
            "explanation": "A /26 SUBNET HAS 32 - 26 = 6 HOST BITS. 2^6 = 64 TOTAL ADDRESSES. USABLE HOSTS = 64 - 2 = 62."
        },
        {
            "question": "WHICH LAYER OF THE OSI MODEL DOES A STANDARD NETWORK ROUTER OPERATE ON?",
            "options": ["LAYER 3 (NETWORK)", "LAYER 2 (DATA LINK)", "LAYER 4 (TRANSPORT)", "LAYER 7 (APPLICATION)"],
            "answer": "LAYER 3 (NETWORK)",
            "explanation": "ROUTERS FORWARD PACKETS USING LOGICAL IP ADDRESSES AT LAYER 3 (NETWORK LAYER)."
        },
        {
            "question": "WHAT IS THE STANDARD PORT NUMBER FOR HTTPS (HTTP OVER TLS/SSL)?",
            "options": ["443", "80", "22", "8080"],
            "answer": "443",
            "explanation": "PORT 443 IS UNIVERSALLY DESIGNATED FOR HTTPS, WHILE HTTP USES PORT 80."
        },
        {
            "question": "WHICH IPV4 ADDRESS BLOCK IS DESIGNATED FOR PRIVATE NETWORKING UNDER RFC 1918 CLASS B?",
            "options": ["172.16.0.0/12", "192.168.0.0/16", "10.0.0.0/8", "169.254.0.0/16"],
            "answer": "172.16.0.0/12",
            "explanation": "CLASS B PRIVATE SPACE SPANS 172.16.0.0 THROUGH 172.31.255.255 (/12 PREFIX)."
        }
    ]

    from rich.prompt import Prompt
    score = 0
    total = len(questions)

    CONSOLE.print("[bold bright_cyan]STARTING 5-QUESTION NETWORKING ASSESSMENT... ANSWER CAREFULLY![/]\n")

    for i, q in enumerate(questions, 1):
        CONSOLE.print(f"[bold bright_yellow]QUESTION {i}/{total}:[/] [bold bright_white]{q['question']}[/]")
        for opt_idx, opt in enumerate(q["options"], 1):
            CONSOLE.print(f"  [bold cyan][{opt_idx}][/] {opt}")

        while True:
            choice = Prompt.ask("\nYOUR ANSWER (1-4)", choices=["1", "2", "3", "4"])
            selected = q["options"][int(choice) - 1]
            break

        if selected.startswith(q["answer"]):
            score += 1
            CONSOLE.print("[bold bright_green][+] CORRECT![/] " + q["explanation"] + "\n")
        else:
            CONSOLE.print(f"[bold bright_red][-] INCORRECT.[/] THE CORRECT ANSWER IS: [bold bright_green]{q['answer']}[/]")
            CONSOLE.print(f"[dim]{q['explanation']}[/]\n")

    pct = int((score / total) * 100)
    badge_style = "bold green" if pct >= 80 else ("bold yellow" if pct >= 60 else "bold red")
    summary = Panel(
        f"[bold bright_white]FINAL QUIZ SCORE:[/] [{badge_style}]{score} / {total} ({pct}%)[/]\n"
        + ("OUTSTANDING! NETWORKING CONCEPTS MASTERED." if pct >= 80 else "KEEP PRACTICING YOUR SUBNETTING AND OSI LAYERS!"),
        title="[bold bright_magenta]:: QUIZ RESULTS ::[/]",
        border_style="bright_blue",
        box=box.ROUNDED
    )
    CONSOLE.print(summary)
