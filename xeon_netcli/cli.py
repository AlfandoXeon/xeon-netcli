import argparse
import sys
from .ui import header, error, CONSOLE
from .menu import interactive_menu
from .commands import (
    cmd_info, cmd_interface, cmd_public_ip, cmd_ip, cmd_subnet,
    cmd_vlsm, cmd_ping, cmd_traceroute, cmd_dns, cmd_route,
    cmd_arp, cmd_connections, cmd_port, cmd_port_scan, cmd_http,
    cmd_diagnose, cmd_wifi, cmd_monitor, cmd_protocol,
    cmd_cidr_table, cmd_learn, cmd_quiz
)

def build_parser():
    parser = argparse.ArgumentParser(
        prog="xeon-netcli",
        description=":: XEON-NETCLI: ADVANCED PYTHON NETWORK TOOLKIT & LEARNING LAB ::",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", help="AVAILABLE COMMANDS (OR RUN WITHOUT ARGUMENTS FOR INTERACTIVE MENU)")

    # MENU
    sub.add_parser("menu", help="LAUNCH INTERACTIVE TERMINAL DASHBOARD MENU")

    # NETWORK IDENTITY & HARDWARE
    sub.add_parser("info", help="DISPLAY HOST, OS AND NETWORK SUMMARY")
    sub.add_parser("interface", aliases=["if"], help="LIST ALL NETWORK ADAPTERS WITH IP/MAC")
    sub.add_parser("publicip", aliases=["wan"], help="SHOW EXTERNAL WAN IP, ISP & GEOIP LOCATION")
    sub.add_parser("route", help="DISPLAY IPV4 ACTIVE ROUTING TABLE")
    sub.add_parser("arp", help="DISPLAY SYSTEM ARP CACHE TABLE")
    sub.add_parser("wifi", help="SHOW WI-FI ADAPTER TELEMETRY & SIGNAL METRICS")

    # IP & SUBNET CALCULATORS
    p_ip = sub.add_parser("ip", help="ANALYZE IPV4/IPV6 ADDRESS CHARACTERISTICS")
    p_ip.add_argument("address", help="TARGET IP ADDRESS (E.G. 192.168.1.10)")

    p_subnet = sub.add_parser("subnet", help="CALCULATE SUBNET PARAMETERS FROM CIDR")
    p_subnet.add_argument("network", help="NETWORK CIDR (E.G. 192.168.1.0/24)")

    p_vlsm = sub.add_parser("vlsm", help="CALCULATE VARIABLE LENGTH SUBNET MASKING (VLSM)")
    p_vlsm.add_argument("network", help="BASE NETWORK CIDR (E.G. 192.168.1.0/24)")
    p_vlsm.add_argument("hosts", nargs="+", type=int, help="HOST COUNTS NEEDED PER SUBNET (E.G. 60 30 20 10)")

    sub.add_parser("cidr", help="DISPLAY IPV4 CIDR PREFIX (/0 - /32) REFERENCE SHEET")

    # DIAGNOSTICS & TESTS
    p_diag = sub.add_parser("diagnose", aliases=["diag"], help="PERFORM COMPREHENSIVE NETWORK HEALTH TEST")
    p_diag.add_argument("host", nargs="?", default="google.com", help="TARGET HOST (DEFAULT: GOOGLE.COM)")

    p_ping = sub.add_parser("ping", help="PING TARGET HOST WITH ICMP ECHO REQUESTS")
    p_ping.add_argument("host", help="TARGET HOSTNAME OR IP")
    p_ping.add_argument("-c", "--count", type=int, default=4, help="NUMBER OF PACKETS (DEFAULT: 4)")

    p_trace = sub.add_parser("trace", aliases=["traceroute"], help="TRACE HOP ROUTE TO REMOTE HOST")
    p_trace.add_argument("host", help="TARGET HOSTNAME OR IP")
    p_trace.add_argument("-m", "--max-hops", type=int, default=15, help="MAXIMUM NUMBER OF HOPS (DEFAULT: 15)")

    p_dns = sub.add_parser("dns", help="RESOLVE DNS RECORDS FOR A DOMAIN")
    p_dns.add_argument("host", help="HOSTNAME / DOMAIN (E.G. GOOGLE.COM)")
    p_dns.add_argument("-t", "--type", default="A", help="DNS RECORD TYPE (DEFAULT: A)")

    p_http = sub.add_parser("http", help="PERFORM HTTP/HTTPS DIAGNOSTIC REQUEST")
    p_http.add_argument("url", help="TARGET URL (E.G. HTTPS://GOOGLE.COM)")

    # PORTS & TRAFFIC
    p_port = sub.add_parser("port", help="CHECK INDIVIDUAL TCP PORT CONNECTIVITY")
    p_port.add_argument("host", help="TARGET HOSTNAME OR IP")
    p_port.add_argument("port", type=int, help="TCP PORT NUMBER (1-65535)")

    p_scan = sub.add_parser("scan", aliases=["portscan"], help="FAST MULTI-PORT SCANNER FOR POPULAR SERVICES")
    p_scan.add_argument("host", help="TARGET HOSTNAME OR IP")
    p_scan.add_argument("-p", "--ports", nargs="+", type=int, help="OPTIONAL CUSTOM PORT LIST TO SCAN")

    sub.add_parser("connections", aliases=["conn"], help="INSPECT ACTIVE TCP CONNECTIONS AND PROCESSES")

    p_mon = sub.add_parser("monitor", help="MONITOR LIVE BANDWIDTH THROUGHPUT IN REAL-TIME")
    p_mon.add_argument("-i", "--interval", type=float, default=1.0, help="SAMPLING INTERVAL IN SECONDS")

    # LEARNING & REFERENCES
    p_proto = sub.add_parser("protocol", help="LOOKUP STANDARD PORT NUMBERS OR SERVICE NAMES")
    p_proto.add_argument("query", help="PORT NUMBER (E.G. 443) OR SERVICE NAME (E.G. SSH)")

    p_learn = sub.add_parser("learn", help="STUDY NETWORKING CONCEPTS (OSI, TCP, CLASSES, ALL)")
    p_learn.add_argument("topic", nargs="?", default="OSI", help="TOPIC TO EXPLORE: OSI, TCP, CLASSES, ALL")

    sub.add_parser("quiz", help="INTERACTIVE NETWORKING STUDENT QUIZ")

    return parser

def app():
    # IF NO ARGUMENTS PROVIDED, LAUNCH INTERACTIVE MENU DIRECTLY
    if len(sys.argv) == 1:
        interactive_menu()
        return

    raw_args = sys.argv[1:]
    if raw_args and not raw_args[0].startswith("-"):
        raw_args[0] = raw_args[0].lower()

    parser = build_parser()
    try:
        args = parser.parse_args(raw_args)
    except SystemExit:
        return

    if not args.command or args.command == "menu":
        interactive_menu()
        return

    header()

    cmd = args.command.lower()
    commands = {
        "info": lambda: cmd_info(),
        "interface": lambda: cmd_interface(),
        "if": lambda: cmd_interface(),
        "publicip": lambda: cmd_public_ip(),
        "wan": lambda: cmd_public_ip(),
        "route": lambda: cmd_route(),
        "arp": lambda: cmd_arp(),
        "wifi": lambda: cmd_wifi(),
        "ip": lambda: cmd_ip(args.address),
        "subnet": lambda: cmd_subnet(args.network),
        "vlsm": lambda: cmd_vlsm(args.network, args.hosts),
        "cidr": lambda: cmd_cidr_table(),
        "diagnose": lambda: cmd_diagnose(args.host),
        "diag": lambda: cmd_diagnose(args.host),
        "ping": lambda: cmd_ping(args.host, args.count),
        "trace": lambda: cmd_traceroute(args.host, args.max_hops),
        "traceroute": lambda: cmd_traceroute(args.host, args.max_hops),
        "dns": lambda: cmd_dns(args.host, args.type),
        "http": lambda: cmd_http(args.url),
        "port": lambda: cmd_port(args.host, args.port),
        "scan": lambda: cmd_port_scan(args.host, args.ports),
        "portscan": lambda: cmd_port_scan(args.host, args.ports),
        "connections": lambda: cmd_connections(),
        "conn": lambda: cmd_connections(),
        "monitor": lambda: cmd_monitor(args.interval),
        "protocol": lambda: cmd_protocol(args.query),
        "learn": lambda: cmd_learn(args.topic),
        "quiz": lambda: cmd_quiz(),
    }

    try:
        if cmd in commands:
            commands[cmd]()
        else:
            parser.print_help()
    except KeyboardInterrupt:
        CONSOLE.print("\n[bold bright_yellow][!] OPERATION CANCELLED BY USER.[/]")
    except Exception as exc:
        error(f"UNEXPECTED ERROR: {exc}")
