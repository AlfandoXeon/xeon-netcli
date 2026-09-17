import os
import socket
import sys
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt
from rich.text import Text
from rich import box

from .ui import (
    CONSOLE, header, status_banner, breadcrumb, tool_info_panel, footer,
    section, success, warning, error, info
)
from .network import interfaces, default_gateway, public_ip_info
from .commands import (
    cmd_info, cmd_interface, cmd_public_ip, cmd_ip, cmd_subnet,
    cmd_vlsm, cmd_ping, cmd_traceroute, cmd_dns, cmd_route,
    cmd_arp, cmd_connections, cmd_port, cmd_port_scan, cmd_http,
    cmd_diagnose, cmd_wifi, cmd_monitor, cmd_protocol,
    cmd_cidr_table, cmd_learn, cmd_quiz
)

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

MENU_MAP = {
    "11": ("NETWORK IDENTITY & HARDWARE", "SYSTEM & NETWORK OVERVIEW"),
    "12": ("NETWORK IDENTITY & HARDWARE", "NETWORK ADAPTERS & STATE"),
    "13": ("NETWORK IDENTITY & HARDWARE", "PUBLIC WAN IP & GEOIP"),
    "14": ("NETWORK IDENTITY & HARDWARE", "ACTIVE ROUTING TABLE"),
    "15": ("NETWORK IDENTITY & HARDWARE", "ARP CACHE INSPECTION"),
    "16": ("NETWORK IDENTITY & HARDWARE", "WIRELESS (WI-FI) TELEMETRY"),

    "21": ("IP & SUBNET CALCULATORS", "IP ADDRESS DEEP ANALYZER"),
    "22": ("IP & SUBNET CALCULATORS", "SUBNET CALCULATOR (CIDR)"),
    "23": ("IP & SUBNET CALCULATORS", "VLSM SUBNETTING CALCULATOR"),
    "24": ("IP & SUBNET CALCULATORS", "CIDR CHEAT SHEET (/0-/32)"),

    "31": ("DIAGNOSTICS & CONNECTIVITY", "FULL NETWORK HEALTH CHECK"),
    "32": ("DIAGNOSTICS & CONNECTIVITY", "ICMP PING ANALYZER"),
    "33": ("DIAGNOSTICS & CONNECTIVITY", "TRACEROUTE PATH INSPECTOR"),
    "34": ("DIAGNOSTICS & CONNECTIVITY", "DNS RESOLVER (A / AAAA)"),
    "35": ("DIAGNOSTICS & CONNECTIVITY", "HTTP / HTTPS DIAGNOSTICS"),

    "41": ("PORTS & ACTIVE TRAFFIC", "SINGLE TCP PORT CHECK"),
    "42": ("PORTS & ACTIVE TRAFFIC", "MULTI-PORT FAST SCANNER"),
    "43": ("PORTS & ACTIVE TRAFFIC", "ACTIVE TCP SOCKETS & PIDS"),
    "44": ("PORTS & ACTIVE TRAFFIC", "LIVE BANDWIDTH MONITOR"),

    "51": ("STUDENT STUDY LAB & QUIZ", "PROTOCOL & PORT DIRECTORY"),
    "52": ("STUDENT STUDY LAB & QUIZ", "OSI 7-LAYER ARCHITECTURE"),
    "53": ("STUDENT STUDY LAB & QUIZ", "TCP 3-WAY HANDSHAKE"),
    "54": ("STUDENT STUDY LAB & QUIZ", "IPV4 ADDRESS CLASSES"),
    "55": ("STUDENT STUDY LAB & QUIZ", "INTERACTIVE SUBNETTING QUIZ"),
}

TOOL_EXPLANATIONS = {
    "11": {
        "desc": "EXTRACTS SYSTEM METRICS, LOCAL HOSTNAME, OS ARCHITECTURE, ACTIVE CPU/RAM CONSUMPTION, PRIMARY LAN IP, DEFAULT GATEWAY, AND PUBLIC WAN GEOLOCATION.",
        "usage": "PROVIDES A COMPREHENSIVE OVERVIEW OF THE MACHINE'S NETWORK AND HARDWARE IDENTITY. HELPFUL TO QUICKLY CONFIRM ROUTABILITY AND SYSTEM SPECS.",
        "input": "NO PARAMETERS REQUIRED (RUNS AUTOMATICALLY)"
    },
    "12": {
        "desc": "ENUMERATES ALL NETWORK INTERFACE CARDS (NICS) ON THE SYSTEM, INCLUDING PHYSICAL ETHERNET, WIRELESS 802.11, VIRTUAL, AND LOOPBACK ADAPTERS. DISPLAYS OPERATIONAL STATUS (UP/DOWN), ASSIGNED IPV4/IPV6 ADDRESSES, HARDWARE MAC ADDRESSES, MTU SIZES, AND LINK SPEEDS.",
        "usage": "USE TO VERIFY CABLE/LINK CONNECTIVITY, LOCATE HARDWARE MAC ADDRESSES FOR STATIC DHCP BINDING, AND CONFIRM IP ASSIGNMENTS.",
        "input": "NO PARAMETERS REQUIRED (RUNS AUTOMATICALLY)"
    },
    "13": {
        "desc": "QUERIES REMOTE GEOLOCATION APIS VIA SECURE HTTP TO RESOLVE YOUR EXTERNAL PUBLIC WAN IP ADDRESS, INTERNET SERVICE PROVIDER (ISP), AUTONOMOUS SYSTEM NUMBER (ASN), AND ESTIMATED GEOGRAPHIC CITY/COUNTRY LOCATION.",
        "usage": "VERIFIES INTERNET ACCESSIBILITY, DETECTS PUBLIC ROUTABLE ADDRESSES, AND CHECKS VPN / PROXY IP INTEGRITY.",
        "input": "NO PARAMETERS REQUIRED (RUNS AUTOMATICALLY)"
    },
    "14": {
        "desc": "PARSES THE OPERATING SYSTEM'S ACTIVE IPV4 KERNEL ROUTING TABLE. REVEALS NETWORK DESTINATIONS, SUBNET MASKS, NEXT-HOP GATEWAYS, BINDING ADAPTER INTERFACES, AND METRIC PRIORITIES.",
        "usage": "CRITICAL FOR DIAGNOSING DEFAULT GATEWAY REACHABILITY, SUB-NETWORK HOP DECISIONS, AND MULTI-ADAPTER PRIORITY CONFLICTS.",
        "input": "NO PARAMETERS REQUIRED (RUNS AUTOMATICALLY)"
    },
    "15": {
        "desc": "INSPECTS THE LOCAL ADDRESS RESOLUTION PROTOCOL (ARP) CACHE TABLE, MAPPING LAYER 3 LOGICAL IP ADDRESSES TO LAYER 2 PHYSICAL HARDWARE MAC ADDRESSES DISCOVERED ON THE LOCAL SUBNET.",
        "usage": "ALLOWS YOU TO DETECT ACTIVE NEIGHBORING DEVICES (ROUTERS, SWITCHES, PCS) ON THE SAME LAN AND DIFFERENTIATES DYNAMIC FROM STATIC ALLOCATIONS.",
        "input": "NO PARAMETERS REQUIRED (RUNS AUTOMATICALLY)"
    },
    "16": {
        "desc": "RETRIEVES WIRELESS TELEMETRY FROM ACTIVE 802.11 WI-FI INTERFACES, INCLUDING CONNECTED SSID NAME, HARDWARE BSSID, RADIO TYPE (802.11AX/AC/N), AUTHENTICATION MODE, AND A VISUAL SIGNAL STRENGTH METER.",
        "usage": "DIAGNOSES WEAK WI-FI SIGNALS, DISCONNECTIONS, AND HELPS IDENTIFY THE EXACT WIRELESS ACCESS POINT IN MULTI-AP ENVIRONMENTS.",
        "input": "NO PARAMETERS REQUIRED (RUNS AUTOMATICALLY)"
    },
    "21": {
        "desc": "DECONSTRUCTS AN IP ADDRESS TO ANALYZE ITS TECHNICAL CHARACTERISTICS: VERSION (IPV4/IPV6), RFC 1918 PRIVATE OR PUBLIC ROUTABILITY, LOOPBACK, MULTICAST, INTEGER VALUE, HEXADECIMAL NOTATION, TRADITIONAL ADDRESS CLASS (A-E), AND 32-BIT BINARY OCTET FORM.",
        "usage": "ENTER ANY IP ADDRESS (E.G., 192.168.1.10 OR 10.0.0.1) TO DECONSTRUCT ITS BITS, IDENTIFY RESERVED RANGES, AND UNDERSTAND BINARY MAPPINGS.",
        "input": "TARGET IP ADDRESS [DEFAULT: 192.168.1.10]"
    },
    "22": {
        "desc": "COMPUTES ESSENTIAL SUBNET BOUNDARIES FROM A CIDR NETWORK STRING (E.G. 192.168.1.0/24). CALCULATES NETWORK ID, BROADCAST ADDRESS, SUBNET MASK, WILDCARD MASK, TOTAL IP COUNT, USABLE HOST CAPACITY, USABLE HOST IP RANGE, AND BINARY NETMASK.",
        "usage": "INPUT NETWORK IP AND PREFIX (E.G., 172.16.0.0/20 OR 10.0.0.0/22). CRUCIAL FOR NETWORK DESIGNERS, CCNA STUDENTS, AND NETWORK ADMINISTRATORS.",
        "input": "NETWORK CIDR NOTATION [DEFAULT: 192.168.1.0/24]"
    },
    "23": {
        "desc": "VARIABLE LENGTH SUBNET MASKING (VLSM) ALGORITHM DIVIDES A BASE IP NETWORK INTO MULTIPLE CUSTOM-SIZED SUBNETS BASED ON VARYING HOST REQUIREMENTS, MINIMIZING UNUSED IP ADDRESS WASTE.",
        "usage": "ENTER BASE NETWORK AND SPACE-SEPARATED HOST COUNTS SORTED AUTOMATICALLY (E.G., BASE 192.168.1.0/24 WITH HOSTS 60 30 10 2).",
        "input": "BASE CIDR AND SPACE-SEPARATED HOST REQUIREMENTS [DEFAULT: 192.168.1.0/24 // 50 25 10 2]"
    },
    "24": {
        "desc": "DISPLAYS A COMPLETE REFERENCE TABLE FOR ALL 33 IPV4 PREFIXES (/0 THROUGH /32), INCLUDING SUBNET MASKS, WILDCARDS, TOTAL IP CAPACITY, USABLE HOSTS, AND COMMON INDUSTRY USE-CASES.",
        "usage": "EXCELLENT CHEAT SHEET FOR EXAMS, QUICK LOOKUPS DURING CONFIGURATION, AND UNDERSTANDING POWERS OF TWO IN IPV4 SUBNETTING.",
        "input": "NO PARAMETERS REQUIRED (RUNS AUTOMATICALLY)"
    },
    "31": {
        "desc": "EXECUTES AN END-TO-END 4-TIER DIAGNOSTIC PIPELINE TO IDENTIFY CONNECTIVITY BOTTLENECKS: 1) LOCAL LAN ADAPTER, 2) DEFAULT GATEWAY REACHABILITY, 3) DNS NAME RESOLUTION, AND 4) REMOTE ICMP INTERNET REACHABILITY.",
        "usage": "INPUT A DESTINATION DOMAIN (DEFAULT: GOOGLE.COM) TO QUICKLY PINPOINT WHETHER A PROBLEM LIES IN HARDWARE, ROUTER, DNS, OR WAN.",
        "input": "TARGET DOMAIN OR IP [DEFAULT: GOOGLE.COM]"
    },
    "32": {
        "desc": "TRANSMITS INTERNET CONTROL MESSAGE PROTOCOL (ICMP) ECHO REQUEST PACKETS TO A TARGET HOST, MEASURING ROUND-TRIP TIME (RTT), DETECTING PACKET LOSS PERCENTAGES, AND ASSESSING CONNECTION LATENCY STABILITY.",
        "usage": "ENTER TARGET HOST OR IP AND NUMBER OF PACKETS TO TRANSMIT. ESSENTIAL FOR DETECTING JITTER, DROPPED PACKETS, OR UNSTABLE LINKS.",
        "input": "TARGET HOST AND PACKET COUNT [DEFAULT: GOOGLE.COM // 4 PACKETS]"
    },
    "33": {
        "desc": "TRACES THE ROUTE PACKETS TAKE ACROSS THE INTERNET TO REACH A REMOTE TARGET BY INCREMENTING TIME-TO-LIVE (TTL) VALUES, REVEALING EACH INTERMEDIATE HOP ROUTER AND ITS RESPECTIVE LATENCY.",
        "usage": "ENTER TARGET HOST OR IP (E.G., 1.1.1.1) AND MAXIMUM HOP COUNT (DEFAULT: 15). PINPOINTS EXACT ROUTER DELAYS OR WAN DROPS.",
        "input": "TARGET HOST AND MAX HOP COUNT [DEFAULT: 1.1.1.1 // 15 HOPS]"
    },
    "34": {
        "desc": "PERFORMS DOMAIN NAME SYSTEM (DNS) RESOLUTION QUERIES, TRANSLATING HUMAN-READABLE DOMAIN NAMES INTO RESOLVED IPV4 (A) AND IPV6 (AAAA) ADDRESSES.",
        "usage": "ENTER ANY DOMAIN NAME (E.G., GOOGLE.COM, CLOUDFLARE.COM) TO INSPECT RESOLVED IP ADDRESSES AND TEST LOCAL DNS RESOLVERS.",
        "input": "TARGET DOMAIN NAME [DEFAULT: GOOGLE.COM]"
    },
    "35": {
        "desc": "ISSUES AN APPLICATION-LAYER HTTP/HTTPS REQUEST TO A REMOTE WEB SERVER, MEASURING TOTAL ROUND-TRIP TIME, REPORTING HTTP STATUS CODES, REDIRECT TARGETS, CONTENT HEADERS, AND SERVER DAEMONS.",
        "usage": "ENTER TARGET URL (E.G. HTTPS://GOOGLE.COM). DIAGNOSES WEB SERVICE AVAILABILITY, SSL/TLS HANDSHAKES, AND HEADER CONFIGURATIONS.",
        "input": "TARGET URL [DEFAULT: HTTPS://GOOGLE.COM]"
    },
    "41": {
        "desc": "ATTEMPTS A THREE-WAY TCP CONNECTION TO A SPECIFIC PORT ON A TARGET HOST TO DETERMINE IF THE APPLICATION SERVICE IS OPEN AND LISTENING, CLOSED, OR BLOCKED BY A FIREWALL.",
        "usage": "ENTER TARGET IP OR HOSTNAME AND PORT NUMBER (1-65535). MEASURES EXACT SOCKET LATENCY IN MILLISECONDS.",
        "input": "TARGET HOST AND TCP PORT NUMBER [DEFAULT: 127.0.0.1 // PORT 80]"
    },
    "42": {
        "desc": "HIGH-SPEED MULTI-THREADED PORT SCANNER EQUIPPED WITH A PROGRESS TELEMETRY BAR. AUDITS EITHER THE TOP 25 COMMON NETWORK SERVICES (SSH, HTTP, HTTPS, MYSQL, RDP, ETC.) OR USER-DEFINED PORTS CONCURRENTLY.",
        "usage": "CHOOSE 'TOP' TO AUDIT POPULAR PORTS OR 'CUSTOM' TO SPECIFY PORTS SEPARATED BY COMMAS (E.G. 21, 22, 80, 443, 8080).",
        "input": "TARGET HOST AND SCAN MODE (TOP / CUSTOM) [DEFAULT: 127.0.0.1]"
    },
    "43": {
        "desc": "INSPECTS ALL ACTIVE TRANSMISSION CONTROL PROTOCOL (TCP) CONNECTIONS ON THE SYSTEM, PROVIDING DETAILED MAPPINGS OF LOCAL SOCKETS, REMOTE SOCKETS, TCP STATES (ESTABLISHED, LISTEN, TIME_WAIT), AND OWNER PROCESS NAMES (PIDS).",
        "usage": "HELPS DETECT UNAUTHORIZED BACKGROUND SERVERS, SUSPICIOUS OUTBOUND SESSIONS, OR LEAKED UNCLOSED SOCKETS.",
        "input": "NO PARAMETERS REQUIRED (RUNS AUTOMATICALLY)"
    },
    "44": {
        "desc": "REAL-TIME BANDWIDTH MONITOR DISPLAYING INSTANTANEOUS RX (DOWNLOAD) AND TX (UPLOAD) TRANSFER SPEEDS AND CUMULATIVE PACKET COUNTERS WITH DYNAMIC UNIT SCALING (B/S, KB/S, MB/S).",
        "usage": "MONITORS CURRENT DATA THROUGHPUT LIVE IN THE CONSOLE. PRESS CTRL+C AT ANY TIME TO STOP AND RETURN.",
        "input": "SAMPLING INTERVAL IN SECONDS [DEFAULT: 1.0 SECONDS]"
    },
    "51": {
        "desc": "SEARCHABLE DIRECTORY OF STANDARD IANA ASSIGNED PORT NUMBERS, TRANSPORT PROTOCOLS (TCP/UDP), AND SERVICE PURPOSES.",
        "usage": "ENTER A PORT NUMBER (E.G., 443) OR SERVICE KEYWORD (E.G., SSH, DNS, HTTP, MYSQL) TO LOOK UP DETAILS.",
        "input": "PORT NUMBER OR SERVICE NAME KEYWORD [DEFAULT: 443]"
    },
    "52": {
        "desc": "COMPREHENSIVE EDUCATIONAL REFERENCE OF THE OPEN SYSTEMS INTERCONNECTION (OSI) 7-LAYER ARCHITECTURE, DETAILING LAYER FUNCTIONS, PROTOCOL DATA UNITS (PDUS: BITS, FRAMES, PACKETS, SEGMENTS, DATA), AND PROTOCOLS.",
        "usage": "STUDY GUIDE FOR NETWORK STUDENTS PREPARING FOR EXAMS (CCNA, NETWORK+, ACADEMIC ASSESSMENTS).",
        "input": "NO PARAMETERS REQUIRED (RUNS AUTOMATICALLY)"
    },
    "53": {
        "desc": "VISUAL GUIDE AND PACKET FLAG SEQUENCE FOR THE TCP THREE-WAY HANDSHAKE (SYN -> SYN/ACK -> ACK) USED TO ESTABLISH RELIABLE CONNECTION-ORIENTED TRANSPORT SESSIONS.",
        "usage": "HELPS STUDENTS MASTER HOW INITIAL SEQUENCE NUMBERS (ISN) ARE SYNCHRONIZED AND ACKNOWLEDGED.",
        "input": "NO PARAMETERS REQUIRED (RUNS AUTOMATICALLY)"
    },
    "54": {
        "desc": "ARCHITECTURAL OVERVIEW OF TRADITIONAL CLASSFUL IPV4 NETWORKING (CLASSES A, B, C, D, E), LEADING BIT PATTERNS, DEFAULT NETMASKS, AND RFC 1918 PRIVATE RESERVED BLOCKS.",
        "usage": "STUDY AID FOR MEMORIZING CLASS BOUNDARIES AND PRIVATE ADDRESS RANGES.",
        "input": "NO PARAMETERS REQUIRED (RUNS AUTOMATICALLY)"
    },
    "55": {
        "desc": "INTERACTIVE 5-QUESTION NETWORKING QUIZ COVERING SUBNET CALCULATIONS, CIDR MASKS, USABLE HOSTS, OSI LAYERS, AND PORT NUMBERS WITH REAL-TIME EVALUATION AND DETAILED EXPLANATIONS.",
        "usage": "ENTER NUMERIC ANSWERS (1-4) FOR EACH QUESTION. AT THE END, RECEIVE YOUR FINAL SCORE AND PERFORMANCE ASSESSMENT.",
        "input": "INTERACTIVE MULTIPLE CHOICE (1-4)"
    }
}

ALIAS_MAP = {
    "INFO": "11",
    "INTERFACE": "12", "IF": "12",
    "PUBLICIP": "13", "WAN": "13",
    "ROUTE": "14", "ROUTING": "14",
    "ARP": "15",
    "WIFI": "16",
    "IP": "21",
    "SUBNET": "22",
    "VLSM": "23",
    "CIDR": "24",
    "DIAGNOSE": "31", "DIAG": "31",
    "PING": "32",
    "TRACE": "33", "TRACEROUTE": "33",
    "DNS": "34",
    "HTTP": "35",
    "PORT": "41",
    "SCAN": "42", "PORTSCAN": "42",
    "CONNECTIONS": "43", "CONN": "43",
    "MONITOR": "44",
    "PROTOCOL": "51", "PROTO": "51",
    "OSI": "52",
    "TCP": "53",
    "CLASSES": "54",
    "QUIZ": "55"
}

def render_main_dashboard():
    """BUILDS THE FULL UPPERCASE DASHBOARD WITH NO EMOJIS AND CLEAN UNDERSCORE SEPARATORS."""
    table = Table(
        box=box.ROUNDED,
        border_style="bright_blue",
        show_header=True,
        header_style="bold bright_white on blue",
        expand=True,
        padding=(0, 1)
    )
    table.add_column("CODE", style="bold bright_cyan", justify="center", width=8)
    table.add_column("TOOL / FEATURE", style="bold bright_white", width=32)
    table.add_column("DESCRIPTION / UTILITY", style="dim white")

    # CATEGORY 1
    table.add_row("[bold bright_magenta]__[/]", "[bold bright_magenta][+] 1. NETWORK IDENTITY & HARDWARE[/]", "[bold bright_magenta]________________________________[/]")
    table.add_row("11", "SYSTEM & NETWORK OVERVIEW", "HOST, OS, GATEWAY, LAN/WAN IP AND HARDWARE SPECS")
    table.add_row("12", "NETWORK ADAPTERS & STATE", "INTERFACE CARDS, IPV4, IPV6, MAC, MTU & SPEED")
    table.add_row("13", "PUBLIC WAN IP & GEOIP", "EXTERNAL WAN IP, ISP ORGANIZATION & GEOLOCATION")
    table.add_row("14", "ACTIVE ROUTING TABLE", "IPV4 ACTIVE ROUTING ROUTES, GATEWAY & METRICS")
    table.add_row("15", "ARP CACHE INSPECTION", "IP-TO-MAC ADDRESS MAPPING TABLE (DYNAMIC/STATIC)")
    table.add_row("16", "WIRELESS (WI-FI) TELEMETRY", "SIGNAL STRENGTH METER, SSID, BSSID & RADIO MODE")

    # CATEGORY 2
    table.add_row("[bold bright_magenta]__[/]", "[bold bright_magenta][+] 2. IP & SUBNET CALCULATORS[/]", "[bold bright_magenta]________________________________[/]")
    table.add_row("21", "IP ADDRESS DEEP ANALYZER", "CLASS, BINARY BITS, PUBLIC/PRIVATE, LOOPBACK CHECKS")
    table.add_row("22", "SUBNET CALCULATOR (CIDR)", "NETMASK, WILDCARD, USABLE HOSTS, BROADCAST & RANGE")
    table.add_row("23", "VLSM SUBNETTING CALCULATOR", "ZERO-WASTE VARIABLE LENGTH SUBNET ALLOCATION PLAN")
    table.add_row("24", "CIDR CHEAT SHEET (/0-/32)", "COMPLETE REFERENCE OF SUBNET MASKS & HOST CAPACITIES")

    # CATEGORY 3
    table.add_row("[bold bright_magenta]__[/]", "[bold bright_magenta][+] 3. DIAGNOSTICS & CONNECTIVITY[/]", "[bold bright_magenta]________________________________[/]")
    table.add_row("31", "FULL NETWORK HEALTH CHECK", "END-TO-END DIAGNOSIS (LAN, GATEWAY, DNS, PING)")
    table.add_row("32", "ICMP PING ANALYZER", "PACKET LOSS ANALYSIS AND ROUND-TRIP LATENCY METRICS")
    table.add_row("33", "TRACEROUTE PATH INSPECTOR", "HOP-BY-HOP PACKET ROUTING AND ROUTER LATENCY TRACE")
    table.add_row("34", "DNS RESOLVER (A / AAAA)", "RESOLVE HOSTNAMES AND DOMAIN IP ADDRESSES")
    table.add_row("35", "HTTP / HTTPS DIAGNOSTICS", "RESPONSE STATUS, HEADERS, LATENCY AND TLS CHECK")

    # CATEGORY 4
    table.add_row("[bold bright_magenta]__[/]", "[bold bright_magenta][+] 4. PORTS & ACTIVE TRAFFIC[/]", "[bold bright_magenta]________________________________[/]")
    table.add_row("41", "SINGLE TCP PORT CHECK", "PROBE INDIVIDUAL PORT LISTENING STATE AND RESPONSE")
    table.add_row("42", "MULTI-PORT FAST SCANNER", "CONCURRENT SCAN OF TOP 25 POPULAR NETWORK SERVICES")
    table.add_row("43", "ACTIVE TCP SOCKETS & PIDS", "LIST ESTABLISHED & LISTENING SOCKETS WITH PROCESS NAME")
    table.add_row("44", "LIVE BANDWIDTH MONITOR", "REAL-TIME DOWNLOAD/UPLOAD SPEED METER (CTRL+C STOP)")

    # CATEGORY 5
    table.add_row("[bold bright_magenta]__[/]", "[bold bright_magenta][+] 5. STUDENT STUDY LAB & QUIZ[/]", "[bold bright_magenta]________________________________[/]")
    table.add_row("51", "PROTOCOL & PORT DIRECTORY", "SEARCH COMMON NETWORK PORT NUMBERS AND SERVICES")
    table.add_row("52", "OSI 7-LAYER ARCHITECTURE", "COMPREHENSIVE LAYER STUDY GUIDE (PDUS & PROTOCOLS)")
    table.add_row("53", "TCP 3-WAY HANDSHAKE", "VISUAL PACKET FLAG SEQUENCE (SYN, SYN/ACK, ACK)")
    table.add_row("54", "IPV4 ADDRESS CLASSES", "CLASS A, B, C, D, E DEFINITIONS AND RFC 1918 BLOCKS")
    table.add_row("55", "INTERACTIVE SUBNETTING QUIZ", "PRACTICE QUESTIONS ON CIDR, HOSTS AND NETWORKING")

    # CONTROLS
    table.add_row("[bold bright_red]__[/]", "[bold bright_red][*] SYSTEM CONTROLS[/]", "[bold bright_red]________________________________[/]")
    table.add_row("CLS", "CLEAR TERMINAL SCREEN", "REFRESH THE TERMINAL WORKSPACE")
    table.add_row("0", "EXIT XEON-NETCLI", "CLOSE AND TERMINATE THE APPLICATION")

    CONSOLE.print(table)

def execute_sub_tool(code):
    """EXECUTES A SPECIFIC TOOL WITH CLEAR SCREEN, HEADER, BREADCRUMB, EXPLANATION AND FOOTER."""
    code = ALIAS_MAP.get(code, code)
    if code not in MENU_MAP:
        warning(f"UNKNOWN TOOL CODE: '{code}'")
        return "continue"

    category, tool_name = MENU_MAP[code]
    exp = TOOL_EXPLANATIONS.get(code, {
        "desc": "PERFORMS THE REQUESTED NETWORK UTILITY OPERATION.",
        "usage": "FOLLOW THE PROMPTED INSTRUCTIONS TO EXECUTE.",
        "input": "AS PROMPTED"
    })

    def run_tool():
        clear_screen()
        header()
        breadcrumb(category, tool_name)
        tool_info_panel(exp["desc"], exp["usage"], exp["input"])

        if code == "11":
            cmd_info()
        elif code == "12":
            cmd_interface()
        elif code == "13":
            cmd_public_ip()
        elif code == "14":
            cmd_route()
        elif code == "15":
            cmd_arp()
        elif code == "16":
            cmd_wifi()

        elif code == "21":
            addr = Prompt.ask("[bold cyan]ENTER IP ADDRESS TO ANALYZE[/]", default="192.168.1.10")
            CONSOLE.print()
            cmd_ip(addr)
        elif code == "22":
            net = Prompt.ask("[bold cyan]ENTER NETWORK ADDRESS IN CIDR FORMAT[/]", default="192.168.1.0/24")
            CONSOLE.print()
            cmd_subnet(net)
        elif code == "23":
            net = Prompt.ask("[bold cyan]ENTER BASE NETWORK CIDR[/]", default="192.168.1.0/24")
            req_input = Prompt.ask("[bold cyan]ENTER NEEDED HOST COUNTS SEPARATED BY SPACES[/]", default="50 25 10 2")
            hosts = [int(x) for x in req_input.split() if x.isdigit()]
            CONSOLE.print()
            if not hosts:
                error("PLEASE PROVIDE VALID INTEGER HOST REQUIREMENTS.")
            else:
                cmd_vlsm(net, hosts)
        elif code == "24":
            cmd_cidr_table()

        elif code == "31":
            target = Prompt.ask("[bold cyan]TARGET HOST TO DIAGNOSE[/]", default="google.com")
            CONSOLE.print()
            cmd_diagnose(target)
        elif code == "32":
            host = Prompt.ask("[bold cyan]TARGET HOSTNAME OR IP TO PING[/]", default="google.com")
            count = IntPrompt.ask("[bold cyan]NUMBER OF ICMP PACKETS[/]", default=4)
            CONSOLE.print()
            cmd_ping(host, count)
        elif code == "33":
            host = Prompt.ask("[bold cyan]TARGET HOSTNAME OR IP TO TRACE[/]", default="1.1.1.1")
            hops = IntPrompt.ask("[bold cyan]MAX HOPS TO TRACE[/]", default=15)
            CONSOLE.print()
            cmd_traceroute(host, hops)
        elif code == "34":
            host = Prompt.ask("[bold cyan]HOSTNAME TO RESOLVE[/]", default="google.com")
            CONSOLE.print()
            cmd_dns(host)
        elif code == "35":
            url = Prompt.ask("[bold cyan]URL TO TEST[/]", default="https://google.com")
            CONSOLE.print()
            cmd_http(url)

        elif code == "41":
            host = Prompt.ask("[bold cyan]TARGET HOST[/]", default="127.0.0.1")
            p = IntPrompt.ask("[bold cyan]TCP PORT NUMBER[/]", default=80)
            CONSOLE.print()
            cmd_port(host, p)
        elif code == "42":
            host = Prompt.ask("[bold cyan]TARGET HOST TO SCAN[/]", default="127.0.0.1")
            custom = Prompt.ask("[bold cyan]SCAN POPULAR TOP 25 PORTS OR CUSTOM? (TOP/CUSTOM)[/]", default="TOP", choices=["TOP", "CUSTOM"])
            CONSOLE.print()
            if custom.upper() == "CUSTOM":
                p_input = Prompt.ask("[bold cyan]ENTER PORTS SEPARATED BY COMMAS/SPACES[/]", default="21, 22, 80, 443, 8080")
                parsed_ports = [int(x) for x in p_input.replace(",", " ").split() if x.isdigit()]
                CONSOLE.print()
                cmd_port_scan(host, parsed_ports)
            else:
                cmd_port_scan(host)
        elif code == "43":
            cmd_connections()
        elif code == "44":
            cmd_monitor()

        elif code == "51":
            query = Prompt.ask("[bold cyan]ENTER PORT NUMBER OR SERVICE NAME TO LOOKUP[/]", default="443")
            CONSOLE.print()
            cmd_protocol(query)
        elif code == "52":
            cmd_learn("OSI")
        elif code == "53":
            cmd_learn("TCP")
        elif code == "54":
            cmd_learn("CLASSES")
        elif code == "55":
            cmd_quiz()

        footer("[ENTER] RETURN TO MAIN MENU  |  [R] RE-RUN TOOL  |  [0] EXIT APPLICATION")

    # Initial Run
    run_tool()

    # Action prompt loop
    while True:
        prompt_next = Prompt.ask(
            "\n[bold bright_cyan]COMMAND ❯[/]",
            default=""
        ).strip().upper()

        if prompt_next == "0":
            return "exit"
        elif prompt_next == "R":
            run_tool()
        else:
            # Enter or anything else -> Return to main menu
            return "menu"

def interactive_menu():
    """RUNS THE MAIN INTERACTIVE TERMINAL MENU LOOP."""
    while True:
        clear_screen()
        header()

        # Quick status banner
        hostname = socket.gethostname()
        gw = default_gateway()
        ifaces = interfaces()
        up = [x["ipv4"] for x in ifaces if x["status"] == "UP" and x["ipv4"] != "-"]
        primary_ip = up[0] if up else "-"
        status_banner(hostname, primary_ip, gw)

        breadcrumb("MAIN DASHBOARD")
        render_main_dashboard()
        footer("[CODE] SELECT TOOL (E.G. 11, 22, 32)  |  [CLS] CLEAR SCREEN  |  [0] EXIT APPLICATION")

        try:
            choice = Prompt.ask("\n[bold bright_cyan]XEON-NETCLI ❯ SELECT TOOL CODE[/]", default="11").strip().upper()
        except (KeyboardInterrupt, EOFError):
            CONSOLE.print("\n[bold bright_yellow][!] EXITING XEON-NETCLI... GOODBYE![/]")
            break

        if choice in ("0", "EXIT", "QUIT", "Q"):
            CONSOLE.print("\n[bold bright_cyan][+] THANK YOU FOR USING XEON-NETCLI! GOODBYE.[/]")
            break
        elif choice in ("CLS", "CLEAR"):
            continue

        res = execute_sub_tool(choice)
        if res == "exit":
            CONSOLE.print("\n[bold bright_cyan][+] THANK YOU FOR USING XEON-NETCLI! GOODBYE.[/]")
            break
