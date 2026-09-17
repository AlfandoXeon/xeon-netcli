import re
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.markup import escape
from rich import box

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

CONSOLE = Console(highlight=False)

# Theme Palette Tokens
PRIMARY = "bold bright_cyan"
SECONDARY = "bold bright_blue"
ACCENT = "bold bright_magenta"
SUCCESS_COLOR = "bold bright_green"
WARNING_COLOR = "bold bright_yellow"
ERROR_COLOR = "bold bright_red"
MUTED = "dim white"

ASCII_LOGO = """
██   ██ ███████  ██████  ███    ██     ███    ██ ███████ ████████        ██████ ██      ██ 
 ██ ██  ██      ██    ██ ████   ██     ████   ██ ██         ██          ██      ██      ██ 
  ███   █████   ██    ██ ██ ██  ██     ██ ██  ██ █████      ██    █████ ██      ██      ██ 
 ██ ██  ██      ██    ██ ██  ██ ██     ██  ██ ██ ██         ██          ██      ██      ██ 
██   ██ ███████  ██████  ██   ████     ██   ████ ███████    ██           ██████ ███████ ██ 
"""

def format_cell(val):
    """Safely converts text to uppercase while preserving lowercase Rich markup tags."""
    s = str(val)
    if "[" in s and "]" in s:
        upp = s.upper()
        return re.sub(r"\[/?[A-Z0-9_\-\s#]+\]", lambda m: m.group(0).lower(), upp)
    return s.upper()

def header():
    """Renders the top brand header in full uppercase."""
    logo_text = Text()
    lines = ASCII_LOGO.strip("\n").split("\n")
    colors = ["bright_cyan", "cyan", "deep_sky_blue1", "dodger_blue1"]
    for i, line in enumerate(lines):
        color = colors[i % len(colors)]
        logo_text.append(line + "\n", style=f"bold {color}")

    subtitle = Text()
    subtitle.append("XEON-NETCLI V1.1.0", style="bold bright_cyan")
    subtitle.append("  //  ", style="bold bright_blue")
    subtitle.append("ADVANCED NETWORK TOOLKIT & LEARNING LAB", style="bold bright_white")
    subtitle.append("  //  ", style="bold bright_blue")
    subtitle.append("STUDENT EDITION", style="bold bright_yellow")

    panel = Panel(
        Text.assemble(logo_text, subtitle),
        border_style="bright_blue",
        box=box.ROUNDED,
        padding=(0, 2),
        title="[bold bright_magenta]:: XEON-NETCLI COMMAND CENTER ::[/]",
        subtitle="[bold bright_cyan]HTTP://GITHUB.COM/XEON-NETCLI[/]",
        subtitle_align="right"
    )
    CONSOLE.print(panel)
    CONSOLE.print()

def breadcrumb(category, tool_name=None):
    """Renders path breadcrumb indicating user's current location."""
    t = Text()
    t.append("LOCATION: ", style="bold bright_yellow")
    t.append("MAIN MENU", style="bold bright_cyan")
    if category:
        t.append("  >>  ", style="bold bright_blue")
        t.append(str(category).upper(), style="bold bright_magenta")
    if tool_name:
        t.append("  >>  ", style="bold bright_blue")
        t.append(str(tool_name).upper(), style="bold bright_green")

    CONSOLE.print(Panel(t, border_style="bright_blue", box=box.ROUNDED, padding=(0, 2)))
    CONSOLE.print()

def status_banner(hostname, local_ip, gateway, wan_ip=None):
    """Renders a quick status bar showing current connectivity metrics."""
    t = Text()
    t.append("HOST: ", style="bold bright_cyan")
    t.append(f"{str(hostname).upper()}", style="bold bright_white")
    t.append("   |   LAN IP: ", style="bold bright_cyan")
    t.append(f"{str(local_ip or '-').upper()}", style="bold bright_green")
    t.append("   |   GATEWAY: ", style="bold bright_cyan")
    t.append(f"{str(gateway or '-').upper()}", style="bold bright_magenta")
    if wan_ip:
        t.append("   |   WAN IP: ", style="bold bright_cyan")
        t.append(f"{str(wan_ip).upper()}", style="bold bright_yellow")

    CONSOLE.print(Panel(t, border_style="dim bright_blue", box=box.ROUNDED, padding=(0, 2)))
    CONSOLE.print()

def tool_info_panel(description, usage_guide=None, expected_input=None):
    """Renders a detailed technical explanation and usage guide for sub-menus."""
    t = Text()
    t.append("[#] OVERVIEW & TECHNICAL PURPOSE:\n", style="bold bright_cyan")
    t.append(f"    {str(description).upper()}\n\n", style="bright_white")

    if usage_guide:
        t.append("[>] USAGE INSTRUCTIONS & WORKFLOW:\n", style="bold bright_yellow")
        t.append(f"    {str(usage_guide).upper()}\n", style="dim white")

    if expected_input:
        t.append("\n[*] EXPECTED PARAMETERS:\n", style="bold bright_green")
        t.append(f"    {str(expected_input).upper()}", style="dim cyan")

    CONSOLE.print(Panel(
        t,
        title="[bold bright_magenta]:: MODULE DOCUMENTATION & USAGE GUIDE ::[/]",
        border_style="bright_blue",
        box=box.ROUNDED,
        padding=(1, 2)
    ))
    CONSOLE.print()

def footer(hint="[ENTER] RETURN TO MAIN MENU  |  [R] RE-RUN TOOL  |  [0] EXIT APPLICATION"):
    """Renders a bottom navigation footer."""
    CONSOLE.print()
    t = Text(f">> CONTROLS: {str(hint).upper()}", style="bold bright_yellow")
    CONSOLE.print(Panel(t, border_style="bright_blue", box=box.ROUNDED, padding=(0, 2)))

def section(title, symbol="::"):
    CONSOLE.print()
    CONSOLE.print(Rule(f"[bold bright_cyan]{symbol}  {str(title).upper()}  {symbol}[/]", style="bright_blue"))
    CONSOLE.print()

def success(msg):
    CONSOLE.print()
    CONSOLE.print(f"[bold bright_green][+] SUCCESS:[/] [bright_white]{escape(str(msg).upper())}[/]")

def warning(msg):
    CONSOLE.print()
    CONSOLE.print(f"[bold bright_yellow][!] WARNING:[/] [bright_white]{escape(str(msg).upper())}[/]")

def error(msg):
    CONSOLE.print()
    CONSOLE.print(f"[bold bright_red][-] ERROR:[/] [bright_white]{escape(str(msg).upper())}[/]")

def info(msg):
    CONSOLE.print()
    CONSOLE.print(f"[bold bright_cyan][*] INFO:[/] [bright_white]{escape(str(msg).upper())}[/]")

def kv_table(title, rows, symbol="[#]"):
    table = Table(
        title=f"[bold bright_cyan]{symbol}  {format_cell(title)}[/]",
        title_style="bold bright_cyan",
        border_style="bright_blue",
        box=box.ROUNDED,
        header_style="bold bright_white on blue",
        padding=(0, 1),
        expand=False
    )
    table.add_column("ATTRIBUTE", style="bold bright_cyan", min_width=22)
    table.add_column("VALUE", style="bright_white", min_width=32)
    for key, value in rows:
        table.add_row(format_cell(key), format_cell(value))
    CONSOLE.print(table)

def simple_table(title, columns, rows, symbol="[#]"):
    table = Table(
        title=f"[bold bright_cyan]{symbol}  {format_cell(title)}[/]",
        title_style="bold bright_cyan",
        border_style="bright_blue",
        box=box.ROUNDED,
        header_style="bold bright_white on blue",
        padding=(0, 1),
        expand=False
    )
    for col in columns:
        table.add_column(format_cell(col), style="bright_white")
    for row in rows:
        table.add_row(*[format_cell(x) for x in row])
    CONSOLE.print(table)

def badge(text, style="green"):
    return f"[{style}] {str(text).upper()} [/{style}]"
