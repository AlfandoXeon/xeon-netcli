import sys

# Ensure UTF-8 console output for Windows cmd and PowerShell
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from xeon_netcli.cli import app

if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        print("\nXeon-NetCLI terminated.")
