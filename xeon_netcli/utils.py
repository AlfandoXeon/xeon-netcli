import platform
import socket
import subprocess
import shutil

def run_command(command):
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=15
        )
    except Exception as exc:
        return None, str(exc)

def executable(name):
    return shutil.which(name)

def local_hostname():
    return socket.gethostname()

def os_name():
    return platform.platform()
