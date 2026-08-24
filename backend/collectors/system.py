import os
import platform
import socket
import subprocess


def run_command(command):
    """Run a read-only system command safely."""

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )

        return {
            "success": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "return_code": result.returncode,
        }

    except Exception as error:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(error),
            "return_code": -1,
        }


def get_distribution():
    """Get Linux distribution name."""

    result = run_command(
        ["bash", "-c", "source /etc/os-release && echo \"$PRETTY_NAME\""]
    )

    return result["stdout"]


def collect_system_info():
    """Collect basic Linux system information."""

    return {
        "hostname": socket.gethostname(),

        "os": {
            "system": platform.system(),
            "distribution": get_distribution(),
            "kernel": platform.release(),
            "architecture": platform.machine(),
        },

        "cpu": {
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
        },

        "python": platform.python_version(),

        "boot_time": run_command(
            ["uptime", "-s"]
        )["stdout"],
    }


if __name__ == "__main__":
    import json

    data = collect_system_info()

    print(json.dumps(data, indent=4))
