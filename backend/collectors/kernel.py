
import json
import os
import platform
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


def get_loaded_modules():
    """Collect currently loaded Linux kernel modules."""

    result = run_command(["lsmod"])

    if not result["success"]:
        return []

    modules = []

    lines = result["stdout"].splitlines()

    # Skip header
    for line in lines[1:]:
        parts = line.split()

        if len(parts) >= 3:
            modules.append({
                "name": parts[0],
                "size": int(parts[1]),
                "used_by": parts[2:],
            })

    return modules


def get_kernel_interfaces():
    """Collect available /sys/kernel interfaces."""

    kernel_path = "/sys/kernel"

    try:
        return sorted(os.listdir(kernel_path))
    except PermissionError:
        return []


def get_kernel_command_line():
    """Read the Linux kernel boot command line."""

    try:
        with open("/proc/cmdline", "r") as file:
            return file.read().strip()
    except (PermissionError, FileNotFoundError):
        return ""


def collect_kernel_info():
    """Collect kernel-related security information."""

    modules = get_loaded_modules()

    return {
        "kernel": {
            "version": platform.release(),
            "architecture": platform.machine(),
            "command_line": get_kernel_command_line(),
        },

        "modules": {
            "loaded_count": len(modules),
            "loaded": modules,
        },

        "interfaces": {
            "sys_kernel": get_kernel_interfaces(),
        },
    }


if __name__ == "__main__":

    data = collect_kernel_info()

    print(json.dumps(data, indent=4))
