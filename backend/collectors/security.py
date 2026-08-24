

import json
import os
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


def check_service(service):
    """Check whether a systemd service is active."""

    result = run_command([
        "systemctl",
        "is-active",
        service
    ])

    return result["stdout"]


def get_apparmor_status():
    """Check AppArmor status."""

    result = run_command([
        "aa-status"
    ])

    return {
        "available": result["success"],
        "output": result["stdout"],
    }


def get_selinux_status():
    """Check SELinux status."""

    result = run_command([
        "getenforce"
    ])

    return {
        "available": result["success"],
        "status": result["stdout"],
    }


def get_firewall_status():
    """Collect firewall backend information."""

    nft = run_command([
        "nft",
        "list",
        "ruleset"
    ])

    iptables = run_command([
        "iptables",
        "-S"
    ])

    return {
        "nftables": {
            "available": nft["success"],
            "rules": nft["stdout"],
        },
        "iptables": {
            "available": iptables["success"],
            "rules": iptables["stdout"],
        },
    }


def get_security_sysctls():
    """Collect selected security-relevant kernel parameters."""

    parameters = [
        "kernel.randomize_va_space",
        "kernel.kptr_restrict",
        "kernel.dmesg_restrict",
        "kernel.unprivileged_bpf_disabled",
        "kernel.yama.ptrace_scope",
    ]

    results = {}

    for parameter in parameters:

        result = run_command([
            "sysctl",
            "-n",
            parameter
        ])

        results[parameter] = (
            result["stdout"]
            if result["success"]
            else None
        )

    return results


def collect_security_info():

    return {
        "apparmor": get_apparmor_status(),

        "selinux": get_selinux_status(),

        "services": {
            "auditd": check_service("auditd"),
        },

        "firewall": get_firewall_status(),

        "kernel_security_parameters": get_security_sysctls(),
    }


if __name__ == "__main__":

    data = collect_security_info()

    print(json.dumps(data, indent=4))
