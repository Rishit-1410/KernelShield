import re
import json
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


def parse_listening_sockets(output):
    """
    Convert ss output into structured socket objects.

    Process attribution is included when available.
    """

    sockets = []

    lines = output.splitlines()

    if not lines:
        return sockets

    for line in lines[1:]:

        parts = line.split()

        if len(parts) < 5:
            continue

        protocol = parts[0]
        state = parts[1]
        local_address = parts[4]

        if ":" not in local_address:
            continue

        address, port = local_address.rsplit(":", 1)

        try:
            port = int(port)
        except ValueError:
            continue

        process_name = None
        pid = None
        fd = None

        process_match = re.search(
            r'users:\(\("([^"]+)",pid=(\d+),fd=(\d+)\)\)',
            line
        )

        if process_match:

            process_name = process_match.group(1)
            pid = int(process_match.group(2))
            fd = int(process_match.group(3))

        sockets.append({
            "protocol": protocol,
            "state": state,
            "address": address,
            "port": port,
            "process": process_name,
            "pid": pid,
            "fd": fd,
        })

    return sockets

def collect_network_info(privileged=False):
    """Collect Linux network attack-surface information."""

    ss_command = [
        "ss",
        "-tulnp"
    ]

    if privileged:
        ss_command = [
            "sudo",
            "ss",
            "-tulnp"
        ]

    sockets_result = run_command(ss_command)

    interfaces = run_command([
        "ip",
        "-brief",
        "address"
    ])

    routes = run_command([
        "ip",
        "route"
    ])

    nft_rules = run_command([
        "nft",
        "list",
        "ruleset"
    ])

    iptables_rules = run_command([
        "iptables",
        "-S"
    ])

    listening_sockets = parse_listening_sockets(
        sockets_result["stdout"]
    )

    return {
        "listening_sockets": listening_sockets,

        "interfaces": interfaces["stdout"],

        "routes": routes["stdout"],

        "firewall": {
            "nftables": {
                "success": nft_rules["success"],
                "rules": nft_rules["stdout"],
                "error": nft_rules["stderr"],
            },

            "iptables": {
                "success": iptables_rules["success"],
                "rules": iptables_rules["stdout"],
                "error": iptables_rules["stderr"],
            },
        },
    }


if __name__ == "__main__":

    data = collect_network_info()

    print(json.dumps(data, indent=4))
