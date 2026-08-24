from dataclasses import dataclass
import re


@dataclass
class AttackPath:
    path_id: str
    title: str
    severity: str
    confidence: str
    stages: list
    evidence: list
    explanation: str
    recommendation: str


def parse_capability_entry(entry):
    """
    Parse a getcap-style capability entry.

    Example:
        /usr/bin/dumpcap cap_net_admin,cap_net_raw=eip
    """

    match = re.match(
        r"^(\S+)\s+(.+?)=([a-zA-Z]+)$",
        entry.strip()
    )

    if not match:
        return None

    executable = match.group(1)
    capabilities = match.group(2).split(",")

    return {
        "executable": executable,
        "capabilities": capabilities,
    }


def find_network_root_process_paths(scan):
    """
    Detect potential attack paths where a network-exposed
    listening service is attributed to a root-owned process.
    """

    sockets = (
        scan
        .get("network", {})
        .get("listening_sockets", [])
    )

    processes = (
        scan
        .get("processes", {})
        .get("processes", [])
    )

    process_map = {
        process.get("pid"): process
        for process in processes
        if process.get("pid") is not None
    }

    paths = []
    seen = set()

    for socket in sockets:

        if socket.get("state") != "LISTEN":
            continue

        pid = socket.get("pid")

        if pid is None:
            continue

        process = process_map.get(pid)

        if not process:
            continue

        uid = process.get("uid")

        if uid != 0:
            continue

        port = socket.get("port")
        protocol = socket.get("protocol")
        address = socket.get("address")
        process_name = process.get("name")
        executable = process.get("executable")

        key = (protocol, port, pid)

        if key in seen:
            continue

        seen.add(key)

        stages = [
            f"{protocol.upper()} {address}:{port}",
            f"PID {pid} ({process_name})",
            "UID 0 (root)",
        ]

        evidence = [
            f"network_address={address}",
            f"port={port}",
            f"pid={pid}",
            f"process={process_name}",
            "uid=0",
        ]

        if executable:
            stages.append(executable)
            evidence.append(
                f"executable={executable}"
            )

        paths.append(
            AttackPath(
                path_id=(
                    f"KS-PATH-NET-ROOT-"
                    f"{protocol}-{port}-{pid}"
                ),
                title=(
                    "Network-exposed root-owned service"
                ),
                severity="HIGH",
                confidence="HIGH",
                stages=stages,
                evidence=evidence,
                explanation=(
                    "A listening network service has been "
                    "attributed to a process running as root. "
                    "If the service contains a remotely reachable "
                    "weakness, compromise could begin from the "
                    "network and reach a highly privileged process."
                ),
                recommendation=(
                    "Verify that network exposure is required, "
                    "restrict access where possible, keep the "
                    "service updated, and review whether it "
                    "needs to run with root privileges."
                ),
            )
        )

    return paths


def find_capability_process_paths(scan):
    """
    Detect capability-bearing executables that are
    currently running as privileged processes.
    """

    capability_data = (
        scan
        .get("filesystem", {})
        .get("capabilities", {})
    )

    entries = capability_data.get("entries", [])

    processes = (
        scan
        .get("processes", {})
        .get("processes", [])
    )

    paths = []

    for entry in entries:

        parsed = parse_capability_entry(entry)

        if not parsed:
            continue

        executable = parsed["executable"]
        capabilities = parsed["capabilities"]

        for process in processes:

            if process.get("executable") != executable:
                continue

            pid = process.get("pid")
            uid = process.get("uid")
            process_name = process.get("name")

            # Only treat root-owned processes as
            # privileged attack-path candidates.
            if uid != 0:
                continue

            capability_text = ", ".join(capabilities)

            paths.append(
                AttackPath(
                    path_id=(
                        "KS-PATH-CAP-ROOT-"
                        f"{pid}"
                    ),
                    title=(
                        "Running root-owned process "
                        "with Linux capabilities"
                    ),
                    severity="HIGH",
                    confidence="HIGH",
                    stages=[
                        f"Capability-bearing executable: {executable}",
                        f"PID {pid} ({process_name})",
                        "UID 0 (root)",
                        f"Capabilities: {capability_text}",
                    ],
                    evidence=[
                        f"executable={executable}",
                        f"pid={pid}",
                        f"process={process_name}",
                        "uid=0",
                        f"capabilities={capability_text}",
                    ],
                    explanation=(
                        "A Linux executable with elevated "
                        "capabilities is currently running "
                        "as root. If the process or executable "
                        "can be compromised, the assigned "
                        "capabilities may increase the impact "
                        "of the compromise."
                    ),
                    recommendation=(
                        "Verify that the capabilities are "
                        "required, keep the executable updated, "
                        "and avoid running the process with "
                        "root privileges when operationally "
                        "possible."
                    ),
                )
            )

    return paths
