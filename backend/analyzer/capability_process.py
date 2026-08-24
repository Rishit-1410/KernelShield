import re


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


def find_capability_processes(scan):
    """
    Correlate filesystem capabilities with running processes.

    A capability is considered active only when the same
    executable is currently running.
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

    results = []

    for entry in entries:

        parsed = parse_capability_entry(entry)

        if not parsed:
            continue

        executable = parsed["executable"]
        capabilities = parsed["capabilities"]

        for process in processes:

            process_executable = process.get("executable")

            if process_executable != executable:
                continue

            results.append({
                "executable": executable,
                "capabilities": capabilities,
                "pid": process.get("pid"),
                "name": process.get("name"),
                "uid": process.get("uid"),
                "command_line": process.get("command_line"),
            })

    return results


if __name__ == "__main__":

    import json

    with open("scan.json", "r") as file:
        scan = json.load(file)

    results = find_capability_processes(scan)

    print(json.dumps(results, indent=2))

