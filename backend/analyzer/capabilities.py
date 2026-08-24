from backend.models.finding import Finding


CAPABILITY_RISK = {
    "cap_net_raw": {
        "severity": "MEDIUM",
        "description": (
            "Allows an executable to perform raw network operations "
            "that normally require elevated privileges."
        ),
        "impact": (
            "If an attacker can abuse the capability-bearing executable, "
            "it may provide additional network-level capabilities."
        ),
    },

    "cap_net_admin": {
        "severity": "HIGH",
        "description": (
            "Allows network administration operations that are normally "
            "restricted to privileged processes."
        ),
        "impact": (
            "Abuse may allow modification of network configuration or "
            "other privileged network operations."
        ),
    },

    "cap_net_bind_service": {
        "severity": "LOW",
        "description": (
            "Allows an executable to bind to privileged network ports "
            "below 1024 without full root privileges."
        ),
        "impact": (
            "Can increase the network exposure of an application, "
            "depending on how the executable is used."
        ),
    },

    "cap_sys_nice": {
        "severity": "MEDIUM",
        "description": (
            "Allows an executable to modify process scheduling "
            "and priority characteristics."
        ),
        "impact": (
            "Abuse may affect process scheduling or system resource "
            "behavior."
        ),
    },
}


def parse_capability_entry(entry):
    """
    Parse a getcap result.

    Example:
        /usr/bin/fping cap_net_raw=ep
    """

    parts = entry.split(" ", 1)

    if len(parts) != 2:
        return None

    executable = parts[0]
    capability_string = parts[1]

    capability_part = capability_string.split("=", 1)[0]

    capabilities = [
        capability.strip()
        for capability in capability_part.split(",")
        if capability.strip()
    ]

    return {
        "executable": executable,
        "capabilities": capabilities,
    }


def check_capabilities(scan):

    entries = (
        scan
        .get("filesystem", {})
        .get("capabilities", {})
        .get("entries", [])
    )

    findings = []

    for entry in entries:

        parsed = parse_capability_entry(entry)

        if not parsed:
            continue

        executable = parsed["executable"]

        for capability in parsed["capabilities"]:

            risk = CAPABILITY_RISK.get(capability)

            if not risk:
                continue

            findings.append(
                Finding(
                    finding_id=(
                        f"KS-CAP-{capability}-"
                        f"{executable.replace('/', '_')}"
                    ),

                    category="Linux Capabilities",

                    title=(
                        f"Privileged capability assigned to "
                        f"{executable}"
                    ),

                    severity=risk["severity"],

                    description=(
                        f"{executable} has {capability}. "
                        f"{risk['description']}"
                    ),

                    evidence=[
                        entry,
                        f"executable={executable}",
                        f"capability={capability}",
                    ],

                    impact=risk["impact"],

                    recommendation=(
                        "Verify that this capability is required by "
                        "the executable. Remove unnecessary capabilities "
                        "where operationally safe."
                    ),

                    confidence="medium",
                )
            )

    return findings
