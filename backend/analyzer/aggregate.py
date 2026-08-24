from collections import defaultdict


def aggregate_capability_findings(findings):
    """
    Group Linux capability findings by executable.

    Individual capabilities remain in the evidence,
    but related capability findings for the same executable
    are represented as one aggregated finding.
    """

    groups = defaultdict(list)
    other_findings = []

    for finding in findings:

        if finding.category != "Linux Capabilities":
            other_findings.append(finding)
            continue

        executable = None

        for evidence in finding.evidence:

            if evidence.startswith("executable="):
                executable = evidence.split("=", 1)[1]
                break

        if not executable:
            other_findings.append(finding)
            continue

        groups[executable].append(finding)

    aggregated = []

    for executable, group in groups.items():

        capabilities = []
        evidence = []

        highest_severity = "LOW"

        severity_order = {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        for finding in group:

            for item in finding.evidence:

                if item.startswith("capability="):

                    capability = item.split("=", 1)[1]

                    if capability not in capabilities:
                        capabilities.append(capability)

                elif item not in evidence:
                    evidence.append(item)

            if (
                severity_order.get(
                    finding.severity, 0
                )
                >
                severity_order.get(
                    highest_severity, 0
                )
            ):
                highest_severity = finding.severity

        first = group[0]

        # Choose correct title based on capability count.
        if len(capabilities) == 1:
            title = (
                f"Privileged capability assigned to "
                f"{executable}"
            )
        else:
            title = (
                f"Multiple privileged capabilities assigned to "
                f"{executable}"
            )

        # Build clean evidence without duplicates.
        final_evidence = [
            f"executable={executable}",
            f"capabilities={', '.join(capabilities)}",
        ]

        for item in evidence:

            if item not in final_evidence:
                final_evidence.append(item)

        # Adjust description based on capability count.
        if len(capabilities) == 1:
            description = (
                f"{executable} has one detected Linux "
                "capability."
            )
        else:
            description = (
                f"{executable} has "
                f"{len(capabilities)} detected Linux "
                "capabilities."
            )

        aggregated.append(
            type(first)(
                finding_id=(
                    "KS-CAP-AGG-"
                    + executable.replace("/", "_")
                ),
                category="Linux Capabilities",
                title=title,
                severity=highest_severity,
                description=description,
                evidence=final_evidence,
                impact=(
                    "Privileged Linux capabilities increase "
                    "the privilege surface of an executable. "
                    "If the executable can be abused, these "
                    "capabilities may provide additional "
                    "system-level privileges."
                ),
                recommendation=(
                    "Review whether each assigned capability "
                    "is required. Remove unnecessary capabilities "
                    "where operationally safe."
                ),
                confidence="medium",
            )
        )

    return other_findings + aggregated
