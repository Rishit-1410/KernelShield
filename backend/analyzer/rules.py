from backend.models.finding import Finding
from backend.analyzer.capabilities import check_capabilities

def check_kptr_restrict(scan):
    """
    Check whether kernel pointer exposure is restricted.
    """

    value = (
        scan
        .get("security", {})
        .get("kernel_security_parameters", {})
        .get("kernel.kptr_restrict")
    )

    if value is None:
        return None

    if value == "0":
        return Finding(
            finding_id="KS-KERNEL-001",
            category="Kernel Hardening",
            title="Kernel pointer exposure is not restricted",
            severity="MEDIUM",
            description=(
                "kernel.kptr_restrict is set to 0, allowing greater "
                "exposure of kernel pointer information to userspace."
            ),
            evidence=[
                "kernel.kptr_restrict=0"
            ],
            impact=(
                "Kernel address information can assist exploitation "
                "of vulnerabilities that depend on kernel memory layout."
            ),
            recommendation=(
                "Review whether kernel pointer exposure is required "
                "and consider using a more restrictive value."
            ),
            confidence="high",
        )

    return None


def check_dmesg_restrict(scan):
    """
    Check whether access to kernel logs is restricted.
    """

    value = (
        scan
        .get("security", {})
        .get("kernel_security_parameters", {})
        .get("kernel.dmesg_restrict")
    )

    if value is None:
        return None

    if value == "0":
        return Finding(
            finding_id="KS-KERNEL-002",
            category="Kernel Hardening",
            title="Kernel log access is not restricted",
            severity="LOW",
            description=(
                "kernel.dmesg_restrict is set to 0, allowing "
                "broader access to kernel message information."
            ),
            evidence=[
                "kernel.dmesg_restrict=0"
            ],
            impact=(
                "Kernel messages may expose information useful during "
                "reconnaissance or exploitation."
            ),
            recommendation=(
                "Consider restricting access to kernel messages "
                "on systems where unprivileged access is unnecessary."
            ),
            confidence="high",
        )

    return None


def check_ptrace_scope(scan):
    """
    Check Yama ptrace scope.
    """

    value = (
        scan
        .get("security", {})
        .get("kernel_security_parameters", {})
        .get("kernel.yama.ptrace_scope")
    )

    if value is None:
        return None

    if value == "0":
        return Finding(
            finding_id="KS-KERNEL-003",
            category="Kernel Hardening",
            title="Process tracing restrictions are permissive",
            severity="MEDIUM",
            description=(
                "kernel.yama.ptrace_scope is set to 0, which permits "
                "less restrictive process tracing."
            ),
            evidence=[
                "kernel.yama.ptrace_scope=0"
            ],
            impact=(
                "A compromised process may have greater opportunity "
                "to inspect or interact with other processes."
            ),
            recommendation=(
                "Review whether a more restrictive ptrace policy "
                "is appropriate for this system."
            ),
            confidence="high",
        )

    return None


def check_bpf(scan):
    """
    Check unprivileged BPF restriction.
    """

    value = (
        scan
        .get("security", {})
        .get("kernel_security_parameters", {})
        .get("kernel.unprivileged_bpf_disabled")
    )

    if value is None:
        return None

    # Values 1 and 2 indicate that unprivileged BPF is restricted.
    if value == "0":
        return Finding(
            finding_id="KS-KERNEL-004",
            category="Kernel Hardening",
            title="Unprivileged BPF is enabled",
            severity="HIGH",
            description=(
                "Unprivileged processes are allowed to use BPF "
                "without elevated privileges."
            ),
            evidence=[
                "kernel.unprivileged_bpf_disabled=0"
            ],
            impact=(
                "BPF functionality can provide powerful kernel interaction "
                "and may increase attack surface."
            ),
            recommendation=(
                "Consider disabling unprivileged BPF unless it is "
                "required by legitimate workloads."
            ),
            confidence="high",
        )

    return None


def check_uid_zero_accounts(scan):
    """
    Identify accounts with UID 0.
    """

    root_accounts = (
        scan
        .get("users", {})
        .get("root_accounts", [])
    )

    findings = []

    for account in root_accounts:

        username = account.get("username", "unknown")

        if username != "root":

            findings.append(
                Finding(
                    finding_id=f"KS-USER-001-{username}",
                    category="Privilege Exposure",
                    title="Additional UID 0 account detected",
                    severity="HIGH",
                    description=(
                        f"The account '{username}' has UID 0 and therefore "
                        "has root-equivalent privileges."
                    ),
                    evidence=[
                        f"username={username}",
                        "uid=0",
                    ],
                    impact=(
                        "Compromise of the account could provide "
                        "root-level control over the system."
                    ),
                    recommendation=(
                        "Review whether this UID 0 account is required. "
                        "Remove unnecessary UID 0 accounts."
                    ),
                    confidence="high",
                )
            )

    return findings

def check_network_exposure(scan):
    """
    Detect TCP services exposed on all network interfaces.

    IPv4 and IPv6 exposure for the same port are grouped
    into a single finding.
    """

    sockets = (
        scan
        .get("network", {})
        .get("listening_sockets", [])
    )

    exposed_services = {}

    for socket in sockets:

        protocol = socket.get("protocol")
        state = socket.get("state")
        address = socket.get("address")
        port = socket.get("port")

        # Only analyze TCP listening sockets.
        if protocol != "tcp" or state != "LISTEN":
            continue

        exposed = address in ["0.0.0.0", "::", "[::]"]

        if not exposed:
            continue

        key = (protocol, port)

        if key not in exposed_services:
            exposed_services[key] = []

        exposed_services[key].append(address)

    findings = []

    for (protocol, port), addresses in exposed_services.items():

        evidence = [
            f"{protocol.upper()} {address}:{port}"
            for address in addresses
        ]

        findings.append(
            Finding(
                finding_id=f"KS-NET-001-{protocol}-{port}",
                category="Network Exposure",
                title="Service exposed on all network interfaces",
                severity="MEDIUM",
                description=(
                    f"A {protocol.upper()} service is listening on "
                    f"port {port} across broadly exposed network "
                    "addresses."
                ),
                evidence=evidence,
                impact=(
                    "A broadly exposed service increases the reachable "
                    "attack surface and may be accessible from networks "
                    "that do not require access."
                ),
                recommendation=(
                    "Verify that this service needs to be externally "
                    "reachable. If not required, bind it to localhost "
                    "or a restricted network interface."
                ),
                confidence="high",
            )
        )

    return findings

def check_seccomp(scan):
    """
    Check whether a large number of processes have Seccomp disabled.
    """

    summary = (
        scan
        .get("syscalls", {})
        .get("userspace_seccomp_summary", {})
    )

    disabled = summary.get("disabled", 0)
    total = sum(summary.values())

    if total == 0:
        return None

    disabled_percent = (disabled / total) * 100

    # Report when more than 50% of observed processes
    # do not use Seccomp protection.
    if disabled_percent > 50:
        return Finding(
            finding_id="KS-SYSCALL-001",
            category="System Call Security",
            title="Many processes run without Seccomp protection",
            severity="MEDIUM",
            description=(
                f"{disabled} of {total} observed processes "
                f"({disabled_percent:.1f}%) have Seccomp disabled."
            ),
            evidence=[
                f"seccomp_disabled={disabled}",
                f"seccomp_filter={summary.get('filter', 0)}",
                f"seccomp_strict={summary.get('strict', 0)}",
                f"seccomp_unknown={summary.get('unknown', 0)}",
            ],
            impact=(
                "Processes without Seccomp filtering have fewer "
                "restrictions on the system calls they can make. "
                "If a vulnerable process is compromised, this may "
                "increase the available kernel attack surface."
            ),
            recommendation=(
                "Review security-sensitive services and applications "
                "and enable an appropriate Seccomp policy where "
                "operationally supported."
            ),
            confidence="high",
        )

    return None

def run_rules(scan):
    """
    Execute all KernelShield security rules.
    """

    findings = []

    checks = [
        check_kptr_restrict,
        check_dmesg_restrict,
        check_ptrace_scope,
        check_bpf,
        check_seccomp,
    ]

    for check in checks:

        result = check(scan)

        if result:
            findings.append(result)

    findings.extend(
        check_uid_zero_accounts(scan)
    )

    findings.extend(
        check_network_exposure(scan)
    )

    findings.extend(
        check_capabilities(scan)
    )

    return findings
