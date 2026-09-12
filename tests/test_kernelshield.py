from backend.models.finding import Finding
from backend.analyzer.risk import calculate_risk
from backend.analyzer.aggregate import aggregate_capability_findings
from backend.analyzer.attack_paths import find_network_root_process_paths
from backend.analyzer.engine import analyze_scan


def test_risk_calculation():
    findings = [
        Finding(
            finding_id="TEST-HIGH",
            category="Test",
            title="High test finding",
            severity="HIGH",
            description="Test finding",
        ),
        Finding(
            finding_id="TEST-MEDIUM",
            category="Test",
            title="Medium test finding",
            severity="MEDIUM",
            description="Test finding",
        ),
        Finding(
            finding_id="TEST-LOW",
            category="Test",
            title="Low test finding",
            severity="LOW",
            description="Test finding",
        ),
    ]

    risk = calculate_risk(findings)

    assert isinstance(risk, dict)
    assert "score" in risk
    assert "risk_level" in risk
    assert 0 <= risk["score"] <= 100


def test_empty_findings_have_low_risk():
    risk = calculate_risk([])

    assert risk["score"] == 0
    assert risk["risk_level"] == "LOW"


def test_network_root_attack_path():
    scan = {
        "network": {
            "listening_sockets": [
                {
                    "protocol": "tcp",
                    "address": "0.0.0.0",
                    "port": 8834,
                    "state": "LISTEN",
                    "pid": 1234,
                }
            ]
        },
        "processes": {
            "processes": [
                {
                    "pid": 1234,
                    "uid": 0,
                    "username": "root",
                    "name": "test-service",
                    "executable": "/usr/bin/test-service",
                }
            ]
        },
    }

    paths = find_network_root_process_paths(scan)

    assert len(paths) == 1
    assert paths[0].severity == "HIGH"
    assert paths[0].confidence == "HIGH"
    assert paths[0].title == "Network-exposed root-owned service"


def test_no_attack_path_for_non_root_process():
    scan = {
        "network": {
            "listening_sockets": [
                {
                    "protocol": "tcp",
                    "address": "0.0.0.0",
                    "port": 8080,
                    "state": "LISTEN",
                    "pid": 1234,
                }
            ]
        },
        "processes": {
            "processes": [
                {
                    "pid": 1234,
                    "uid": 1000,
                    "username": "user",
                    "name": "test-service",
                    "executable": "/usr/bin/test-service",
                }
            ]
        },
    }

    paths = find_network_root_process_paths(scan)

    assert paths == []


def test_capability_findings_are_aggregated():
    findings = [
        Finding(
            finding_id="KS-CAP-1",
            category="Linux Capabilities",
            title="Capability assigned",
            severity="MEDIUM",
            description="capability",
            evidence=[
                "executable=/usr/bin/test",
                "capabilities=cap_net_raw",
            ],
            recommendation="Review capability.",
        ),
        Finding(
            finding_id="KS-CAP-2",
            category="Linux Capabilities",
            title="Capability assigned",
            severity="HIGH",
            description="capability",
            evidence=[
                "executable=/usr/bin/test",
                "capabilities=cap_net_admin",
            ],
            recommendation="Review capability.",
        ),
    ]

    aggregated = aggregate_capability_findings(findings)

    assert len(aggregated) == 1
    assert aggregated[0].severity == "HIGH"
    assert "/usr/bin/test" in aggregated[0].title


def test_detection_engine_returns_kernel_finding():
    scan = {
        "security": {
            "kernel_security_parameters": {
                "kernel.kptr_restrict": "0",
                "kernel.dmesg_restrict": "0",
                "kernel.yama.ptrace_scope": "0",
                "kernel.unprivileged_bpf_disabled": "1",
            }
        },
        "network": {
            "listening_sockets": []
        },
        "processes": {
            "processes": []
        },
        "syscalls": {},
        "users": {
            "root_accounts": [
                {
                    "username": "root",
                    "uid": 0,
                }
            ]
        },
    }

    findings = analyze_scan(scan)

    assert isinstance(findings, list)

    assert any(
        finding.finding_id == "KS-KERNEL-001"
        for finding in findings
    )

    assert any(
        finding.title == "Kernel pointer exposure is not restricted"
        for finding in findings
    )


def test_attack_path_requires_matching_process():
    scan = {
        "network": {
            "listening_sockets": [
                {
                    "protocol": "tcp",
                    "address": "0.0.0.0",
                    "port": 9000,
                    "state": "LISTEN",
                    "pid": 9999,
                }
            ]
        },
        "processes": {
            "processes": [
                {
                    "pid": 1234,
                    "uid": 0,
                    "username": "root",
                    "name": "other-service",
                    "executable": "/usr/bin/other",
                }
            ]
        },
    }

    paths = find_network_root_process_paths(scan)

    assert paths == []
