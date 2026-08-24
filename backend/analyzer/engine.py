from backend.analyzer.rules import run_rules


def analyze_scan(scan):
    """
    Analyze a KernelShield scan and return security findings.
    """

    findings = run_rules(scan)

    return findings


def findings_to_dict(findings):

    return [
        finding.to_dict()
        for finding in findings
    ]
