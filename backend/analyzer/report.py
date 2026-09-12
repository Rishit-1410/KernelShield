from datetime import datetime


def build_report(scan, findings, risk, attack_paths):
    """
    Build a structured KernelShield security assessment report.
    """

    return {
        "project": scan.get("project", "KernelShield"),
"version": scan.get("version", "unknown"),
"timestamp": datetime.now().isoformat(),
"scan_mode": scan.get("scan_mode", "Standard"),

        "system": scan.get("system", {}),

        "risk": {
            "score": risk.get("score", 0),
            "risk_level": risk.get("risk_level", "UNKNOWN"),
            "severity_counts": risk.get(
                "severity_counts",
                {}
            ),
        },

        "findings": [
            {
                "finding_id": finding.finding_id,
                "title": finding.title,
                "category": finding.category,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "description": finding.description,
                "evidence": finding.evidence,
                "impact": finding.impact,
                "recommendation": finding.recommendation,
            }
            for finding in findings
        ],

        "attack_paths": [
            {
                "path_id": path.path_id,
                "title": path.title,
                "severity": path.severity,
                "confidence": path.confidence,
                "stages": path.stages,
                "evidence": path.evidence,
                "explanation": path.explanation,
                "recommendation": path.recommendation,
            }
            for path in attack_paths
        ],
    }
