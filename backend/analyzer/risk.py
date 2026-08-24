from collections import Counter


SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 6,
    "MEDIUM": 3,
    "LOW": 1,
    "INFO": 0,
}


def calculate_risk(findings):
    """
    Calculate KernelShield's normalized risk score.

    The score ranges from 0 to 100.
    Higher score = higher security risk.
    """

    if not findings:
        return {
            "score": 0,
            "risk_level": "LOW",
            "severity_counts": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            },
        }

    counts = Counter(
        finding.severity
        for finding in findings
    )

    weighted_score = sum(
        counts.get(severity, 0) * weight
        for severity, weight in SEVERITY_WEIGHTS.items()
    )

    # Normalize against the number of findings.
    maximum_possible = len(findings) * 10

    score = int(
        (weighted_score / maximum_possible) * 100
    )

    score = max(0, min(100, score))

    if score >= 80:
        risk_level = "CRITICAL"
    elif score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "score": score,
        "risk_level": risk_level,
        "severity_counts": {
            "CRITICAL": counts.get("CRITICAL", 0),
            "HIGH": counts.get("HIGH", 0),
            "MEDIUM": counts.get("MEDIUM", 0),
            "LOW": counts.get("LOW", 0),
            "INFO": counts.get("INFO", 0),
        },
    }
