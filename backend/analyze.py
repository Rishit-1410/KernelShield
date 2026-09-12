import json

from backend.analyzer.engine import analyze_scan
from backend.analyzer.risk import calculate_risk
from backend.analyzer.aggregate import aggregate_capability_findings
from backend.analyzer.attack_paths import (
    find_network_root_process_paths,
    find_capability_process_paths,
)
from backend.analyzer.report import build_report
from backend.ai.analyst import generate_ai_analysis


def main():

    # ---------------------------------------------------------
    # Load scan
    # ---------------------------------------------------------

    with open("scan.json", "r") as file:
        scan = json.load(file)

    # ---------------------------------------------------------
    # Analyze findings
    # ---------------------------------------------------------

    findings = analyze_scan(scan)

    findings = aggregate_capability_findings(findings)

    # ---------------------------------------------------------
    # Detect attack paths
    # ---------------------------------------------------------

    attack_paths = find_network_root_process_paths(scan)

    capability_paths = find_capability_process_paths(scan)

    attack_paths.extend(capability_paths)

    # ---------------------------------------------------------
    # Calculate risk
    # ---------------------------------------------------------

    risk = calculate_risk(findings)

    # ---------------------------------------------------------
    # Build structured report
    # ---------------------------------------------------------

    report = build_report(
        scan,
        findings,
        risk,
        attack_paths,
    )
    report["ai_analysis"] = generate_ai_analysis(report)

    # ---------------------------------------------------------
    # Save report
    # ---------------------------------------------------------

    with open("report.json", "w") as file:
        json.dump(
            report,
            file,
            indent=4,
        )

    print(
        f"Report generated with "
        f"{len(report['findings'])} findings and "
        f"{len(report['attack_paths'])} attack paths."
    )

    print("Report saved to report.json")

    # ---------------------------------------------------------
    # Header
    # ---------------------------------------------------------

    print()
    print("=" * 60)
    print("             KernelShield Analysis")
    print("=" * 60)
    print()

    # ---------------------------------------------------------
    # Risk summary
    # ---------------------------------------------------------

    print(f"Findings discovered: {len(findings)}")
    print()

    print(f"Security Risk Score: {risk['score']}/100")
    print(f"Overall Risk Level: {risk['risk_level']}")
    print()

    print("Severity Summary:")

    for severity, count in risk["severity_counts"].items():
        print(f"  {severity}: {count}")

    print()

    # ---------------------------------------------------------
    # Findings
    # ---------------------------------------------------------

    print("=" * 60)
    print("                    Findings")
    print("=" * 60)
    print()

    for finding in findings:

        print(
            f"[{finding.severity}] {finding.title}"
        )

        print(f"ID: {finding.finding_id}")
        print(f"Category: {finding.category}")
        print(f"Confidence: {finding.confidence}")
        print()

        print("Evidence:")

        for evidence in finding.evidence:
            print(f"  - {evidence}")

        print()

        print("Impact:")
        print(f"  {finding.impact}")

        print()

        print("Recommendation:")
        print(f"  {finding.recommendation}")

        print()
        print("-" * 60)

    # ---------------------------------------------------------
    # Attack paths
    # ---------------------------------------------------------

    print()
    print("=" * 60)
    print("                  Attack Paths")
    print("=" * 60)
    print()

    if not attack_paths:

        print(
            "No correlated attack paths identified."
        )

    else:

        print(
            f"Attack paths discovered: "
            f"{len(attack_paths)}"
        )

        print()

        for path in attack_paths:

            print(
                f"[{path.severity}] {path.title}"
            )

            print(f"ID: {path.path_id}")
            print(f"Confidence: {path.confidence}")
            print()

            print("Path:")

            for index, stage in enumerate(
                path.stages,
                start=1,
            ):
                print(
                    f"  {index}. {stage}"
                )

            print()

            print("Evidence:")

            for evidence in path.evidence:
                print(
                    f"  - {evidence}"
                )

            print()

            print("Explanation:")
            print(
                f"  {path.explanation}"
            )

            print()

            print("Recommendation:")
            print(
                f"  {path.recommendation}"
            )

            print()
            print("-" * 60)


if __name__ == "__main__":
    main()
