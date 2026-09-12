import json
import sys
from pathlib import Path

# KernelShield project root
BASE_DIR = Path(__file__).resolve().parent.parent

# Make backend importable when running:
# python frontend/app.py
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from flask import Flask, render_template, jsonify, request

from backend.scanner import run_scan
from backend.analyzer.engine import analyze_scan
from backend.analyzer.risk import calculate_risk
from backend.analyzer.aggregate import aggregate_capability_findings
from backend.analyzer.attack_paths import (
    find_network_root_process_paths,
    find_capability_process_paths,
)
from backend.analyzer.report import build_report
from backend.ai.analyst import generate_ai_analysis

app = Flask(__name__)


SCAN_FILE = BASE_DIR / "scan.json"
REPORT_FILE = BASE_DIR / "report.json"


def load_report():
    if not REPORT_FILE.exists():
        report = {
            "project": "KernelShield",
            "version": "unknown",
            "timestamp": None,
            "scan_mode": "Standard",
            "risk": {
                "score": 0,
                "risk_level": "UNKNOWN",
                "severity_counts": {}
            },
            "findings": [],
            "attack_paths": []
        }
    else:
        with open(REPORT_FILE, "r") as file:
            report = json.load(file)

    # Ensure older or empty reports are compatible with the dashboard.
    if "ai_analysis" not in report:
        report["ai_analysis"] = generate_ai_analysis(report)

        # Persist upgraded reports when possible.
        with open(REPORT_FILE, "w") as file:
            json.dump(report, file, indent=4)

    return report


def perform_scan(privileged=False):
    """
    Run KernelShield collectors and generate a fresh security report.
    """

    # Collect fresh system information
    scan = run_scan(privileged=privileged)

    # Save fresh scan data
    with open(SCAN_FILE, "w") as file:
        json.dump(scan, file, indent=4)

    # Analyze scan
    findings = analyze_scan(scan)

    # Aggregate related capability findings
    findings = aggregate_capability_findings(findings)

    # Detect attack paths
    attack_paths = find_network_root_process_paths(scan)

    # Detect capability-related attack paths
    capability_paths = find_capability_process_paths(scan)

    # Combine attack paths
    attack_paths.extend(capability_paths)

    # Calculate risk
    risk = calculate_risk(findings)

    # Build report
    report = build_report(
        scan,
        findings,
        risk,
        attack_paths
    )

    # AI-assisted defensive assessment
    report["ai_analysis"] = generate_ai_analysis(report)

    # Save report
    with open(REPORT_FILE, "w") as file:
        json.dump(report, file, indent=4)

    return report


@app.route("/")
def dashboard():
    report = load_report()
    return render_template(
        "dashboard.html",
        report=report
    )


@app.route("/api/report")
def api_report():
    return jsonify(load_report())


@app.route("/api/scan", methods=["POST"])
def api_scan():
    try:
        data = request.get_json(silent=True) or {}

        privileged = bool(
            data.get("privileged", False)
        )

        report = perform_scan(
            privileged=privileged
        )

        return jsonify({
            "success": True,
            "message": "Scan completed successfully.",
            "report": report
        })

    except Exception as error:
        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
