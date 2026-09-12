import json
import urllib.request
import urllib.error


OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
OLLAMA_MODEL = "qwen2.5:0.5b-instruct"


SYSTEM_PROMPT = """
You are KernelShield AI, a defensive Linux security analyst.

You are given a security assessment produced by KernelShield.

IMPORTANT:
- KernelShield findings, severities, risk score, and attack paths are authoritative.
- Do not invent findings, vulnerabilities, CVEs, exploits, processes, or attack paths.
- Do not claim exploitability.
- Do not call a security finding an attack path.
- An attack path exists ONLY when explicitly provided in the attack_paths section.
- Keep explanations concise and evidence-based.
- Use defensive security language.

Return ONLY valid JSON with EXACTLY these fields:

{
  "executive_summary": "2-3 sentence defensive summary",
  "finding_insights": [
    "one concise insight for each supplied finding, in the same order"
  ],
  "attack_path_insights": [
    "one concise defensive assessment for each supplied attack path, in the same order"
  ]
}

Do not return titles, severities, IDs, recommendations, dictionaries, markdown, or extra fields.
"""


def _compact_report(report):
    findings = report.get("findings", [])
    attack_paths = report.get("attack_paths", [])
    risk = report.get("risk", {})

    return {
        "risk": {
            "score": risk.get("score"),
            "risk_level": risk.get("risk_level"),
            "severity_counts": risk.get("severity_counts", {}),
        },
        "findings": [
            {
                "title": f.get("title"),
                "severity": f.get("severity"),
                "category": f.get("category"),
                "evidence": f.get("evidence", []),
                "impact": f.get("impact"),
            }
            for f in findings[:10]
        ],
        "attack_paths": [
            {
                "title": p.get("title"),
                "severity": p.get("severity"),
                "confidence": p.get("confidence"),
                "stages": p.get("stages", []),
                "evidence": p.get("evidence", []),
                "explanation": p.get("explanation"),
            }
            for p in attack_paths[:5]
        ],
    }


def _fallback_analysis(report, reason=""):
    findings = report.get("findings", [])
    attack_paths = report.get("attack_paths", [])
    risk = report.get("risk", {})

    score = risk.get("score", 0)
    level = risk.get("risk_level", "UNKNOWN")
    counts = risk.get("severity_counts", {})

    summary = (
        f"KernelShield identified a {level} security posture with "
        f"{len(findings)} findings and {len(attack_paths)} potential "
        f"correlated attack path(s). "
    )

    if attack_paths:
        summary += (
            "The highest-priority correlated exposure should be reviewed "
            "to reduce externally reachable privileged attack surface."
        )
    else:
        summary += (
            "The identified findings represent defensive hardening "
            "opportunities across the assessed Linux host."
        )

    priority_findings = []

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }

    ordered = sorted(
        findings,
        key=lambda f: severity_order.get(
            str(f.get("severity", "INFO")).upper(), 5
        ),
    )

    for finding in ordered[:5]:
        priority_findings.append({
            "title": finding.get("title", "Security finding"),
            "severity": finding.get("severity", "INFO"),
            "why_it_matters": finding.get(
                "impact",
                "This finding represents a security hardening concern."
            ),
        })

    attack_analysis = []

    for path in attack_paths:
        attack_analysis.append({
            "title": path.get(
                "title",
                "Potential correlated attack path"
            ),
            "assessment": path.get(
                "explanation",
                "Potential correlated path requiring defensive review."
            ),
        })

    recommendations = []

    for finding in ordered:
        recommendation = finding.get("recommendation")

        if recommendation and recommendation not in recommendations:
            recommendations.append(recommendation)

    return {
        "enabled": False,
        "mode": "fallback",
        "provider": "fallback",
        "model": None,
        "status": "fallback",
        "reason": reason,
        "executive_summary": summary,
        "priority_findings": priority_findings,
        "attack_path_analysis": attack_analysis,
        "recommendations": recommendations[:6],
    }


def generate_ai_analysis(report, timeout=1):

    context = _compact_report(report)

    user_prompt = (
        "Analyze the following KernelShield assessment. "
        "Remember that the supplied findings and attack_paths are authoritative. "
        "Provide concise defensive interpretation only.\n\n"
        + json.dumps(context, indent=2)
    )

    payload = {
        "model": OLLAMA_MODEL,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.0,
            "num_ctx": 4096,
        },
        "messages": [
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": user_prompt,
            },
        ],
    }

    try:
        request = urllib.request.Request(
            OLLAMA_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_data = json.loads(
                response.read().decode("utf-8")
            )

        content = response_data.get(
            "message", {}
        ).get("content", "")

        if not content:
            return _fallback_analysis(
                report,
                "Ollama returned an empty response."
            )

        ai = json.loads(content)

        findings = report.get("findings", [])
        attack_paths = report.get("attack_paths", [])

        raw_finding_insights = ai.get(
            "finding_insights", []
        )

        raw_attack_insights = ai.get(
            "attack_path_insights", []
        )

        # -------------------------------------------------
        # Deterministic structure
        # -------------------------------------------------

        priority_findings = []

        for index, finding in enumerate(findings[:5]):

            insight = (
                raw_finding_insights[index]
                if index < len(raw_finding_insights)
                else None
            )

            if not isinstance(insight, str) or len(insight.strip()) < 10:
                insight = finding.get(
                    "impact",
                    "This finding represents a security hardening concern."
                )

            priority_findings.append({
                "title": finding.get(
                    "title",
                    "Security finding"
                ),
                "severity": finding.get(
                    "severity",
                    "INFO"
                ),
                "why_it_matters": insight.strip(),
            })

        attack_path_analysis = []

        for index, path in enumerate(attack_paths[:5]):

            insight = (
                raw_attack_insights[index]
                if index < len(raw_attack_insights)
                else None
            )

            if not isinstance(insight, str) or len(insight.strip()) < 15:
                insight = path.get(
                    "explanation",
                    "Potential correlated security path requiring defensive review."
                )

            attack_path_analysis.append({
                "title": path.get(
                    "title",
                    "Potential correlated attack path"
                ),
                "assessment": insight.strip(),
            })

        # -------------------------------------------------
        # Always use deterministic recommendations.
        # The AI does not control these.
        # -------------------------------------------------

        recommendations = []

        severity_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4,
        }

        ordered_findings = sorted(
            findings,
            key=lambda f: severity_order.get(
                str(f.get("severity", "INFO")).upper(),
                5,
            ),
        )

        for finding in ordered_findings:

            recommendation = finding.get("recommendation")

            if (
                isinstance(recommendation, str)
                and recommendation
                and recommendation not in recommendations
            ):
                recommendations.append(recommendation)

        # -------------------------------------------------
        # Authoritative executive summary
        #
        # Do NOT allow the small local model to redefine
        # severity, exploitability, or attack-path facts.
        # -------------------------------------------------

        risk_data = report.get("risk", {})
        risk_level = risk_data.get("risk_level", "UNKNOWN")
        risk_score = risk_data.get("score", 0)

        summary = (
            f"KernelShield identified a {risk_level} security posture "
            f"with a risk score of {risk_score}/100, "
            f"{len(findings)} findings, and "
            f"{len(attack_paths)} potential correlated attack path(s)."
        )

        if attack_paths:
            summary += (
                " The highest-priority exposure is a network-facing "
                "privileged service that warrants defensive review."
            )
        else:
            summary += (
                " The identified findings represent defensive "
                "hardening opportunities across the assessed host."
            )

        # Final recommendation normalization.
        # The dashboard expects plain display strings only.
        clean_recommendations = []

        for recommendation in recommendations:
            if isinstance(recommendation, str):
                text = recommendation.strip()

            elif isinstance(recommendation, dict):
                text = (
                    recommendation.get("recommendation")
                    or recommendation.get("title")
                    or ""
                )
                text = str(text).strip()

            else:
                text = str(recommendation).strip()

            if text and text not in clean_recommendations:
                clean_recommendations.append(text)

        return {
            "enabled": True,
            "mode": "active",
            "provider": "Ollama",
            "model": OLLAMA_MODEL,
            "status": "success",
            "executive_summary": summary.strip(),
            "priority_findings": priority_findings,
            "attack_path_analysis": attack_path_analysis,
            "recommendations": clean_recommendations[:6],
        }

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
    ) as error:

        return _fallback_analysis(
            report,
            f"Ollama unavailable: {error}"
        )

    except (
        json.JSONDecodeError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:

        return _fallback_analysis(
            report,
            f"Invalid AI response: {error}"
        )

    except Exception as error:

        return _fallback_analysis(
            report,
            f"AI analysis error: {error}"
        )
