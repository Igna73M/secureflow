"""Adapters that convert scanner output into SecureFlow's common schema."""

from typing import Any

from engine.normalizer import normalize_many
from engine.orchestrator import parse_json_output, run_check


def normalize_bandit_report(report: Any) -> list[dict[str, Any]]:
    """Convert a Bandit JSON report into normalized SecureFlow findings."""
    if not isinstance(report, dict):
        raise ValueError("Bandit report must be a JSON object.")

    results = report.get("results")
    errors = report.get("errors", [])

    if not isinstance(results, list):
        raise ValueError("Bandit report is missing its results list.")

    if not isinstance(errors, list):
        raise ValueError("Bandit report contains an invalid errors list.")

    if errors:
        raise ValueError("Bandit reported file or scan errors.")

    raw_findings = []

    for item in results:
        if not isinstance(item, dict):
            raise ValueError("Bandit report contains an invalid finding.")

        raw_findings.append({
            "rule_id": item.get("test_id", "unknown"),
            "severity": item.get("issue_severity", "INFO"),
            "title": item.get("issue_text", "Bandit finding"),
            "message": item.get("issue_text", "Bandit finding"),
            "file": item.get("filename"),
            "line": item.get("line_number"),
        })

    return normalize_many("bandit", raw_findings)


def run_bandit(
    target: str,
    *,
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    """Run Bandit and return a SecureFlow-compatible check result.

    Bandit exit code 1 means findings were reported, not necessarily that
    the scanner failed. The policy engine decides whether they block.
    """
    execution = run_check(
        "bandit",
        ["bandit", "-q", "-f", "json", "-r", target],
        timeout_seconds=timeout_seconds,
        success_exit_codes={0, 1},
    )

    base = {
        "name": "bandit",
        "status": "ERROR",
        "findings": [],
        "duration_ms": execution.get("duration_ms", 0),
    }

    if execution["status"] == "ERROR":
        base["error"] = execution.get("error", "Bandit execution failed.")
        return base

    try:
        report = parse_json_output(execution.get("stdout", ""))
        findings = normalize_bandit_report(report)
    except ValueError as exc:
        base["error"] = str(exc)
        return base

    base["status"] = "PASS"
    base["findings"] = findings
    return base
