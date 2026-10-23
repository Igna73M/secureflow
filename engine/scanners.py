"""Adapters that convert scanner output into SecureFlow's common schema."""

from pathlib import Path
from typing import Any

from engine.normalizer import normalize_many
from engine.orchestrator import parse_json_output, run_check


def normalize_bandit_report(
    report: Any,
    target_root: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Convert Bandit JSON output into normalized SecureFlow findings."""
    if not isinstance(report, dict):
        raise ValueError("Bandit report must be a JSON object.")

    root = Path(target_root).resolve() if target_root is not None else None
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

        filename = item.get("filename")

        safe_relative_file = None
        if isinstance(filename, str):
            candidate = Path(filename)

            if root is not None:
                try:
                    safe_relative_file = candidate.resolve().relative_to(root).as_posix()
                except (OSError, ValueError, RuntimeError):
                    safe_relative_file = None
            elif not candidate.is_absolute():
                safe_relative_file = filename

        raw_findings.append({
            "rule_id": item.get("test_id", "unknown"),
            "severity": item.get("issue_severity", "INFO"),
            "title": item.get("issue_text", "Bandit finding"),
            "message": item.get("issue_text", "Bandit finding"),
            "file": safe_relative_file,
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
        findings = normalize_bandit_report(report, target_root=target)
    except ValueError as exc:
        base["error"] = str(exc)
        return base

    base["status"] = "PASS"
    base["findings"] = findings
    return base


def _relative_file(filename: Any, target_root: str | Path) -> str | None:
    """Return a safe target-relative path, or None for outside paths."""
    if not isinstance(filename, str) or not filename.strip():
        return None

    root = Path(target_root).resolve()
    candidate = Path(filename)

    try:
        if not candidate.is_absolute():
            candidate = root / candidate
        return candidate.resolve().relative_to(root).as_posix()
    except (OSError, ValueError, RuntimeError):
        return None


def normalize_semgrep_report(
    report: Any,
    target_root: str | Path,
) -> list[dict[str, Any]]:
    """Convert a Semgrep JSON report to SecureFlow findings."""
    if not isinstance(report, dict):
        raise ValueError("Semgrep report must be a JSON object.")

    results = report.get("results")
    errors = report.get("errors")

    if not isinstance(results, list):
        raise ValueError("Semgrep report is missing its results list.")
    if not isinstance(errors, list):
        raise ValueError("Semgrep report contains an invalid errors list.")
    if errors:
        raise ValueError("Semgrep reported scan errors.")

    raw_findings = []
    for item in results:
        if not isinstance(item, dict):
            raise ValueError("Semgrep report contains an invalid finding.")

        extra = item.get("extra")
        start = item.get("start")
        if not isinstance(extra, dict) or not isinstance(start, dict):
            raise ValueError("Semgrep finding has invalid location or metadata.")

        severity_map = {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "INFO": "LOW",
        }
        severity = severity_map.get(str(extra.get("severity", "INFO")).upper())
        if severity is None:
            raise ValueError("Semgrep finding has an unknown severity.")

        raw_findings.append({
            "rule_id": item.get("check_id", "unknown"),
            "severity": severity,
            "title": extra.get("message", "Semgrep finding"),
            "message": extra.get("message", "Semgrep finding"),
            "file": _relative_file(item.get("path"), target_root),
            "line": start.get("line"),
        })

    return normalize_many("semgrep", raw_findings)


def normalize_eslint_report(
    report: Any,
    target_root: str | Path,
) -> list[dict[str, Any]]:
    """Convert ESLint's JSON array into SecureFlow findings."""
    if not isinstance(report, list):
        raise ValueError("ESLint report must be a JSON array.")

    raw_findings = []
    for file_result in report:
        if not isinstance(file_result, dict):
            raise ValueError("ESLint report contains an invalid file result.")

        messages = file_result.get("messages")
        if not isinstance(messages, list):
            raise ValueError("ESLint file result is missing its messages list.")

        if file_result.get("fatalErrorCount", 0):
            raise ValueError("ESLint reported a fatal parsing or configuration error.")

        for message in messages:
            if not isinstance(message, dict):
                raise ValueError("ESLint report contains an invalid message.")

            severity_value = message.get("severity")
            if severity_value not in (1, 2):
                raise ValueError("ESLint message has an invalid severity.")

            raw_findings.append({
                "rule_id": message.get("ruleId") or "eslint/fatal",
                "severity": "HIGH" if severity_value == 2 else "LOW",
                "title": message.get("message", "ESLint finding"),
                "message": message.get("message", "ESLint finding"),
                "file": _relative_file(file_result.get("filePath"), target_root),
                "line": message.get("line"),
            })

    return normalize_many("eslint", raw_findings)


def run_semgrep(
    target: str,
    *,
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    """Run the repository's local Semgrep rules and normalize the report."""
    execution = run_check(
        "semgrep",
        [
            "semgrep", "scan",
            "--config", "rules/javascript-security.yml",
            "--json", "--no-git-ignore", target,
        ],
        timeout_seconds=timeout_seconds,
        cwd=str(Path(__file__).resolve().parent.parent),
        success_exit_codes={0, 1},
    )

    base = {
        "name": "semgrep",
        "status": "ERROR",
        "findings": [],
        "duration_ms": execution.get("duration_ms", 0),
    }

    if execution["status"] == "ERROR":
        base["error"] = execution.get("error", "Semgrep execution failed.")
        return base

    try:
        report = parse_json_output(execution.get("stdout", ""))
        findings = normalize_semgrep_report(report, target)
    except ValueError as exc:
        base["error"] = str(exc)
        return base

    base["status"] = "PASS"
    base["findings"] = findings
    return base



def run_eslint(
    target: str,
    *,
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    """Run ESLint using SecureFlow's explicit flat configuration."""
    repo_root = Path(__file__).resolve().parent.parent
    api_root = repo_root / "api"
    eslint_bin = api_root / "node_modules" / ".bin" / "eslint"
    config = api_root / "eslint.config.mjs"

    target_path = Path(target).resolve()
    if target_path == api_root.resolve():
        scan_targets = [
            str(api_root / "src"),
            str(api_root / "tests"),
        ]
    elif target_path.is_dir():
        # ESLint 10 can ignore source files inside external temp directories.
        # Pass supported JavaScript files explicitly instead.
        scan_targets = [
            str(item)
            for item in sorted(target_path.rglob("*"))
            if item.is_file()
            and item.suffix.lower() in {".js", ".cjs", ".mjs"}
        ]
    else:
        scan_targets = [str(target_path)]

    execution = run_check(
        "eslint",
        [
            str(eslint_bin),
            "--no-config-lookup",
            "--config", str(config),
            "--format", "json",
            "--no-warn-ignored",
            *scan_targets,
        ],
        timeout_seconds=timeout_seconds,
        cwd=str(repo_root),
        success_exit_codes={0, 1},
    )

    base = {
        "name": "eslint",
        "status": "ERROR",
        "findings": [],
        "duration_ms": execution.get("duration_ms", 0),
    }

    if execution["status"] == "ERROR":
        base["error"] = execution.get("error", "ESLint execution failed.")
        return base

    try:
        report = parse_json_output(execution.get("stdout", ""))
        findings = normalize_eslint_report(report, target_path)
    except ValueError as exc:
        base["error"] = str(exc)
        return base

    base["status"] = "PASS"
    base["findings"] = findings
    return base
