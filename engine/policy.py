"""Fail-closed security policy evaluation for SecureFlow."""

from typing import Any

VALID_STATUSES = {"PASS", "FAIL", "ERROR"}


def evaluate_policy(
    checks: list[dict[str, Any]],
    required_checks: list[str] | None = None,
) -> dict[str, Any]:
    """Evaluate checks and decide whether promotion is allowed.

    Decisions:
      PASS  - all checks completed successfully without blocking findings
      FAIL  - a check failed or a blocking finding was detected
      ERROR - input is invalid or a check could not complete
    """
    errors: list[str] = []
    blocking_findings: list[dict[str, Any]] = []
    normalized_checks: list[dict[str, Any]] = []
    seen_names: set[str] = set()

    if not isinstance(checks, list):
        checks = []
        errors.append("Checks must be a list.")

    if required_checks is None:
        required: list[str] = []
    elif (
        isinstance(required_checks, list)
        and all(isinstance(name, str) and name.strip()
                for name in required_checks)
    ):
        required = required_checks
    else:
        required = []
        errors.append("Required checks must be a list of non-empty names.")

    for check in checks:
        if not isinstance(check, dict):
            errors.append("A check result is not an object.")
            continue

        name = check.get("name")
        status = check.get("status")
        findings = check.get("findings", [])

        if not isinstance(name, str) or not name.strip():
            errors.append("A check has a missing or invalid name.")
            continue

        if name in seen_names:
            errors.append(f"Duplicate check name: {name}")
            continue
        seen_names.add(name)

        if not isinstance(status, str) or status not in VALID_STATUSES:
            errors.append(f"Check '{name}' has an invalid status.")
            continue

        if not isinstance(findings, list):
            errors.append(f"Check '{name}' has invalid findings.")
            continue

        if status == "ERROR":
            errors.append(f"Check '{name}' did not complete.")

        normalized_checks.append({
            "name": name,
            "status": status,
            "findings": findings,
        })

        for finding in findings:
            if not isinstance(finding, dict):
                errors.append(f"Check '{name}' contains an invalid finding.")
                continue

            blocking = finding.get("blocking", True)
            if not isinstance(blocking, bool):
                errors.append(
                    f"Finding in check '{name}' has invalid blocking value."
                )
                continue

            if blocking:
                # Set the trusted check name last so a finding cannot spoof it.
                blocking_findings.append({**finding, "check": name})

    missing = sorted(set(required) - seen_names)
    for name in missing:
        errors.append(f"Required check '{name}' is missing.")

    if errors:
        decision = "ERROR"
    elif blocking_findings or any(
        check["status"] == "FAIL" for check in normalized_checks
    ):
        decision = "FAIL"
    else:
        decision = "PASS"

    return {
        "decision": decision,
        "promotion_allowed": decision == "PASS",
        "errors": errors,
        "blocking_findings": blocking_findings,
        "checks": normalized_checks,
    }
