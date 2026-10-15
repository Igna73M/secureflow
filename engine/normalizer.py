"""Normalize scanner findings into SecureFlow's common schema."""

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*(['\"]?)[^\s,'\";]+"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
]


def redact(text: Any) -> str:
    """Convert input to text and redact common secret-like values."""
    value = str(text) if text is not None else ""
    for pattern in SECRET_PATTERNS:
        if pattern.groups:
            value = pattern.sub(r"\1=[REDACTED]", value)
        else:
            value = pattern.sub("[REDACTED]", value)
    return value[:2000]


def _safe_file(value: Any) -> str | None:
    """Keep repository-relative paths; reject absolute and traversing paths."""
    if not isinstance(value, str) or not value.strip():
        return None

    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)

    if path.is_absolute() or ".." in path.parts:
        return None

    # Avoid treating a Windows drive path as a relative path on Linux.
    if re.match(r"^[A-Za-z]:", normalized):
        return None

    return normalized[:500]


def normalize_finding(
    scanner: str,
    raw: dict[str, Any],
    blocking_severities: set[str] | None = None,
) -> dict[str, Any]:
    """Normalize one generic finding dictionary.

    Scanner adapters should map their native output fields to this input shape.
    """
    if not isinstance(scanner, str) or not scanner.strip():
        raise ValueError("scanner must be a non-empty string")
    if not isinstance(raw, dict):
        raise ValueError("raw finding must be an object")

    severity = str(raw.get("severity", "INFO")).upper()
    if severity not in SEVERITIES:
        severity = "INFO"

    rule_id = redact(raw.get("rule_id") or raw.get("rule") or "unknown")
    title = redact(raw.get("title") or raw.get("message") or rule_id)
    message = redact(raw.get("message") or title)
    file_path = _safe_file(raw.get("file") or raw.get("path"))

    line_value = raw.get("line")
    line = line_value if isinstance(line_value, int) and not isinstance(line_value, bool) and line_value > 0 else None

    blocking_levels = blocking_severities or {"CRITICAL", "HIGH"}
    blocking_override = raw.get("blocking")

    # Scanner output cannot lower a configured severity threshold.
    blocking = severity in blocking_levels
    if isinstance(blocking_override, bool) and blocking_override is True:
        blocking = True

    identity = {
        "scanner": scanner,
        "rule_id": rule_id,
        "file": file_path,
        "line": line,
        "title": title,
    }
    finding_id = hashlib.sha256(
        json.dumps(identity, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]

    return {
        "id": finding_id,
        "scanner": scanner,
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "file": file_path,
        "line": line,
        "message": message,
        "blocking": blocking,
    }


def normalize_many(
    scanner: str,
    findings: list[dict[str, Any]],
    blocking_severities: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Normalize a list of findings, rejecting malformed collection inputs."""
    if not isinstance(findings, list):
        raise ValueError("findings must be a list")

    return [
        normalize_finding(scanner, finding, blocking_severities)
        for finding in findings
    ]
