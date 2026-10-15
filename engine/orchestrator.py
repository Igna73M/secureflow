"""Execute explicitly configured security checks with bounded resources."""

import json
import subprocess
import time
from typing import Any

from engine.policy import evaluate_policy

MAX_OUTPUT_BYTES = 1_000_000
DEFAULT_TIMEOUT_SECONDS = 60


def run_check(
    name: str,
    command: list[str],
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    success_exit_codes: set[int] | None = None,
    finding_exit_codes: set[int] | None = None,
) -> dict[str, Any]:
    """Run one trusted command and return a structured check result.

    Commands must be argument lists, never shell strings. Callers must only
    provide commands from trusted configuration, not user-supplied input.
    """
    started = time.monotonic()

    if (
        not isinstance(name, str)
        or not name.strip()
        or not isinstance(command, list)
        or not command
        or not all(isinstance(arg, str) for arg in command)
    ):
        return {
            "name": str(name)[:200],
            "status": "ERROR",
            "findings": [],
            "error": "Invalid check name or command configuration.",
            "duration_ms": 0,
        }

    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or timeout_seconds <= 0
        or timeout_seconds > 3600
    ):
        return {
            "name": name,
            "status": "ERROR",
            "findings": [],
            "error": "Timeout must be greater than 0 and at most 3600 seconds.",
            "duration_ms": 0,
        }

    success_codes = success_exit_codes or {0}
    finding_codes = finding_exit_codes or set()

    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "name": name,
            "status": "ERROR",
            "findings": [],
            "error": f"Check timed out after {timeout_seconds} seconds.",
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
    except (OSError, ValueError) as exc:
        return {
            "name": name,
            "status": "ERROR",
            "findings": [],
            "error": f"Could not execute check: {type(exc).__name__}",
            "duration_ms": int((time.monotonic() - started) * 1000),
        }

    stdout = completed.stdout[:MAX_OUTPUT_BYTES].decode(
        "utf-8", errors="replace"
    )
    stderr = completed.stderr[:MAX_OUTPUT_BYTES].decode(
        "utf-8", errors="replace"
    )
    truncated = (
        len(completed.stdout) > MAX_OUTPUT_BYTES
        or len(completed.stderr) > MAX_OUTPUT_BYTES
    )

    if completed.returncode in success_codes:
        status = "PASS"
        error = None
    elif completed.returncode in finding_codes:
        status = "FAIL"
        error = None
    else:
        status = "ERROR"
        error = f"Check exited with unexpected code {completed.returncode}."

    return {
        "name": name,
        "status": status,
        "findings": [],
        "exit_code": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "output_truncated": truncated,
        "error": error,
        "duration_ms": int((time.monotonic() - started) * 1000),
    }


def parse_json_output(output: str) -> Any:
    """Parse scanner JSON output, raising ValueError for invalid JSON."""
    try:
        return json.loads(output)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Scanner did not produce valid JSON.") from exc


def evaluate_checks(
    checks: list[dict[str, Any]],
    required_checks: list[str] | None = None,
) -> dict[str, Any]:
    """Apply the central policy to completed check results."""
    return evaluate_policy(checks, required_checks=required_checks)
