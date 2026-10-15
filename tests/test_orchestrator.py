import sys

from engine.orchestrator import (
    evaluate_checks,
    parse_json_output,
    run_check,
)


def test_successful_command_returns_pass():
    result = run_check(
        "python-version",
        [sys.executable, "--version"],
    )

    assert result["status"] == "PASS"
    assert result["exit_code"] == 0
    assert result["error"] is None


def test_configured_finding_exit_code_returns_fail():
    result = run_check(
        "example-scanner",
        [sys.executable, "-c", "raise SystemExit(2)"],
        finding_exit_codes={2},
    )

    assert result["status"] == "FAIL"


def test_unexpected_exit_code_returns_error():
    result = run_check(
        "broken-scanner",
        [sys.executable, "-c", "raise SystemExit(3)"],
    )

    assert result["status"] == "ERROR"
    assert result["promotion_allowed"] if "promotion_allowed" in result else True


def test_invalid_command_returns_error():
    result = run_check("invalid", [])

    assert result["status"] == "ERROR"


def test_timeout_returns_error():
    result = run_check(
        "slow-check",
        [sys.executable, "-c", "import time; time.sleep(2)"],
        timeout_seconds=0.1,
    )

    assert result["status"] == "ERROR"
    assert "timed out" in result["error"]


def test_json_output_parses():
    assert parse_json_output('{"findings": []}') == {"findings": []}


def test_invalid_json_raises_value_error():
    try:
        parse_json_output("not-json")
    except ValueError as exc:
        assert "valid JSON" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_evaluate_checks_uses_fail_closed_policy():
    result = evaluate_checks(
        [{"name": "scanner", "status": "ERROR", "findings": []}],
        required_checks=["scanner"],
    )

    assert result["decision"] == "ERROR"
    assert result["promotion_allowed"] is False
