import pytest

from engine.policy import evaluate_policy


def test_clean_checks_allow_promotion():
    result = evaluate_policy([
        {"name": "tests", "status": "PASS", "findings": []},
        {"name": "secrets", "status": "PASS", "findings": []},
    ], required_checks=["tests", "secrets"])

    assert result["decision"] == "PASS"
    assert result["promotion_allowed"] is True


def test_blocking_finding_fails_pipeline():
    result = evaluate_policy([{
        "name": "secrets",
        "status": "PASS",
        "findings": [{"rule": "secret-detected", "blocking": True}],
    }])

    assert result["decision"] == "FAIL"
    assert result["promotion_allowed"] is False
    assert len(result["blocking_findings"]) == 1


def test_non_blocking_finding_allows_promotion():
    result = evaluate_policy([{
        "name": "audit",
        "status": "PASS",
        "findings": [{"rule": "informational", "blocking": False}],
    }])

    assert result["decision"] == "PASS"


def test_scanner_error_fails_closed():
    result = evaluate_policy([{
        "name": "secrets", "status": "ERROR", "findings": []
    }])

    assert result["decision"] == "ERROR"
    assert result["promotion_allowed"] is False


def test_missing_required_check_fails_closed():
    result = evaluate_policy([], required_checks=["secrets"])

    assert result["decision"] == "ERROR"
    assert result["promotion_allowed"] is False


def test_duplicate_check_names_fail_closed():
    result = evaluate_policy([
        {"name": "tests", "status": "PASS", "findings": []},
        {"name": "tests", "status": "PASS", "findings": []},
    ])

    assert result["decision"] == "ERROR"


@pytest.mark.parametrize("status", ["UNKNOWN", "", None])
def test_invalid_status_fails_closed(status):
    result = evaluate_policy([{
        "name": "tests", "status": status, "findings": []
    }])

    assert result["decision"] == "ERROR"
    assert result["promotion_allowed"] is False


def test_finding_cannot_spoof_originating_check():
    result = evaluate_policy([{
        "name": "secrets",
        "status": "PASS",
        "findings": [{
            "rule": "secret-detected",
            "blocking": True,
            "check": "fake-scanner",
        }],
    }])

    assert result["decision"] == "FAIL"
    assert result["blocking_findings"][0]["check"] == "secrets"


def test_invalid_blocking_value_fails_closed():
    result = evaluate_policy([{
        "name": "secrets",
        "status": "PASS",
        "findings": [{"rule": "secret-detected", "blocking": "false"}],
    }])

    assert result["decision"] == "ERROR"
    assert result["promotion_allowed"] is False


def test_invalid_checks_argument_fails_closed():
    result = evaluate_policy(None)  # type: ignore[arg-type]

    assert result["decision"] == "ERROR"
    assert result["promotion_allowed"] is False


def test_invalid_required_checks_argument_fails_closed():
    result = evaluate_policy([], required_checks="secrets")  # type: ignore[arg-type]

    assert result["decision"] == "ERROR"
    assert result["promotion_allowed"] is False
