import json

from engine.cli import scan_target


def test_vulnerable_fixture_fails_policy():
    result = scan_target("fixtures/bandit")

    assert result["decision"] == "FAIL"
    assert result["promotion_allowed"] is False
    assert any(
        finding["rule_id"] == "B602"
        for finding in result["blocking_findings"]
    )


def test_missing_target_returns_error():
    result = scan_target("fixtures/does-not-exist-secureflow")

    assert result["decision"] == "ERROR"
    assert result["promotion_allowed"] is False
    assert result["errors"]


def test_result_is_json_serializable():
    result = scan_target("fixtures/bandit")

    encoded = json.dumps(result)
    decoded = json.loads(encoded)

    assert decoded["decision"] == "FAIL"
