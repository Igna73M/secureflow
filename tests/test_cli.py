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

def test_safe_javascript_fixture_allows_promotion():
    import shutil
    import tempfile
    from pathlib import Path

    repo_root = Path.cwd()
    with tempfile.TemporaryDirectory(
        dir=repo_root,
        prefix=".test-safe-js-",
    ) as directory:
        shutil.copy(
            "fixtures/javascript/safe.js",
            Path(directory) / "safe.js",
        )

        result = scan_target(directory)

    assert result["decision"] == "PASS"
    assert result["promotion_allowed"] is True
    assert result["blocking_findings"] == []

def test_vulnerable_javascript_fixture_blocks_promotion():
    result = scan_target("fixtures/javascript")

    assert result["decision"] == "FAIL"
    assert result["promotion_allowed"] is False
    assert any(
        finding["scanner"] == "semgrep"
        and finding["rule_id"] == "rules.secureflow.javascript.eval"
        for finding in result["blocking_findings"]
    )
    assert any(
        finding["scanner"] == "eslint"
        and finding["rule_id"] == "security/detect-child-process"
        for finding in result["blocking_findings"]
    )
