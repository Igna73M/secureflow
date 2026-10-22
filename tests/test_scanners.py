import sys

import pytest

from engine.policy import evaluate_policy
from engine.scanners import normalize_bandit_report, run_bandit


@pytest.fixture
def bandit_report():
    return {
        "results": [
            {
                "test_id": "B404",
                "issue_severity": "LOW",
                "issue_text": "Importing subprocess may have security implications.",
                "filename": "sample.py",
                "line_number": 1,
            },
            {
                "test_id": "B602",
                "issue_severity": "HIGH",
                "issue_text": "subprocess call with shell=True identified.",
                "filename": "sample.py",
                "line_number": 8,
            },
        ],
        "errors": [],
    }


def test_normalizes_bandit_report(bandit_report):
    findings = normalize_bandit_report(bandit_report)

    assert len(findings) == 2
    assert findings[0]["rule_id"] == "B404"
    assert findings[0]["blocking"] is False
    assert findings[1]["rule_id"] == "B602"
    assert findings[1]["blocking"] is True


def test_policy_blocks_high_bandit_finding(bandit_report):
    findings = normalize_bandit_report(bandit_report)
    result = evaluate_policy([{
        "name": "bandit",
        "status": "PASS",
        "findings": findings,
    }])

    assert result["decision"] == "FAIL"
    assert result["promotion_allowed"] is False


def test_rejects_report_with_scan_errors():
    with pytest.raises(ValueError, match="scan errors"):
        normalize_bandit_report({
            "results": [],
            "errors": [{"filename": "missing.py", "error": "Could not read"}],
        })


def test_rejects_invalid_report():
    with pytest.raises(ValueError):
        normalize_bandit_report({"errors": []})


def test_run_bandit_on_sample_fixture():
    result = run_bandit("fixtures/bandit")

    assert result["status"] == "PASS"
    assert result["findings"]
    assert any(
        finding["rule_id"] == "B602"
        for finding in result["findings"]
    )


def test_missing_bandit_target_fails_closed():
    result = run_bandit("fixtures/does-not-exist-secureflow")

    assert result["status"] == "ERROR"
    assert result["findings"] == []

def test_run_bandit_preserves_relative_finding_paths():
    result = run_bandit("fixtures/bandit")

    assert result["status"] == "PASS"
    assert result["findings"]

    finding = next(
        item for item in result["findings"]
        if item["rule_id"] == "B602"
    )

    assert finding["file"] == "vulnerable_sample.py"


def test_normalizes_semgrep_report(tmp_path):
    from engine.scanners import normalize_semgrep_report

    report = {
        "results": [
            {
                "check_id": "secureflow.javascript.eval",
                "path": str(tmp_path / "vulnerable.js"),
                "start": {"line": 3},
                "extra": {
                    "severity": "ERROR",
                    "message": "Avoid eval.",
                },
            }
        ],
        "errors": [],
    }

    findings = normalize_semgrep_report(report, tmp_path)

    assert len(findings) == 1
    assert findings[0]["scanner"] == "semgrep"
    assert findings[0]["rule_id"] == "secureflow.javascript.eval"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["file"] == "vulnerable.js"
    assert findings[0]["line"] == 3
    assert findings[0]["blocking"] is True


def test_semgrep_rejects_scan_errors(tmp_path):
    from engine.scanners import normalize_semgrep_report

    with pytest.raises(ValueError, match="scan errors"):
        normalize_semgrep_report(
            {"results": [], "errors": [{"message": "scan failed"}]},
            tmp_path,
        )


def test_normalizes_eslint_report(tmp_path):
    from engine.scanners import normalize_eslint_report

    report = [
        {
            "filePath": str(tmp_path / "vulnerable.js"),
            "fatalErrorCount": 0,
            "messages": [
                {
                    "ruleId": "security/detect-child-process",
                    "severity": 2,
                    "message": "Unsafe child process command.",
                    "line": 4,
                },
                {
                    "ruleId": "example/notice",
                    "severity": 1,
                    "message": "Review this code.",
                    "line": 5,
                },
            ],
        }
    ]

    findings = normalize_eslint_report(report, tmp_path)

    assert len(findings) == 2
    assert findings[0]["scanner"] == "eslint"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["file"] == "vulnerable.js"
    assert findings[0]["line"] == 4
    assert findings[0]["blocking"] is True
    assert findings[1]["severity"] == "LOW"
    assert findings[1]["blocking"] is False


def test_eslint_rejects_fatal_errors(tmp_path):
    from engine.scanners import normalize_eslint_report

    report = [
        {
            "filePath": str(tmp_path / "broken.js"),
            "fatalErrorCount": 1,
            "messages": [],
        }
    ]

    with pytest.raises(ValueError, match="fatal"):
        normalize_eslint_report(report, tmp_path)
