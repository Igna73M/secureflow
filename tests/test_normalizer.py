import pytest

from engine.normalizer import normalize_finding, normalize_many, redact


def test_normalizes_finding_and_applies_severity_threshold():
    finding = normalize_finding("bandit", {
        "rule_id": "B105",
        "severity": "HIGH",
        "title": "Possible hardcoded password",
        "file": "src/auth.py",
        "line": 12,
    })

    assert finding["scanner"] == "bandit"
    assert finding["severity"] == "HIGH"
    assert finding["blocking"] is True
    assert finding["file"] == "src/auth.py"
    assert finding["line"] == 12


def test_low_severity_is_non_blocking_by_default():
    finding = normalize_finding("bandit", {
        "rule_id": "B101",
        "severity": "LOW",
        "title": "Assert used",
    })

    assert finding["blocking"] is False


def test_scanner_cannot_suppress_high_severity():
    finding = normalize_finding("scanner", {
        "rule_id": "R1",
        "severity": "HIGH",
        "blocking": False,
    })

    assert finding["blocking"] is True


def test_unknown_severity_becomes_info():
    finding = normalize_finding("scanner", {
        "rule_id": "R1",
        "severity": "unexpected",
    })

    assert finding["severity"] == "INFO"
    assert finding["blocking"] is False


def test_rejects_unsafe_file_paths():
    finding = normalize_finding("scanner", {
        "severity": "HIGH",
        "file": "../../etc/passwd",
    })

    assert finding["file"] is None


def test_finding_id_is_stable():
    raw = {"rule_id": "R1", "severity": "MEDIUM", "file": "src/a.py"}
    first = normalize_finding("scanner", raw)
    second = normalize_finding("scanner", raw)

    assert first["id"] == second["id"]


def test_redacts_common_secret_patterns():
    text = "api_key=supersecret123 token=ghp_abcdefghijklmnopqrstuvwxyz123456"
    cleaned = redact(text)

    assert "supersecret123" not in cleaned
    assert "ghp_abcdefghijklmnopqrstuvwxyz123456" not in cleaned


def test_normalize_many_rejects_non_list():
    with pytest.raises(ValueError):
        normalize_many("scanner", {"not": "a list"})  # type: ignore[arg-type]
