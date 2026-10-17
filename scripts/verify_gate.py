"""Verify that SecureFlow blocks an intentionally vulnerable fixture."""

import json
import subprocess
import sys


def main() -> int:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "engine.cli",
            "scan",
            "fixtures/bandit",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )

    if result.returncode != 1:
        print(
            "ERROR: expected scan exit code 1 (FAIL), "
            f"got {result.returncode}",
            file=sys.stderr,
        )
        print(result.stdout, file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return 1

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        print(f"ERROR: scan output was not valid JSON: {exc}", file=sys.stderr)
        return 1

    if report.get("decision") != "FAIL":
        print("ERROR: expected decision FAIL", file=sys.stderr)
        return 1

    if report.get("promotion_allowed") is not False:
        print("ERROR: promotion must be blocked", file=sys.stderr)
        return 1

    blocking_findings = [
        finding
        for check in report.get("checks", [])
        for finding in check.get("findings", [])
        if finding.get("blocking") is True
    ]

    if not blocking_findings:
        print("ERROR: expected at least one blocking finding", file=sys.stderr)
        return 1

    print(
        "PASS: vulnerable fixture blocked "
        f"({len(blocking_findings)} blocking finding(s))."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
