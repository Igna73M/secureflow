
"""Command-line interface for SecureFlow."""

import argparse
import json
import sys
from pathlib import Path

from engine.policy import evaluate_policy
from engine.scanners import run_bandit, run_eslint, run_semgrep


PYTHON_EXTENSIONS = {".py"}
JAVASCRIPT_EXTENSIONS = {".js", ".cjs", ".mjs"}


def scan_target(target: str) -> dict:
    """Run the required scanners for the languages present in a directory."""
    path = Path(target).resolve()

    if not path.exists() or not path.is_dir():
        return {
            "decision": "ERROR",
            "promotion_allowed": False,
            "errors": [f"Target directory does not exist: {target}"],
            "checks": [],
            "blocking_findings": [],
        }

    python_files = [
        item for item in path.rglob("*")
        if item.is_file() and item.suffix.lower() in PYTHON_EXTENSIONS
    ]
    javascript_files = [
        item for item in path.rglob("*")
        if item.is_file() and item.suffix.lower() in JAVASCRIPT_EXTENSIONS
    ]

    # Don't let an empty or unsupported directory pass without a scan.
    if not python_files and not javascript_files:
        return {
            "decision": "ERROR",
            "promotion_allowed": False,
            "errors": ["Target contains no supported Python or JavaScript files."],
            "checks": [],
            "blocking_findings": [],
            "target": str(path),
        }

    checks = []
    required_checks = []

    if python_files:
        checks.append(run_bandit(str(path)))
        required_checks.append("bandit")

    if javascript_files:
        checks.append(run_semgrep(str(path)))
        checks.append(run_eslint(str(path)))
        required_checks.extend(["semgrep", "eslint"])

    decision = evaluate_policy(checks, required_checks=required_checks)

    return {
        **decision,
        "target": str(path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="secureflow",
        description="SecureFlow CI/CD security gate",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a target directory",
    )
    scan_parser.add_argument("target", help="Directory to scan")

    args = parser.parse_args()

    if args.command == "scan":
        result = scan_target(args.target)
        print(json.dumps(result, indent=2))

        if result["decision"] == "PASS":
            return 0
        if result["decision"] == "FAIL":
            return 1
        return 2

    return 2


if __name__ == "__main__":
    sys.exit(main())
