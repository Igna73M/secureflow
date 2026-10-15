"""Command-line interface for SecureFlow."""

import argparse
import json
import sys
from pathlib import Path

from engine.policy import evaluate_policy
from engine.scanners import run_bandit


def scan_target(target: str) -> dict:
    """Run configured scanners and evaluate the security policy."""
    path = Path(target).resolve()

    if not path.exists() or not path.is_dir():
        return {
            "decision": "ERROR",
            "promotion_allowed": False,
            "errors": [f"Target directory does not exist: {target}"],
            "checks": [],
            "blocking_findings": [],
        }

    check = run_bandit(str(path))

    # Scanner execution errors must remain ERROR, not be mistaken for clean.
    decision = evaluate_policy(
        [check],
        required_checks=["bandit"],
    )

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
