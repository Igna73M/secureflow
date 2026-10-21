
"""Execute explicitly configured security checks with bounded resources."""

import json
import os
import signal
import subprocess
import threading
import time
from typing import Any, BinaryIO

from engine.policy import evaluate_policy

MAX_OUTPUT_BYTES = 1_000_000
DEFAULT_TIMEOUT_SECONDS = 60
READ_CHUNK_BYTES = 64 * 1024


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate the scanner and its child processes on POSIX systems."""
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.kill()
        except OSError:
            pass


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

    Commands must be argument lists from trusted configuration, never
    user-supplied shell strings.
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

    success_codes = {0} if success_exit_codes is None else success_exit_codes
    finding_codes = set() if finding_exit_codes is None else finding_exit_codes

    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=(os.name == "posix"),
        )
    except (OSError, ValueError) as exc:
        return {
            "name": name,
            "status": "ERROR",
            "findings": [],
            "error": f"Could not execute check: {type(exc).__name__}",
            "duration_ms": int((time.monotonic() - started) * 1000),
        }

    captured = {"stdout": bytearray(), "stderr": bytearray()}
    output_exceeded = threading.Event()

    def drain_stream(stream: BinaryIO, key: str) -> None:
        """Drain a pipe while retaining no more than its configured limit."""
        buffer = captured[key]

        try:
            while True:
                chunk = stream.read(READ_CHUNK_BYTES)
                if not chunk:
                    break

                remaining = MAX_OUTPUT_BYTES - len(buffer)
                if remaining > 0:
                    buffer.extend(chunk[:remaining])

                if len(chunk) > remaining:
                    output_exceeded.set()
                    _kill_process_group(process)
        except (OSError, ValueError):
            # The process may have been killed while the pipe was being read.
            pass

    if process.stdout is None or process.stderr is None:
        _kill_process_group(process)
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                pass

        return {
            "name": name,
            "status": "ERROR",
            "findings": [],
            "error": "Could not capture scanner output streams.",
            "duration_ms": int((time.monotonic() - started) * 1000),
        }

    readers = [
        threading.Thread(
            target=drain_stream,
            args=(process.stdout, "stdout"),
            daemon=True,
        ),
        threading.Thread(
            target=drain_stream,
            args=(process.stderr, "stderr"),
            daemon=True,
        ),
    ]

    for reader in readers:
        reader.start()

    timed_out = False
    reader_timeout = False
    deadline = time.monotonic() + timeout_seconds
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process_group(process)

        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            # Fallback: try killing the scanner process directly.
            try:
                process.kill()
            except OSError:
                pass

            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                # Never block the gate indefinitely during cleanup.
                pass

    # Wait only until the original deadline for output streams to close.
    for reader in readers:
        reader.join(timeout=max(0.0, deadline - time.monotonic()))

    # Record whether the deadline was missed before cleanup can unblock readers.
    reader_timeout = any(reader.is_alive() for reader in readers)
    if reader_timeout:
        _kill_process_group(process)
        cleanup_deadline = time.monotonic() + 1.0
        for reader in readers:
            reader.join(
                timeout=max(0.0, cleanup_deadline - time.monotonic())
            )

    # Close streams only after readers have stopped using them.
    if not any(reader.is_alive() for reader in readers):
        for stream in (process.stdout, process.stderr):
            stream.close()

    stdout = captured["stdout"].decode("utf-8", errors="replace")
    stderr = captured["stderr"].decode("utf-8", errors="replace")
    duration_ms = int((time.monotonic() - started) * 1000)

    if reader_timeout:
        return {
            "name": name,
            "status": "ERROR",
            "findings": [],
            "exit_code": process.returncode,
            "output_truncated": True,
            "error": "Scanner output streams did not close within the cleanup deadline.",
            "duration_ms": duration_ms,
        }

    if timed_out:
        return {
            "name": name,
            "status": "ERROR",
            "findings": [],
            "error": f"Check timed out after {timeout_seconds} seconds.",
            "duration_ms": duration_ms,
        }

    if output_exceeded.is_set():
        return {
            "name": name,
            "status": "ERROR",
            "findings": [],
            "exit_code": process.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "output_truncated": True,
            "error": (
                "Check exceeded the maximum output size "
                f"of {MAX_OUTPUT_BYTES} bytes per stream."
            ),
            "duration_ms": duration_ms,
        }

    if process.returncode in success_codes:
        status = "PASS"
        error = None
    elif process.returncode in finding_codes:
        status = "FAIL"
        error = None
    else:
        status = "ERROR"
        error = f"Check exited with unexpected code {process.returncode}."

    return {
        "name": name,
        "status": status,
        "findings": [],
        "exit_code": process.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "output_truncated": False,
        "error": error,
        "duration_ms": duration_ms,
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
