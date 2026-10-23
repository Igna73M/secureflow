# SecureFlow Demo Guide

This guide walks through the local test suite, Python and JavaScript scans, the deliberately vulnerable Bandit fixture, and an optional API demonstration. Commands assume a POSIX-compatible shell and that they are run from the repository root unless noted.

The demo illustrates selected behavior in the current implementation. A `PASS` means the configured checks completed without policy-blocking findings; it does not prove that source is free from vulnerabilities or that SecureFlow is production-ready.

## Prerequisites

- Python 3.14, matching the version configured in the GitHub Actions workflow.
- Node.js 22 and npm, for API tests, API development, and the local ESLint executable used for JavaScript scans.
- Git and a POSIX-compatible shell.

Python dependencies are listed in [`requirements.txt`](../requirements.txt). API packages and exact resolved versions are recorded in [`api/package-lock.json`](../api/package-lock.json). The JavaScript scanner path uses Semgrep from the Python environment and ESLint from `api/node_modules/.bin`.

## 1. Install dependencies

From the repository root, create and activate a virtual environment, then install Python requirements:

```bash
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Install the API dependencies using the repository's npm lockfile:

```bash
cd api
npm ci
cd ..
```

Keep the virtual environment activated for the following commands. If the API source-upload route is used, its subprocess defaults to `python`; that executable must also be available on `PATH` (or selected with `SECUREFLOW_PYTHON`).

## 2. Run the automated tests

From the repository root:

```bash
make test
```

This invokes `python -m pytest -v` and the API's `npm test` script. The tests cover policy decisions and malformed inputs, scanner normalization and errors, subprocess timeout/output limits, CLI results for Python and JavaScript fixtures, and API validation, persistence, and source uploads. Passing these tests demonstrates only the covered cases.

## 3. Scan the engine

Run the same engine scan target used by the Makefile:

```bash
python -m engine.cli scan engine
```

The CLI recursively finds `.py`, `.js`, `.cjs`, and `.mjs` files. Bandit runs when Python files are found; Semgrep and ESLint both run when JavaScript files are found. The output is a JSON report on standard output. The scan may return `PASS`, `FAIL`, or `ERROR` depending on the current source, dependencies, scanner results, and policy. Do not assume this target always passes.

A `PASS` sets `promotion_allowed` to `true` and returns exit code `0`. It describes the result of the configured checks and policy only; it is not a guarantee that the engine or another target has no vulnerabilities.

## 4. Demonstrate that vulnerable code is blocked

The fixture [`fixtures/bandit/vulnerable_sample.py`](../fixtures/bandit/vulnerable_sample.py) includes a deliberately unsafe subprocess call. Run the repository's gate verification script:

```bash
python scripts/verify_gate.py
```

The script invokes the CLI on `fixtures/bandit`, parses its JSON, and checks for all of the following:

- The scan decision is `FAIL`.
- The CLI returns exit code `1`.
- `promotion_allowed` is `false`.
- At least one finding is marked blocking.

For this fixture, `FAIL` is the expected scan decision. The verification script itself exits successfully only when the gate blocks it as expected; it exits unsuccessfully if the scan unexpectedly allows promotion or returns a different result. The GitHub Actions workflow contains a corresponding vulnerable-fixture assertion.

To inspect the report directly, use:

```bash
python -m engine.cli scan fixtures/bandit
```

This direct command is expected to return exit code `1`, which a shell may display as a command failure even though it is the expected result for this fixture. The verification script is the easier way to get a successful process status when the expected blocking behavior is observed.

## 5. Optional: scan JavaScript fixtures

JavaScript directory scans require both Semgrep and the API-installed ESLint executable. With the dependencies installed, run:

```bash
python -m engine.cli scan fixtures/javascript
```

The directory includes [`safe.js`](../fixtures/javascript/safe.js) and [`vulnerable.js`](../fixtures/javascript/vulnerable.js). The tests verify a clean JavaScript target can pass and the vulnerable fixture is blocked by the configured Semgrep/ESLint checks. The actual result and findings are printed as JSON; inspect the exit code and report rather than relying on a fixed output transcript.

## 6. Interpret the report and exit status

The CLI report includes:

- `decision`: overall `PASS`, `FAIL`, or `ERROR`.
- `promotion_allowed`: `true` only when the overall decision is `PASS`.
- `checks`: the applicable scanner checks, each with a check-level status and normalized `findings`.
- Finding fields such as `scanner`, `rule_id`, `severity`, `file`, `line`, `message`, and `blocking`.
- `blocking_findings`: findings that block promotion.
- `errors`: messages explaining checks or evaluation that could not be completed.
- `target`: the resolved directory for a valid directory scan.

| CLI exit code | Decision | Interpretation |
|---:|---|---|
| `0` | `PASS` | Required checks completed successfully and there are no blocking findings or failed checks. Promotion is allowed by policy. |
| `1` | `FAIL` | A blocking finding exists or a check has status `FAIL`. Promotion is denied. |
| `2` | `ERROR` | The target or check/evaluation input is invalid or incomplete, a required check is missing, or a scanner could not reliably complete. Promotion is denied. |

Not every finding blocks promotion. The normalizer marks `CRITICAL` and `HIGH` findings blocking by default; lower severities are not blocking by default, though an explicit blocking flag may block. A valid scanner check may itself have status `PASS` while reporting findings; the overall policy can still be `FAIL`. The policy is fail-closed: missing required checks and evaluation/scanner errors do not become a successful promotion decision.

## 7. Run the complete local CI target

The root Makefile's complete local sequence is:

```bash
make ci
```

It runs `make test`, `make gate-test`, and `make scan-engine` in order: Python and API tests, vulnerable-fixture verification, then a scan of the `engine` directory. `make scan-engine` propagates the CLI exit status, so `make ci` can exit nonzero if the engine scan returns `FAIL` or `ERROR`. A nonzero result should be understood from the step and JSON report that produced it.

Local test or CI success is separate from hosted GitHub Actions success. Check the repository's Actions page for an actual hosted run; this guide does not claim one has passed.

## 8. Optional: run the API demo

The API is optional for the CLI demo. It can scan one uploaded source file through the CLI, or accept a report already produced elsewhere. These routes are not equivalent:

- `POST /api/scan-upload` validates and scans one uploaded source file, then stores the resulting decision and findings.
- `POST /api/scans` validates and stores a caller-submitted report. It does not scan source or independently recompute the policy decision.

### Start and check the API

From the repository root:

```bash
cd api
npm start
```

The server listens on `127.0.0.1:3000` by default. In another terminal, check that the API and database are available:

```bash
curl -i http://127.0.0.1:3000/health
```

The health route returns `200` with `{"status":"ok"}` when SQLite is available, or `503` with `{"status":"unavailable"}` otherwise. Stop the server with `Ctrl+C` when finished.

### Scan one uploaded source file

From a second terminal at the repository root, upload source as JSON:

```bash
curl -i -X POST http://127.0.0.1:3000/api/scan-upload \
	-H 'Content-Type: application/json' \
	-d '{"filename":"example.py","content":"print(\"hello\")\n"}'
```

Supported extensions are `.py`, `.js`, `.cjs`, and `.mjs`. The filename must be non-empty and at most 255 characters; source content must be non-empty and no larger than 100 KiB in UTF-8 bytes. The general JSON request body limit is 256 KiB. The API writes the file to a temporary directory, invokes the CLI with a 65-second subprocess timeout and a 2,100,000-byte output buffer limit, persists the result, and attempts temporary-directory cleanup. Python uploads use Bandit; JavaScript uploads use Semgrep and ESLint.

A processed scan returns HTTP `201` for `PASS`, `FAIL`, or `ERROR`. Check the returned `decision` and `promotion_allowed`; HTTP `201` means the request was processed and stored, not that promotion passed.

### Submit a report for storage only

`POST /api/scans` expects a JSON object with `target`, `decision`, `promotion_allowed`, and `findings`. Each finding has scanner, rule, severity, title, message, blocking status, and optional file/line data. The API validates the fields and checks that the promotion flag matches the decision; it rejects a `PASS` containing a finding explicitly marked blocking. It does **not** rerun a scanner or fully recompute policy.

Example request for storing a report that claims a failed scan:

```bash
curl -i -X POST http://127.0.0.1:3000/api/scans \
	-H 'Content-Type: application/json' \
	-d '{
		"target": "demo-project",
		"decision": "FAIL",
		"promotion_allowed": false,
		"findings": [{
			"scanner": "bandit",
			"rule_id": "B602",
			"severity": "HIGH",
			"title": "Shell execution detected",
			"file": "src/example.py",
			"line": 12,
			"message": "Potential unsafe shell execution.",
			"blocking": true
		}]
	}'
```

This is submitted data, not a scan of `demo-project`. Because the API has no authentication or authorization, do not expose it to untrusted users or networks. Do not treat a stored report as independently verified security evidence.

For API history, `GET /api/scans` lists recent records (default limit `20`, permitted range `1` to `100`) and `GET /api/scans/:id` retrieves one record with findings. See [`api/tests/api.test.js`](../api/tests/api.test.js) for exercised request and response behavior.

## Troubleshooting

### Dependencies are missing

Activate the virtual environment and install Python packages, then install API dependencies:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
cd api
npm ci
cd ..
```

Run commands from the repository root unless a step explicitly says to enter `api/`.

### A scanner executable is unavailable

Bandit and Semgrep are installed from `requirements.txt`; `npm ci` installs ESLint under `api/node_modules`. Confirm the virtual environment is active and the API packages are installed. A scanner launch failure is reported as `ERROR`, not a clean scan. For API uploads, ensure `python` is on `PATH`, or set `SECUREFLOW_PYTHON` to the intended Python executable.

### The vulnerable fixture does not produce the expected block

Run `python scripts/verify_gate.py` from the repository root and inspect its diagnostic output. Confirm the Python environment and Bandit dependency are available. The direct scan is expected to return exit `1`; the verification script should itself exit successfully only when that expected `FAIL` and blocking finding are present. Do not weaken policy merely to make the demo pass.

### A scan returns `ERROR`

Check that the target exists and is a directory with at least one supported file (`.py`, `.js`, `.cjs`, or `.mjs`). Inspect the JSON `errors` and check statuses; verify each applicable scanner is installed. `ERROR` means the scan could not be evaluated reliably and promotion is denied.

### The engine scan returns `FAIL`

Review `blocking_findings`, check findings, severity, and scanner identity. The engine scan's result depends on the checked-out code, scanner versions, and policy; a `FAIL` is not automatically a failure of the test suite. Address findings rather than bypassing the gate.

### GitHub Actions does not start or fails before running tests

Inspect the actual Actions run and repository/account settings. Billing, plan limits, disabled Actions, organization policy, or workflow permissions can prevent hosted runs from starting; this guide does not establish that any billing or settings issue is resolved. Local `make test` or `make ci` success does not prove hosted GitHub Actions is available or passing.

## Demo limits

The fixtures and tests demonstrate selected expected behavior for configured scanners. They do not prove complete Python or JavaScript vulnerability coverage, and a `PASS` is not a security certification. The API has no authentication or authorization; submitted report ingestion trusts client-provided scan claims subject only to structural and consistency checks. Do not use this demo as evidence that SecureFlow is ready for production deployment.

For implementation details, see the [architecture](architecture.md), [threat model](threat-model.md), and [architecture decision records](decisions.md).
