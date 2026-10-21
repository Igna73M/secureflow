# SecureFlow Demo Guide

## 1. Purpose

This guide demonstrates SecureFlow’s CI/CD security-gate behavior:

1. Install the project dependencies.
2. Run the automated tests.
3. Scan a deliberately vulnerable Python fixture.
4. Verify that blocking findings prevent promotion.
5. Scan the engine code and inspect the structured result.
6. Run the complete local CI target.

The demo uses the current Bandit integration. It is a demonstration of the implemented gate behavior, not proof that an application is free from vulnerabilities.

## 2. Prerequisites

- Git
- Python 3.14
- Node.js 22 and npm
- A terminal in the SecureFlow repository

Commands below assume a POSIX-compatible shell, such as Bash.

## 3. Set Up the Project

From the repository root:

```bash
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cd api
npm ci
cd ..
```

If the virtual environment is already active and dependencies are installed, you can skip the setup commands.

## 4. Run the Tests

Run the Python and API tests:

```bash
make test
```

Expected result: both test suites complete successfully. If a test fails, resolve the failure before interpreting the demo as a successful verification.

## 5. Demonstrate Vulnerable-Code Blocking

Run the dedicated gate verification script:

```bash
python scripts/verify_gate.py
```

The script scans the deliberately vulnerable fixture under `fixtures/bandit` and checks that the gate denies promotion.

Expected behavior:

- The scan produces a `FAIL` decision.
- `promotion_allowed` is `false`.
- At least one finding is marked as blocking.
- The verification script exits successfully only when those expectations hold.

You can also inspect the scan output directly:

```bash
python -m engine.cli scan fixtures/bandit
```

For this intentionally vulnerable fixture, the CLI is expected to return exit code `1` for `FAIL`. That non-zero exit code is expected for this demonstration; it is not a successful scan decision.

To inspect the exit code explicitly:

```bash
python -m engine.cli scan fixtures/bandit
status=$?
printf 'SecureFlow exit code: %s\n' "$status"
```

Expected exit code: `1`.

## 6. Inspect a Normal Engine Scan

Run:

```bash
python -m engine.cli scan engine
```

Inspect the JSON output for:

- `decision`
- `promotion_allowed`
- check status and scanner metadata
- finding severity and blocking status
- any reported scanner errors

A successful gate decision is represented by `PASS`, `promotion_allowed: true`, and exit code `0`.

Do not assume that scanning the engine will always pass: the result depends on the current source, scanner version, and policy configuration. If the scan returns `FAIL` or `ERROR`, inspect the reported findings or errors rather than treating the result as a demo failure automatically.

## 7. Understand the Exit Codes

| Exit code | Meaning | Expected gate behavior |
|---:|---|---|
| `0` | `PASS` | Promotion may proceed |
| `1` | `FAIL` | Promotion is denied |
| `2` | `ERROR` | Promotion is denied |

A CI workflow should stop when the gate returns `1` or `2`. It must not treat a scanner error as a successful security assessment.

## 8. Run the Complete Local CI Target

Run:

```bash
make ci
```

This target runs:

1. Python and API tests.
2. The vulnerable-fixture gate verification.
3. A scan of the `engine` directory.

Expected result: each command completes according to the checks configured in the current `Makefile`. The engine scan may report findings; review its exit code and decision rather than relying only on the presence of JSON output.

A successful local run does not establish that GitHub Actions is healthy. Verify hosted workflow runs separately.

## 9. Optional: Exercise the Reporting API

The Express API provides endpoints for health checks and scan-report storage and retrieval. Start it from the API directory:

```bash
cd api
npm start
```

In another terminal, check health:

```bash
curl -i http://127.0.0.1:3000/health
```

The default port is `3000`; the server configuration can be overridden through environment variables.

Available routes in the inspected implementation:

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/api/scans` | Submit a scan report |
| `GET` | `/api/scans` | List scan reports |
| `GET` | `/api/scans/:id` | Retrieve a report by ID |

Use the API tests as the authoritative examples of the currently accepted request schema:

```bash
cd api
npm test
```

**Security warning:** the inspected API does not implement authentication or authorization. Do not expose it to an untrusted network or submit sensitive scan reports to an untrusted instance. The API validates parts of submitted reports, but it does not independently rerun the scanner or fully recalculate the security decision. Treat submitted reports as untrusted unless their provenance is verified.

Stop the server with `Ctrl+C` when finished.

## 10. Troubleshooting

### Dependencies are missing

Activate the Python virtual environment and reinstall Python requirements:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

For API dependencies:

```bash
cd api
npm ci
```

### The vulnerable fixture does not produce `FAIL`

Check that Bandit is installed and available in the active Python environment:

```bash
python -m bandit --version
```

Then rerun:

```bash
python scripts/verify_gate.py
```

Review the output and scanner configuration before changing the policy. Do not weaken blocking rules merely to make the demo pass.

### The engine scan returns `FAIL`

Inspect the JSON findings and determine whether they are expected, blocking under the current policy, or require remediation. The gate should not be bypassed simply to obtain exit code `0`.

### The scan returns `ERROR`

Inspect the reported error, confirm dependencies are installed, and verify the target directory exists. An `ERROR` is a denied promotion outcome, not a clean scan.

### Local checks pass but hosted CI fails

Inspect the specific GitHub Actions run and its annotations. A workflow startup failure is different from a test failure inside a running job; diagnose the actual failure before changing application code.

## 11. Demo Completion Checklist

- [ ] Dependencies installed successfully.
- [ ] Python and API tests passed.
- [ ] Vulnerable fixture produced `FAIL`.
- [ ] Gate verification confirmed promotion was denied.
- [ ] Engine scan output and exit code were reviewed.
- [ ] `make ci` completed as expected.
- [ ] API security limitations were reviewed if the API was started.
- [ ] Hosted CI status was checked independently.

## 12. What This Demo Proves — and Does Not Prove

The demo can verify that the current implementation runs its tests, processes the Bandit fixture, and denies promotion for the expected blocking result.

It does **not** prove complete vulnerability coverage, production readiness, API security against untrusted clients, or successful hosted CI execution. Those require additional testing, controls, and independent verification.
