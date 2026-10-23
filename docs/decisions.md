# SecureFlow Architecture Decision Records

An Architecture Decision Record (ADR) documents a consequential design choice, its context, and its trade-offs. The records below describe current architectural decisions supported by the repository; they do not claim a specific historical discussion, author, or approval date. **Accepted** means the approach is present in the current implementation, not that it is production-ready.

When the implementation or constraints change, update the relevant ADR or add a new one. Mark an ADR **Superseded** only when a replacement decision exists, and link the replacement. Keep recommendations clearly separate from implemented decisions.

## Decision summary

| ID | Decision | Status |
|---|---|---|
| ADR-001 | Bandit integration for Python scanning | Accepted (current implementation) |
| ADR-002 | Fail-closed policy evaluation and required checks | Accepted (current implementation) |
| ADR-003 | Structured CLI report and exit-code contract | Accepted (current implementation) |
| ADR-004 | Bounded scanner subprocess execution | Accepted (current implementation) |
| ADR-005 | Separate scan enforcement from report persistence | Accepted (current architecture) |
| ADR-006 | SQLite for API scan history | Accepted (current implementation) |
| ADR-007 | Treat client-submitted reports as unverified | Accepted as a trust constraint; verification features are not implemented |
| ADR-008 | Semgrep and ESLint for JavaScript scanning | Accepted (current implementation) |
| ADR-009 | Vulnerable-fixture gate verification in CI | Accepted (current workflow) |

## ADR-001: Bandit integration for Python scanning

**Status:** Accepted (current implementation)

**Context**

The CLI needs a Python scanner whose output can be normalized into SecureFlow findings and evaluated by the shared policy. The repository also needs a reproducible vulnerable Python target for checking the scan-to-policy path.

**Decision**

When the CLI discovers one or more `.py` files in a target directory, it runs Bandit recursively in quiet JSON-report mode. Bandit findings are adapted to the common finding schema before policy evaluation. Bandit exit code `1` is accepted as report output because it can indicate findings; parsed blocking findings, rather than that scanner exit code alone, determine the overall security decision.

**Rationale**

The current integration supplies a concrete Python scan path and structured results for policy evaluation. This record describes the present choice; the repository does not document the historical selection process.

**Consequences**

- Bandit execution, parsing, or reported scan errors become a scanner check error and deny promotion.
- The finding adapter maps Bandit's rule ID, severity, message, filename, and line into normalized fields.
- Coverage is limited to Bandit's detection capabilities and the files selected by the CLI; a clean result is not proof of vulnerability absence.

**Implementation evidence**

- [`engine/cli.py`](../engine/cli.py) — Python file discovery and required `bandit` check.
- [`engine/scanners.py`](../engine/scanners.py) — Bandit invocation and report normalization.
- [`engine/normalizer.py`](../engine/normalizer.py) — common finding severity, blocking, path, and redaction behavior.
- [`tests/test_scanners.py`](../tests/test_scanners.py) — Bandit result, error, and finding tests.
- [`tests/test_cli.py`](../tests/test_cli.py) — vulnerable Python target produces a blocked decision.

## ADR-002: Fail-closed policy evaluation and required checks

**Status:** Accepted (current implementation)

**Context**

A gate cannot grant promotion when a required scan is missing, invalid, or unable to complete. A scanner execution error is different from a valid scan that reports a blocking finding, and both must deny promotion.

**Decision**

[`engine/policy.py`](../engine/policy.py) returns `PASS` only when inputs are valid, required checks are present, no check has status `FAIL` or `ERROR`, and no finding is blocking. It returns `FAIL` for a failed check or blocking finding, provided no evaluation errors exist. Invalid inputs, malformed check or finding data, duplicate check names, missing required checks, and check status `ERROR` produce `ERROR`. Evaluation errors take precedence over findings or check failures. `promotion_allowed` is true exactly for `PASS`.

The CLI derives required checks from discovered file types: `bandit` for Python and both `semgrep` and `eslint` for JavaScript. `ERROR` must not authorize promotion because it indicates that the required assessment did not produce a reliable result.

**Rationale**

Failing closed prevents missing or unusable checks from being treated as evidence of a clean scan. Distinguishing `FAIL` from `ERROR` preserves the difference between a policy violation and inability to evaluate.

**Consequences**

- Scanner outages and malformed results block promotion, potentially interrupting CI until resolved.
- A check-level `PASS` means the scanner produced a valid report; the overall decision can still be `FAIL` if that report contains blocking findings.
- Downstream workflows must stop on both nonzero CLI exits; policy behavior cannot prevent a consumer from ignoring the result.

**Implementation evidence**

- [`engine/policy.py`](../engine/policy.py) — decision rules and validation.
- [`engine/cli.py`](../engine/cli.py) — language-derived required checks.
- [`tests/test_policy.py`](../tests/test_policy.py) — pass, block, error, missing-check, duplicate, and malformed-input cases.
- [`tests/test_orchestrator.py`](../tests/test_orchestrator.py) — check errors are evaluated fail-closed.

## ADR-003: Structured CLI report and exit-code contract

**Status:** Accepted (current implementation)

**Context**

CI consumers need machine-readable scan details and a process status that communicates whether promotion may proceed.

**Decision**

The `python -m engine.cli scan DIRECTORY` command prints an indented JSON result to standard output and maps the overall decision to these exit codes:

| Exit code | Decision | Meaning |
|---:|---|---|
| `0` | `PASS` | Promotion is allowed by the evaluated policy. |
| `1` | `FAIL` | A check failed or a blocking finding was detected; promotion is denied. |
| `2` | `ERROR` | The target or evaluation is invalid/incomplete; promotion is denied. |

**Rationale**

JSON lets automation and humans inspect the same structured result. Separate nonzero codes distinguish a security failure from an evaluation failure.

**Consequences**

- Consumers must preserve the exit status when redirecting or processing JSON.
- Exit code `0` is the only successful gate status. Do not interpret JSON output alone as permission to promote.
- Changes to the report schema or exit mapping affect automation contracts and should be covered by tests.

**Implementation evidence**

- [`engine/cli.py`](../engine/cli.py) — JSON serialization and exact exit mapping.
- [`tests/test_cli.py`](../tests/test_cli.py) — JSON output and decision behavior.
- [`scripts/verify_gate.py`](../scripts/verify_gate.py) — checks the vulnerable fixture's exit code and report.

## ADR-004: Bounded scanner subprocess execution

**Status:** Accepted (current implementation)

**Context**

The scanner tools run as external processes over source that may be untrusted. The gate must not use shell interpolation for target paths and must treat process or output failures as inability to assess, not as clean results.

**Decision**

[`engine/orchestrator.py`](../engine/orchestrator.py) invokes trusted configured commands as argument lists using `subprocess.Popen` with `shell=False`, closed stdin, captured stdout/stderr, and a new process session on POSIX. The default per-check timeout is 60 seconds, and each output stream is capped at 1,000,000 bytes. Timeout, process launch failure, output overflow, and output streams that do not close within the cleanup deadline return check status `ERROR`. On POSIX, cleanup kills the scanner process group; other platforms use process termination fallback.

The API upload path is a separate Node.js subprocess boundary: `api/src/app.js` uses `execFile` with a 65-second timeout and a 2,100,000-byte max buffer.

**Rationale**

Argument-list invocation avoids shell parsing of target paths. Bounded time and captured output limit some resource risks and ensure common execution failures cannot be mistaken for successful checks.

**Consequences**

- A timeout or output cap can produce `ERROR` and block promotion.
- These limits do not sandbox scanners or impose CPU/memory quotas, filesystem restrictions, privilege reduction, or network isolation.
- The Node upload subprocess has separate limits and cleanup behavior from the Python scanner runner; the two should not be conflated.

**Implementation evidence**

- [`engine/orchestrator.py`](../engine/orchestrator.py) — process creation, timeout, output caps, and cleanup.
- [`engine/scanners.py`](../engine/scanners.py) — scanner command arguments and accepted scanner exit codes.
- [`api/src/app.js`](../api/src/app.js) — upload subprocess timeout and buffer limit.
- [`tests/test_orchestrator.py`](../tests/test_orchestrator.py) — timeout, output limit, and child-pipe cleanup cases.

## ADR-005: Separate scanning, policy evaluation, and report persistence

**Status:** Accepted (current architecture)

**Context**

The repository has a CLI gate and an API for upload scanning and scan-history persistence. These paths have different trust and operational behavior, so storage acceptance must not be confused with policy enforcement.

**Decision**

The CLI discovers files, invokes scanner adapters, evaluates policy, prints the decision, and returns the enforcement exit code. It does not persist to SQLite. `POST /api/scan-upload` validates one source file, invokes the CLI in a subprocess, validates the returned result, and stores the generated decision/findings. `POST /api/scans` accepts a submitted report, validates its structure and limited consistency, and stores it without running scanners. The current GitHub Actions workflow does not automatically submit CLI output to the API.

**Rationale**

The current structure keeps the CLI's promotion decision independent of API/database availability. The distinction also makes it explicit which API path actually scans source and which merely ingests caller-provided data.

**Consequences**

- A direct CLI scan is fresh scanner execution and policy evaluation, but does not create history records.
- An upload result comes from a fresh scan, but HTTP `201` means processed/stored, not `PASS`; callers must inspect `decision` and `promotion_allowed`.
- Report ingestion can create structurally valid but fabricated records. Persistence does not authenticate provenance or make the decision authoritative.
- No current CI-to-API submission integration is implemented.

**Implementation evidence**

- [`engine/cli.py`](../engine/cli.py) — scan orchestration and policy call.
- [`api/src/app.js`](../api/src/app.js) — distinct `POST /api/scan-upload` and `POST /api/scans` handlers.
- [`api/src/db.js`](../api/src/db.js) — persistence layer.
- [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — CI scans and tests without API submission.
- [`api/tests/api.test.js`](../api/tests/api.test.js) — upload scanning and report-ingestion behavior.

## ADR-006: SQLite for API scan history

**Status:** Accepted (current implementation)

**Context**

The API needs persistence for scan headers and associated findings. The repository does not document the original selection history or define a production deployment workload.

**Decision**

The API uses SQLite through `better-sqlite3`. The database initializes `scans` and `findings` tables, inserts a scan and findings in one transaction, enables foreign keys and WAL mode, sets a 5-second busy timeout, and creates indexes for scan creation time and finding-to-scan lookup. The default file is `api/secureflow.db`; `SECUREFLOW_DB_PATH` can select another path.

**Rationale**

As a current engineering rationale, an embedded database avoids requiring a separate database service for local use and provides transactional relational persistence. This is not asserted as the original historical motivation.

**Consequences**

- The database is file-backed; host filesystem permissions, backup, retention, and recovery are operational responsibilities not implemented by the API.
- Database constraints and transactions support data consistency but do not validate report provenance or authorize clients.
- Capacity, concurrency, and suitability for multi-instance or higher-volume deployment must be assessed against an actual deployment model; none is specified here.

**Implementation evidence**

- [`api/src/db.js`](../api/src/db.js) — SQLite path, schema, indexes, and connection pragmas.
- [`api/src/app.js`](../api/src/app.js) — prepared statements and transactional inserts.
- [`api/tests/api.test.js`](../api/tests/api.test.js) — persistence and retrieval tests.

## ADR-007: Treat client-submitted reports as unverified

**Status:** Accepted as a trust constraint; verification mechanisms are not implemented

**Context**

The API's `POST /api/scans` route accepts a client-provided decision and findings. It checks supported values and basic consistency, but does not rescan source, recompute the complete policy decision, authenticate the caller, or establish report provenance.

**Decision**

An accepted and stored report is not an independently verified scan result. Do not use a client-submitted decision as promotion authorization or authoritative audit evidence solely because the API returned `201`.

**Rationale**

The current validation protects record shape and selected invariants, not the truth of caller-provided claims. The status records the current trust boundary; it does not imply that the missing verification controls have been implemented.

**Consequences**

- A fabricated but consistent `PASS` with no explicitly blocking findings can be stored.
- The API has no authentication or authorization; the server binds to loopback by default, but `SECUREFLOW_HOST` can change the host.
- Before reports are used as authoritative evidence, implement authentication/authorization and a provenance strategy, or recompute policy from trusted scanner evidence.

**Implementation evidence**

- [`api/src/app.js`](../api/src/app.js) — `validateScan` and `POST /api/scans` behavior.
- [`api/src/server.js`](../api/src/server.js) — default and configurable bind host.
- [`api/tests/api.test.js`](../api/tests/api.test.js) — decision consistency and blocking finding validation; no test establishes report provenance.
- [Threat model](threat-model.md) — risk analysis and recommended controls.

## ADR-008: Semgrep and ESLint for JavaScript scanning

**Status:** Accepted (current implementation)

**Context**

The CLI supports JavaScript source alongside Python. JavaScript results must use the same finding and policy contracts while preserving each scanner's native report semantics.

**Decision**

When a target contains `.js`, `.cjs`, or `.mjs` files, the CLI requires both Semgrep and ESLint checks. Semgrep runs with the repository's [`rules/javascript-security.yml`](../rules/javascript-security.yml) configuration and JSON output. ESLint runs using `api/eslint.config.mjs` and its JSON formatter. Semgrep maps `ERROR`, `WARNING`, and `INFO` to `HIGH`, `MEDIUM`, and `LOW`; ESLint severities `2` and `1` map to `HIGH` and `LOW`. Both adapters normalize findings before policy evaluation. TypeScript files are not currently discovered by the CLI, even though the Semgrep rule file declares JavaScript and TypeScript languages.

**Rationale**

Using two configured checks makes both Semgrep's repository-specific rules and the project's ESLint rules required for JavaScript targets. Shared normalization and policy evaluation provide one overall gate contract across the supported languages.

**Consequences**

- A JavaScript target requires the local Semgrep rules and installed ESLint binary/configuration; inability to execute or parse either check results in `ERROR`.
- The local Semgrep rules are narrow, and ESLint coverage depends on the checked-in configuration; neither implies comprehensive JavaScript or TypeScript security analysis.
- The explicit extension list excludes TypeScript files from CLI target selection.

**Implementation evidence**

- [`engine/cli.py`](../engine/cli.py) — JavaScript extension discovery and required check names.
- [`engine/scanners.py`](../engine/scanners.py) — Semgrep/ESLint commands, report parsing, and severity mapping.
- [`rules/javascript-security.yml`](../rules/javascript-security.yml) — local Semgrep rules.
- [`api/eslint.config.mjs`](../api/eslint.config.mjs) — ESLint configuration.
- [`tests/test_scanners.py`](../tests/test_scanners.py) — Semgrep and ESLint normalization tests.
- [`tests/test_cli.py`](../tests/test_cli.py) — safe and vulnerable JavaScript target behavior.

## ADR-009: Verify blocking behavior with a vulnerable fixture

**Status:** Accepted (current workflow)

**Context**

Unit tests cover policy and adapters separately. The CI workflow also needs an end-to-end check that the configured Python scan path reports a blocking finding and denies promotion for a known vulnerable fixture.

**Decision**

Maintain the vulnerable Python fixture and have the verification script and GitHub Actions workflow assert a `FAIL` decision, exit code `1`, `promotion_allowed: false`, and at least one blocking finding. The workflow also runs the test suites and scans the engine directory.

**Rationale**

The fixture exercises the integrated scanner-to-policy behavior for a known case and detects regressions in that path.

**Consequences**

- The test verifies a selected vulnerable case, not comprehensive scanner coverage or production security.
- A safe JavaScript scan and vulnerable JavaScript scan are covered by unit tests, but the hosted workflow's inline gate assertion is specifically for the Bandit fixture.
- Local success does not prove that a hosted GitHub Actions run succeeded; no hosted result is asserted here.

**Implementation evidence**

- [`fixtures/bandit/vulnerable_sample.py`](../fixtures/bandit/vulnerable_sample.py) — intentionally vulnerable fixture.
- [`scripts/verify_gate.py`](../scripts/verify_gate.py) — checks expected decision, exit code, and blocking finding.
- [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — test, vulnerable-fixture verification, and engine scan steps.
- [`tests/test_cli.py`](../tests/test_cli.py) — Python and JavaScript gate behavior tests.

## Revisiting decisions

Review the relevant ADR when scanner selection or normalization changes, policy semantics or exit codes change, the API becomes part of enforcement, report verification or access controls are added, SQLite is replaced, or the CI/deployment integration changes. Do not mark an ADR superseded without identifying its replacement. Recommendations in these records remain proposals until implemented and verified.
