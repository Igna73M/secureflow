# SecureFlow Architecture Decision Records

## 1. Purpose

This document records significant architectural and security decisions made in SecureFlow, including the rationale, trade-offs, and consequences.

These records describe the current implementation and its design direction. A decision marked **Accepted** describes the chosen approach; it does not, by itself, prove that all related production-hardening work is complete.

## 2. Decision Summary

| ID | Decision | Status |
|---|---|---|
| ADR-001 | Fail closed when checks are missing or fail | Accepted |
| ADR-002 | Start with Bandit as the Python security scanner | Accepted |
| ADR-003 | Use structured JSON and distinct CLI exit codes | Accepted |
| ADR-004 | Bound scanner execution and avoid shell invocation | Accepted |
| ADR-005 | Separate CLI policy enforcement from API reporting | Accepted |
| ADR-006 | Use SQLite for scan-report persistence | Accepted |
| ADR-007 | Verify gate behavior in CI using a vulnerable fixture | Accepted |
| ADR-008 | Treat API-submitted decisions as untrusted until verified | Security requirement; implementation incomplete |

---

## ADR-001: Fail-Closed Policy Evaluation

**Status:** Accepted

### Context

A CI/CD security gate must not authorize promotion when required security checks are missing, fail, or produce an error. Treating an incomplete assessment as success would undermine the purpose of the gate.

### Decision

SecureFlow allows promotion only when policy evaluation returns `PASS`. Blocking findings, failed checks, missing required checks, and policy-validation errors must not authorize promotion.

### Consequences

- Incomplete or unsuccessful checks deny promotion.
- CI can distinguish a security failure from an evaluation error.
- The gate may block a build when a required scanner is unavailable, which is intentional.
- Downstream workflows must enforce the CLI exit code rather than ignoring it.

### Verification

Automated tests should cover successful evaluation, blocking findings, failed checks, missing required checks, and invalid inputs.

---

## ADR-002: Start With Bandit as the Initial Scanner

**Status:** Accepted

### Context

SecureFlow needs a concrete scanner integration to establish the execution, normalization, policy, and CI verification path before adding multiple scanner types.

### Decision

Use Bandit as the initial scanner integration for Python source code.

### Rationale

- Provides a focused initial scope.
- Enables a reproducible vulnerable fixture.
- Allows the gate behavior to be tested without implementing several scanner adapters simultaneously.

### Consequences

- Current scanner coverage is limited to the implemented Bandit integration.
- Bandit findings are not a complete assessment of application security.
- Additional scanners will require adapters, result normalization, failure semantics, and dedicated tests.
- Adding a scanner must not weaken fail-closed policy behavior.

### Verification

Run Bandit against the deliberately vulnerable fixture and verify that blocking findings result in `FAIL` and promotion denial.

---

## ADR-003: Use JSON Results and Distinct CLI Exit Codes

**Status:** Accepted

### Context

CI systems need a machine-readable decision and a reliable process status to determine whether a pipeline should continue.

### Decision

The CLI emits a structured JSON result and uses these exit codes:

| Exit code | Meaning |
|---:|---|
| `0` | `PASS` — promotion allowed |
| `1` | `FAIL` — promotion denied |
| `2` | `ERROR` — promotion denied |

### Consequences

- Automation can consume results without parsing human-readable prose.
- Security failures are distinguishable from execution or evaluation errors.
- CI integrations must preserve and enforce the exit code.
- Output-schema changes should be treated as compatibility changes and tested.

### Verification

Test the result schema and the expected exit code for PASS, FAIL, and ERROR cases.

---

## ADR-004: Bound Scanner Execution and Avoid Shell Invocation

**Status:** Accepted

### Context

Scanner processes operate on repository content that may be untrusted. Unbounded execution or unsafe command construction can introduce resource-exhaustion and command-injection risks.

### Decision

Invoke scanner commands using argument lists with `shell=False`, apply an execution timeout, clean up timed-out process groups, and limit captured output.

### Consequences

- Target paths are passed as arguments rather than interpolated into shell command strings.
- Long-running scanner processes cannot run indefinitely under the configured timeout.
- Excessive output is bounded.
- Timeout and output-limit conditions must be handled as errors, not mistaken for successful scans.

### Verification

Maintain tests for command construction, timeout handling, process cleanup, output limits, and scanner-error behavior.

---

## ADR-005: Separate Policy Enforcement From API Reporting

**Status:** Accepted

### Context

The CLI is responsible for executing the scan and evaluating the policy. The API provides a separate way to persist and retrieve scan reports.

Combining report storage with the enforcement path would couple promotion decisions to the availability of the reporting service.

### Decision

Keep the CLI decision path and Express reporting API as separate components.

The CLI runs the scanner and evaluates policy. The API accepts and stores submitted reports and provides retrieval endpoints.

### Consequences

- The CLI can evaluate policy without requiring the reporting API to be available.
- The reporting API can support scan history and dashboard use cases.
- The current CI workflow does not automatically submit CLI results to the API.
- API persistence is not proof that the submitted scan decision is authentic or correct.
- Any future integration must define report provenance, authentication, and trust boundaries explicitly.

### Verification

Test CLI policy behavior independently from API persistence and API route behavior.

---

## ADR-006: Use SQLite for Scan-Report Persistence

**Status:** Accepted

### Context

SecureFlow needs persistent storage for scan reports and their associated findings without requiring a separate database server for local development.

### Decision

Use SQLite through `better-sqlite3` for the reporting API.

### Rationale

- Simple local setup.
- No separate database service for the initial implementation.
- Transactional storage and relational constraints support report consistency.
- Appropriate for an initial single-instance deployment model.

### Consequences

- Database file permissions and backups are operational security responsibilities.
- Concurrent-write behavior and storage capacity should be evaluated for the intended workload.
- Multi-instance or higher-volume deployments may require a different persistence architecture.
- Database constraints improve consistency but do not authenticate report submitters or establish report provenance.

### Verification

Test database initialization, persistence, foreign-key behavior, and API error handling. Document backup and retention procedures before production use.

---

## ADR-007: Verify Gate Behavior With a Vulnerable Fixture in CI

**Status:** Accepted

### Context

Unit tests alone may not prove that the complete scanner-to-policy path blocks vulnerable input and propagates the expected result to CI.

### Decision

Maintain a deliberately vulnerable Python fixture and a verification script that asserts a `FAIL` decision, denied promotion, and at least one blocking finding. Run this verification from the project’s CI target.

### Consequences

- The end-to-end blocking path has a reproducible test case.
- Fixture changes must preserve the intended finding and expected decision.
- Scanner or policy changes that break the expected behavior are detected.
- A complementary safe-target assertion is recommended to verify the successful path explicitly.

### Verification

Run:

```bash
python scripts/verify_gate.py
```

Then run:

```bash
make ci
```

Local success does not prove that hosted GitHub Actions completed successfully. Hosted workflow status must be verified separately.

---

## ADR-008: Treat API-Submitted Decisions as Untrusted Until Verified

**Status:** Security requirement; implementation incomplete

### Context

The API accepts submitted scan reports and validates their structure and certain consistency conditions. It does not independently rerun the scanner or fully recalculate the policy decision from trusted scanner evidence.

A caller may therefore submit a report that is structurally consistent but does not represent a genuine scan result.

### Decision

Do not treat an API-submitted decision as an authoritative security-gate result solely because the API accepted and stored it.

Before relying on API reports for deployment authorization or trusted audit evidence, SecureFlow must establish report authenticity and decision integrity.

### Required follow-up

- Add authentication and authorization appropriate to the deployment.
- Define a trusted method for establishing report provenance.
- Recalculate the policy decision server-side from trusted evidence, or otherwise verify the decision cryptographically and operationally.
- Distinguish imported or unverified reports from verified gate results.
- Keep deployment enforcement tied to a trusted gate result, not merely a stored database record.

### Consequences

- The API should remain restricted to a trusted local environment until appropriate access controls exist.
- Report storage and report verification are separate security responsibilities.
- A successful API response means the request was accepted under the implemented checks; it does not establish that the source code passed an independently verified scan.

### Verification

Add tests showing that untrusted clients cannot create or alter authoritative gate decisions and that report provenance is checked before a report is treated as verified.

---

## 3. Revisiting Decisions

Revisit these records when:

- New scanner integrations are added.
- Policy semantics or exit codes change.
- The API begins participating in enforcement.
- Authentication, authorization, or report-verification mechanisms are introduced.
- SQLite is replaced or the deployment model changes.
- CI or release architecture changes materially.

When a decision is superseded, retain the old record with its status marked **Superseded** and reference the replacement decision. This preserves the reasoning behind earlier design choices.
