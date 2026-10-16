
const express = require("express");
const db = require("./db");

const app = express();

app.disable("x-powered-by");
app.use(express.json({ limit: "256kb", strict: true }));

const VALID_DECISIONS = new Set(["PASS", "FAIL", "ERROR"]);
const VALID_SEVERITIES = new Set([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
]);

function isNonEmptyString(value, maxLength) {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    value.length <= maxLength
  );
}

function isSafeRelativePath(value) {
  if (value === null) return true;
  if (typeof value !== "string" || value.length > 500) return false;
  if (value.includes("\0")) return false;

  const normalized = value.replace(/\\/g, "/");
  return (
    !normalized.startsWith("/") &&
    !/^[a-zA-Z]:/.test(normalized) &&
    !normalized.split("/").includes("..")
  );
}

function validateScan(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return "Request body must be a JSON object.";
  }

  if (!isNonEmptyString(body.target, 1000)) {
    return "target must be a non-empty string of at most 1000 characters.";
  }

  if (!VALID_DECISIONS.has(body.decision)) {
    return "decision must be PASS, FAIL, or ERROR.";
  }

  if (typeof body.promotion_allowed !== "boolean") {
    return "promotion_allowed must be a boolean.";
  }

  // Fail closed: only PASS may allow promotion.
  if (body.promotion_allowed !== (body.decision === "PASS")) {
    return "promotion_allowed must be true exactly when decision is PASS.";
  }
  if (
  body.decision === "PASS" &&
  Array.isArray(body.findings) &&
  body.findings.some((finding) =>
    finding &&
    typeof finding === "object" &&
    finding.blocking === true
  )
) {
  return "A scan with blocking findings cannot have decision PASS.";
}

  if (!Array.isArray(body.findings) || body.findings.length > 1000) {
    return "findings must be an array with at most 1000 entries.";
  }

  for (const [index, finding] of body.findings.entries()) {
    if (!finding || typeof finding !== "object" || Array.isArray(finding)) {
      return `findings[${index}] must be an object.`;
    }

    if (!isNonEmptyString(finding.scanner, 100)) {
      return `findings[${index}].scanner is invalid.`;
    }

    if (!isNonEmptyString(finding.rule_id, 100)) {
      return `findings[${index}].rule_id is invalid.`;
    }

    if (!VALID_SEVERITIES.has(finding.severity)) {
      return `findings[${index}].severity is invalid.`;
    }

    if (!isNonEmptyString(finding.title, 500)) {
      return `findings[${index}].title is invalid.`;
    }

    if (
      finding.file !== null &&
      finding.file !== undefined &&
      !isSafeRelativePath(finding.file)
    ) {
      return `findings[${index}].file must be a safe relative path or null.`;
    }

    if (
      finding.line !== null &&
      finding.line !== undefined &&
      (!Number.isSafeInteger(finding.line) || finding.line < 1)
    ) {
      return `findings[${index}].line must be a positive integer or null.`;
    }

    if (!isNonEmptyString(finding.message, 2000)) {
      return `findings[${index}].message is invalid.`;
    }

    if (typeof finding.blocking !== "boolean") {
      return `findings[${index}].blocking must be a boolean.`;
    }
  }

  return null;
}

const insertScan = db.prepare(`
  INSERT INTO scans (target, decision, promotion_allowed)
  VALUES (?, ?, ?)
`);

const insertFinding = db.prepare(`
  INSERT INTO findings (
    scan_id, scanner, rule_id, severity, title,
    file, line, message, blocking
  )
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertScanWithFindings = db.transaction((body) => {
  const scanResult = insertScan.run(
    body.target.trim(),
    body.decision,
    body.promotion_allowed ? 1 : 0
  );

  const scanId = Number(scanResult.lastInsertRowid);

  for (const finding of body.findings) {
    insertFinding.run(
      scanId,
      finding.scanner.trim(),
      finding.rule_id.trim(),
      finding.severity,
      finding.title.trim(),
      finding.file ?? null,
      finding.line ?? null,
      finding.message.trim(),
      finding.blocking ? 1 : 0
    );
  }

  return scanId;
});

app.get("/health", (req, res) => {
  try {
    db.prepare("SELECT 1").get();
    res.json({ status: "ok" });
  } catch {
    res.status(503).json({ status: "unavailable" });
  }
});

app.post("/api/scans", (req, res) => {
  const validationError = validateScan(req.body);

  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  try {
    const id = insertScanWithFindings(req.body);
    return res.status(201).json({
      id,
      decision: req.body.decision,
      promotion_allowed: req.body.promotion_allowed,
    });
  } catch {
    return res.status(500).json({ error: "Could not save scan." });
  }
});

app.get("/api/scans", (req, res) => {
  const rawLimit = req.query.limit ?? "20";
  const limit = Number(rawLimit);

  if (
    typeof rawLimit !== "string" ||
    !/^\d+$/.test(rawLimit) ||
    !Number.isSafeInteger(limit) ||
    limit < 1 ||
    limit > 100
  ) {
    return res.status(400).json({ error: "limit must be an integer from 1 to 100." });
  }

  const scans = db.prepare(`
    SELECT id, target, decision, promotion_allowed, created_at
    FROM scans
    ORDER BY id DESC
    LIMIT ?
  `).all(limit);

  return res.json({
    scans: scans.map((scan) => ({
      ...scan,
      promotion_allowed: Boolean(scan.promotion_allowed),
    })),
  });
});

app.get("/api/scans/:id", (req, res) => {
  if (!/^[1-9]\d*$/.test(req.params.id)) {
    return res.status(400).json({ error: "id must be a positive integer." });
  }

  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id)) {
    return res.status(400).json({ error: "id is outside the supported range." });
  }

  const scan = db.prepare(`
    SELECT id, target, decision, promotion_allowed, created_at
    FROM scans
    WHERE id = ?
  `).get(id);

  if (!scan) {
    return res.status(404).json({ error: "Scan not found." });
  }

  const findings = db.prepare(`
    SELECT id, scanner, rule_id, severity, title, file, line, message, blocking
    FROM findings
    WHERE scan_id = ?
    ORDER BY id ASC
  `).all(id);

  return res.json({
    ...scan,
    promotion_allowed: Boolean(scan.promotion_allowed),
    findings: findings.map((finding) => ({
      ...finding,
      blocking: Boolean(finding.blocking),
    })),
  });
});

// Malformed JSON and oversized payload handling.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Malformed JSON." });
  }

  if (err.type === "entity.too.large") {
    return res.status(413).json({ error: "Request body is too large." });
  }

  return res.status(500).json({ error: "Internal server error." });
});

module.exports = app;
