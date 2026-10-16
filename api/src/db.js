
const Database = require("better-sqlite3");
const path = require("node:path");
const fs = require("node:fs");

const configuredPath = process.env.SECUREFLOW_DB_PATH;
const dbPath = configuredPath
  ? path.resolve(configuredPath)
  : path.resolve(__dirname, "../secureflow.db");

// Ensure the parent directory exists before opening the database.
fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const db = new Database(dbPath);

// SQLite safeguards.
db.pragma("foreign_keys = ON");
db.pragma("journal_mode = WAL");
db.pragma("busy_timeout = 5000");

db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    decision TEXT NOT NULL
      CHECK (decision IN ('PASS', 'FAIL', 'ERROR')),
    promotion_allowed INTEGER NOT NULL
      CHECK (promotion_allowed IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );

  CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    scanner TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL
      CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    title TEXT NOT NULL,
    file TEXT,
    line INTEGER,
    message TEXT NOT NULL,
    blocking INTEGER NOT NULL
      CHECK (blocking IN (0, 1)),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_scans_created_at
    ON scans(created_at);

  CREATE INDEX IF NOT EXISTS idx_findings_scan_id
    ON findings(scan_id);
`);

module.exports = db;
