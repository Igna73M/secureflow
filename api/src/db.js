
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


function initializeSchema(database) {
    const version = database.pragma("user_version", { simple: true });
    if (version > 1) {
        throw new Error("Database schema version is newer than this application supports.");
    }

    database.pragma("foreign_keys = ON");
    database.pragma("journal_mode = WAL");
    database.pragma("busy_timeout = 5000");

    database.exec(`
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target TEXT NOT NULL,
      decision TEXT NOT NULL CHECK (decision IN ('PASS', 'FAIL', 'ERROR')),
      promotion_allowed INTEGER NOT NULL CHECK (promotion_allowed IN (0, 1)),
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );

    CREATE TABLE IF NOT EXISTS findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER NOT NULL,
      scanner TEXT NOT NULL,
      rule_id TEXT NOT NULL,
      severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
      title TEXT NOT NULL,
      file TEXT,
      line INTEGER,
      message TEXT NOT NULL,
      blocking INTEGER NOT NULL CHECK (blocking IN (0, 1)),
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
    CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
  `);

    if (version > 1) throw new Error("Database schema version is newer than this application supports.");
    if (version === 1) return;

    const columns = new Set(database.pragma("table_info(scans)").map((column) => column.name));
    const migrate = database.transaction(() => {
        database.exec(`
      CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email_normalized TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      );

      CREATE TABLE sessions (
        sid TEXT PRIMARY KEY,
        sess TEXT NOT NULL,
        expired INTEGER NOT NULL
      );
      CREATE INDEX idx_sessions_expired ON sessions(expired);

      CREATE TABLE auth_rate_limits (
        bucket_key TEXT PRIMARY KEY,
        window_started INTEGER NOT NULL,
        attempts INTEGER NOT NULL
      );
    `);

        if (!columns.has("user_id")) {
            database.exec("ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL");
        }
        if (!columns.has("verified")) {
            database.exec("ALTER TABLE scans ADD COLUMN verified INTEGER NOT NULL DEFAULT 0 CHECK (verified IN (0, 1))");
        }
        database.exec("CREATE INDEX idx_scans_user_id ON scans(user_id)");
        database.pragma("user_version = 1");
    });

    migrate.immediate();
}

initializeSchema(db);

module.exports = db;
module.exports.initializeSchema = initializeSchema;
