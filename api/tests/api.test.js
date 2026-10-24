
const { test, before, after, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");
const http = require("node:http");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Database = require("better-sqlite3");
const argon2 = require("argon2");
const { spawnSync } = require("node:child_process");
const { ScanLimiter } = require("../src/scan-limiter");

const testDbPath = path.join(__dirname, "secureflow-test.db");
process.env.SECUREFLOW_DB_PATH = testDbPath;
process.env.SECUREFLOW_SESSION_SECRET = "secureflow-test-session-secret-32-bytes-minimum";
process.env.SECUREFLOW_COOKIE_SECURE = "false";
process.env.SECUREFLOW_PUBLIC_ORIGIN = "http://127.0.0.1";

const db = require("../src/db");
const app = require("../src/app");
let agent;
let csrfToken;
let currentUser;

async function createAccount(email = "tester@example.com", password = "correct-horse-battery") {
    const accountAgent = request.agent(app);
    const bootstrap = await accountAgent.get("/api/auth/me");
    const response = await accountAgent
        .post("/api/auth/register")
        .set("X-CSRF-Token", bootstrap.body.csrfToken)
        .send({ email, password });
    return { agent: accountAgent, response };
}

async function postAsUser(route, body, csrf = csrfToken) {
    return agent.post(route)
        .set("X-CSRF-Token", csrf)
        .send(body);
}

function createControlledScanner() {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "secureflow-test-scanner-"));
    const executable = path.join(directory, "scanner");
    fs.writeFileSync(executable, [
        "#!/usr/bin/env node",
        "const fs = require('node:fs');",
        "if (process.env.SECUREFLOW_TEST_SCANNER_STARTED) {",
        "  fs.appendFileSync(process.env.SECUREFLOW_TEST_SCANNER_STARTED, 'started\\n');",
        "}",
        "if (process.env.SECUREFLOW_TEST_SCANNER_FAIL === 'true') process.exit(2);",
        "const gate = process.env.SECUREFLOW_TEST_SCANNER_GATE;",
        "const finish = () => {",
        "  if (gate && !fs.existsSync(gate)) return setTimeout(finish, 5);",
        "  process.stdout.write(JSON.stringify({ decision: 'PASS', promotion_allowed: true, checks: [], errors: [] }));",
        "};",
        "finish();",
        "",
    ].join("\n"));
    fs.chmodSync(executable, 0o700);
    return { directory, executable };
}

async function waitFor(condition) {
    const deadline = Date.now() + 5000;
    while (!condition()) {
        if (Date.now() >= deadline) throw new Error("Timed out waiting for test condition.");
        await new Promise(resolve => setTimeout(resolve, 5));
    }
}

function uploadTempDirectories() {
    return fs.readdirSync(os.tmpdir())
        .filter(name => name.startsWith("secureflow-upload-"))
        .sort();
}

beforeEach(async () => {
    db.exec(`
    DELETE FROM findings;
    DELETE FROM scans;
    DELETE FROM sessions;
    DELETE FROM users;
    DELETE FROM auth_rate_limits;
  `);
    agent = request.agent(app);
    const bootstrap = await agent.get("/api/auth/me");
    const registered = await agent
        .post("/api/auth/register")
        .set("X-CSRF-Token", bootstrap.body.csrfToken)
        .send({ email: "tester@example.com", password: "correct-horse-battery" });
    assert.equal(registered.status, 201);
    csrfToken = registered.body.csrfToken;
    currentUser = registered.body.user;
});

after(() => {
    db.close();
    for (const suffix of ["", "-shm", "-wal"]) {
        const file = testDbPath + suffix;
        if (fs.existsSync(file)) fs.unlinkSync(file);
    }
});

const validScan = {
    target: "demo-project",
    decision: "FAIL",
    promotion_allowed: false,
    findings: [
        {
            scanner: "bandit",
            rule_id: "B602",
            severity: "HIGH",
            title: "Shell execution detected",
            file: "src/example.py",
            line: 12,
            message: "Potential unsafe shell execution.",
            blocking: true
        }
    ]
};

test("health endpoint responds successfully", async () => {
    const response = await request(app).get("/health");

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, { status: "ok" });
});

test("serves the public home and existing scan console", async () => {
    const home = await request(app).get("/");
    const consolePage = await request(app).get("/console.html");

    assert.equal(home.status, 200);
    assert.match(home.text, /Security decisions for every release/);
    assert.match(home.text, /Both ERROR and FAIL deny\s+promotion/);
    assert.equal(consolePage.status, 302);
    assert.equal(consolePage.headers.location, "/login");
    const signedInConsole = await agent.get("/console.html");
    assert.equal(signedInConsole.status, 200);
    assert.match(signedInConsole.text, /id="upload-form"/);
    assert.match(signedInConsole.text, /id="history-filters"/);
    assert.match(signedInConsole.text, /id="previous-page"/);
    assert.match(signedInConsole.text, /id="severity-filter"/);
    assert.match(signedInConsole.text, /id="detail-scanner-filter"/);
});

test("serves real accessible login and registration forms", async () => {
    const login = await request(app).get("/login");
    const register = await request(app).get("/register");
    assert.equal(login.status, 200);
    assert.match(login.text, /autocomplete="current-password"/);
    assert.match(login.text, /role="alert"/);
    assert.equal(register.status, 200);
    assert.match(register.text, /autocomplete="new-password"/);
    assert.match(register.text, /12 to 128 UTF-8 bytes/);
});

test("registration normalizes email and stores only an Argon2id hash", async () => {
    const { response } = await createAccount("  NEW.User@Example.COM ");
    assert.equal(response.status, 201);
    assert.equal(response.body.user.email, "new.user@example.com");
    assert.equal("password" in response.body, false);
    const user = db.prepare("SELECT email_normalized, password_hash FROM users WHERE id = ?")
        .get(response.body.user.id);
    assert.equal(user.email_normalized, "new.user@example.com");
    assert.match(user.password_hash, /^\$argon2id\$/);
    assert.equal(await argon2.verify(user.password_hash, "correct-horse-battery"), true);
    assert.equal(user.password_hash.includes("correct-horse-battery"), false);
});

test("registration rejects duplicate normalized email", async () => {
    const bootstrap = await agent.get("/api/auth/me");
    const duplicate = await agent
        .post("/api/auth/register")
        .set("X-CSRF-Token", bootstrap.body.csrfToken)
        .send({ email: " TESTER@EXAMPLE.COM ", password: "another-valid-password" });
    assert.equal(duplicate.status, 409);
});

test("registration validates email and password length", async () => {
    const accountAgent = request.agent(app);
    const bootstrap = await accountAgent.get("/api/auth/me");
    for (const credentials of [
        { email: "not-an-email", password: "correct-horse-battery" },
        { email: "valid@example.com", password: "short" },
        { email: "valid@example.com", password: "x".repeat(129) },
    ]) {
        const response = await accountAgent
            .post("/api/auth/register")
            .set("X-CSRF-Token", bootstrap.body.csrfToken)
            .send(credentials);
        assert.equal(response.status, 400);
        assert.equal("password" in response.body, false);
    }
});

test("login accepts valid credentials and rotates the session identifier", async () => {
    const accountAgent = request.agent(app);
    const bootstrap = await accountAgent.get("/api/auth/me");
    const beforeCookie = bootstrap.headers["set-cookie"][0].match(/secureflow\.sid=([^;]+)/)[1];
    const login = await accountAgent
        .post("/api/auth/login")
        .set("X-CSRF-Token", bootstrap.body.csrfToken)
        .send({ email: " TESTER@example.com ", password: "correct-horse-battery" });
    const afterCookie = login.headers["set-cookie"][0].match(/secureflow\.sid=([^;]+)/)[1];
    assert.equal(login.status, 200);
    assert.notEqual(afterCookie, beforeCookie);
    assert.equal(login.body.user.id, currentUser.id);
    assert.equal("password_hash" in login.body, false);
    assert.match(login.headers["set-cookie"][0], /HttpOnly/);
    assert.match(login.headers["set-cookie"][0], /SameSite=Lax/);
    assert.doesNotMatch(login.headers["set-cookie"][0], /Secure/);
});

test("production HTTPS configuration issues Secure cookies", () => {
    const secureDbPath = path.join(__dirname, "secure-cookie-test.db");
    const script = `const request=require('supertest');const app=require('./src/app');request(app).get('/api/auth/me').set('X-Forwarded-Proto','https').then((response)=>{if(!response.headers['set-cookie']?.[0]?.includes('Secure'))process.exitCode=1;});`;
    const result = spawnSync(process.execPath, ["-e", script], {
        cwd: path.join(__dirname, ".."),
        encoding: "utf8",
        env: {
            ...process.env,
            NODE_ENV: "production",
            SECUREFLOW_SESSION_SECRET: "secureflow-production-test-session-secret-32-bytes",
            SECUREFLOW_COOKIE_SECURE: "true",
            SECUREFLOW_PUBLIC_ORIGIN: "https://secureflow.example",
            SECUREFLOW_TRUST_PROXY_HOPS: "1",
            SECUREFLOW_DB_PATH: secureDbPath,
        },
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    for (const suffix of ["", "-shm", "-wal"]) {
        const file = secureDbPath + suffix;
        if (fs.existsSync(file)) fs.unlinkSync(file);
    }
});

test("login failures are generic for unknown accounts and incorrect passwords", async () => {
    const accountAgent = request.agent(app);
    const bootstrap = await accountAgent.get("/api/auth/me");
    const unknown = await accountAgent
        .post("/api/auth/login")
        .set("X-CSRF-Token", bootstrap.body.csrfToken)
        .send({ email: "missing@example.com", password: "incorrect-password" });
    const wrongPassword = await accountAgent
        .post("/api/auth/login")
        .set("X-CSRF-Token", bootstrap.body.csrfToken)
        .send({ email: "tester@example.com", password: "incorrect-password" });
    assert.equal(unknown.status, 401);
    assert.equal(wrongPassword.status, 401);
    assert.deepEqual(unknown.body, wrongPassword.body);
    assert.equal(unknown.body.error, "Email or password is incorrect.");
});

test("current-user endpoint is safe and logout invalidates the session", async () => {
    const beforeLogout = await agent.get("/api/auth/me");
    assert.equal(beforeLogout.body.authenticated, true);
    assert.deepEqual(beforeLogout.body.user, currentUser);
    assert.deepEqual(Object.keys(beforeLogout.body).sort(), ["authenticated", "csrfToken", "user"]);
    const logout = await agent
        .post("/api/auth/logout")
        .set("X-CSRF-Token", beforeLogout.body.csrfToken)
        .send({});
    assert.equal(logout.status, 204);
    assert.match(logout.headers["set-cookie"][0], /Expires=/);
    const history = await agent.get("/api/scans");
    assert.equal(history.status, 401);
});

test("rejects missing, expired, and invalid sessions on private APIs", async () => {
    assert.equal((await request(app).get("/api/scans")).status, 401);
    const stored = db.prepare("SELECT sid, sess FROM sessions LIMIT 1").get();
    const sessionData = JSON.parse(stored.sess);
    sessionData.authenticatedAt = Date.now() - 13 * 60 * 60 * 1000;
    db.prepare("UPDATE sessions SET sess = ? WHERE sid = ?").run(JSON.stringify(sessionData), stored.sid);
    assert.equal((await agent.get("/api/scans")).status, 401);
    assert.equal((await request(app).get("/api/scans").set("Cookie", "secureflow.sid=invalid")).status, 401);
});

test("SQLite session expiry is enforced server-side", async () => {
    const stored = db.prepare("SELECT sid FROM sessions ORDER BY rowid DESC LIMIT 1").get();
    db.prepare("UPDATE sessions SET expired = ? WHERE sid = ?").run(Date.now() - 1, stored.sid);
    assert.equal((await agent.get("/api/scans")).status, 401);
});

test("absolute expiry refreshes an anonymous CSRF session for sign-in", async () => {
    const stored = db.prepare("SELECT sid, sess FROM sessions ORDER BY rowid DESC LIMIT 1").get();
    const sessionData = JSON.parse(stored.sess);
    sessionData.authenticatedAt = Date.now() - 13 * 60 * 60 * 1000;
    db.prepare("UPDATE sessions SET sess = ? WHERE sid = ?").run(JSON.stringify(sessionData), stored.sid);
    const expired = await agent.get("/api/auth/me");
    assert.equal(expired.body.authenticated, false);
    assert.equal(typeof expired.body.csrfToken, "string");
    const login = await agent
        .post("/api/auth/login")
        .set("X-CSRF-Token", expired.body.csrfToken)
        .send({ email: "tester@example.com", password: "correct-horse-battery" });
    assert.equal(login.status, 200);
});

test("requires CSRF token and same-origin for authenticated state changes", async () => {
    assert.equal((await agent.post("/api/scans").send(validScan)).status, 403);
    const wrongOrigin = await agent
        .post("/api/scans")
        .set("X-CSRF-Token", csrfToken)
        .set("Origin", "https://attacker.example")
        .send(validScan);
    assert.equal(wrongOrigin.status, 403);
    const accepted = await postAsUser("/api/scans", validScan);
    assert.equal(accepted.status, 201);
});

test("unauthenticated callers cannot read history or submit stored reports", async () => {
    const anonymous = request.agent(app);
    assert.equal((await anonymous.get("/api/scans")).status, 401);
    const bootstrap = await anonymous.get("/api/auth/me");
    const write = await anonymous
        .post("/api/scans")
        .set("X-CSRF-Token", bootstrap.body.csrfToken)
        .send(validScan);
    assert.equal(write.status, 401);
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM scans").get().count, 0);
});

test("registration and repeated failed login attempts are rate limited", async () => {
    db.exec("DELETE FROM auth_rate_limits");
    const accountAgent = request.agent(app);
    let bootstrap = await accountAgent.get("/api/auth/me");
    let token = bootstrap.body.csrfToken;
    for (let attempt = 1; attempt <= 5; attempt += 1) {
        const response = await accountAgent
            .post("/api/auth/register")
            .set("X-CSRF-Token", token)
            .send({ email: `limited${attempt}@example.com`, password: "correct-horse-battery" });
        assert.equal(response.status, 201);
        token = response.body.csrfToken;
    }
    const registrationLimited = await accountAgent
        .post("/api/auth/register")
        .set("X-CSRF-Token", token)
        .send({ email: "limited6@example.com", password: "correct-horse-battery" });
    assert.equal(registrationLimited.status, 429);

    const loginAgent = request.agent(app);
    bootstrap = await loginAgent.get("/api/auth/me");
    for (let attempt = 0; attempt < 5; attempt += 1) {
        const failed = await loginAgent
            .post("/api/auth/login")
            .set("X-CSRF-Token", bootstrap.body.csrfToken)
            .send({ email: "tester@example.com", password: "incorrect-password" });
        assert.equal(failed.status, 401);
    }
    const limited = await loginAgent
        .post("/api/auth/login")
        .set("X-CSRF-Token", bootstrap.body.csrfToken)
        .send({ email: "tester@example.com", password: "incorrect-password" });
    assert.equal(limited.status, 429);
});

test("scan history is isolated between users and ignores client-supplied ownership", async () => {
    const created = await postAsUser("/api/scans", { ...validScan, user_id: 99999 });
    assert.equal(created.status, 201);
    assert.equal(db.prepare("SELECT user_id FROM scans WHERE id = ?").get(created.body.id).user_id, currentUser.id);

    const other = await createAccount("second@example.com");
    assert.equal(other.response.status, 201);
    const list = await other.agent.get("/api/scans");
    const details = await other.agent.get(`/api/scans/${created.body.id}`);
    assert.equal(list.status, 200);
    assert.deepEqual(list.body.scans, []);
    assert.equal(details.status, 404);
});

test("legacy scans remain unowned and invisible in account history", async () => {
    const result = db.prepare(`
        INSERT INTO scans (target, decision, promotion_allowed) VALUES (?, ?, ?)
    `).run("legacy", "PASS", 1);
    const row = db.prepare("SELECT user_id, verified FROM scans WHERE id = ?").get(result.lastInsertRowid);
    assert.equal(row.user_id, null);
    assert.equal(row.verified, 0);
    assert.deepEqual((await agent.get("/api/scans")).body.scans, []);
});

test("anonymous scan upload remains available and its record stays unowned", async () => {
    const anonymous = request.agent(app);
    const bootstrap = await anonymous.get("/api/auth/me");
    const uploaded = await anonymous
        .post("/api/scan-upload")
        .set("X-CSRF-Token", bootstrap.body.csrfToken)
        .send({ filename: "anonymous.py", content: "print('safe')\n" });
    assert.equal(uploaded.status, 201);
    assert.equal(uploaded.body.verified, true);
    assert.equal(db.prepare("SELECT user_id FROM scans WHERE id = ?").get(uploaded.body.id).user_id, null);
});

test("client-submitted PASS reports remain explicitly unverified", async () => {
    const submitted = await postAsUser("/api/scans", {
        target: "caller-claimed-pass",
        decision: "PASS",
        promotion_allowed: true,
        findings: [],
    });
    assert.equal(submitted.status, 201);
    assert.equal(submitted.body.verified, false);
    const stored = db.prepare("SELECT verified FROM scans WHERE id = ?").get(submitted.body.id);
    assert.equal(stored.verified, 0);
    assert.equal((await agent.get("/api/scans")).body.scans[0].verified, false);
});

test("additive migration preserves legacy scans and findings", () => {
    const legacyPath = path.join(__dirname, "legacy-migration-test.db");
    const legacyDb = new Database(legacyPath);
    legacyDb.exec(`
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            decision TEXT NOT NULL,
            promotion_allowed INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT '2025-01-01T00:00:00.000Z'
        );
        CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            scanner TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            file TEXT,
            line INTEGER,
            message TEXT NOT NULL,
            blocking INTEGER NOT NULL
        );
        INSERT INTO scans (target, decision, promotion_allowed) VALUES ('before-auth', 'FAIL', 0);
        INSERT INTO findings (scan_id, scanner, rule_id, severity, title, message, blocking)
        VALUES (1, 'bandit', 'B602', 'HIGH', 'Finding', 'Message', 1);
    `);
    db.initializeSchema(legacyDb);
    const scan = legacyDb.prepare("SELECT target, user_id, verified FROM scans WHERE id = 1").get();
    const finding = legacyDb.prepare("SELECT rule_id FROM findings WHERE scan_id = 1").get();
    assert.deepEqual(scan, { target: "before-auth", user_id: null, verified: 0 });
    assert.deepEqual(finding, { rule_id: "B602" });
    assert.equal(legacyDb.pragma("user_version", { simple: true }), 1);
    legacyDb.close();
    for (const suffix of ["", "-shm", "-wal"]) {
        const file = legacyPath + suffix;
        if (fs.existsSync(file)) fs.unlinkSync(file);
    }
});

test("stores a scan and its findings", async () => {
    const created = await postAsUser("/api/scans", validScan);

    assert.equal(created.status, 201);
    assert.equal(created.body.decision, "FAIL");
    assert.equal(created.body.promotion_allowed, false);

    const details = await agent.get(`/api/scans/${created.body.id}`);

    assert.equal(details.status, 200);
    assert.equal(details.body.findings.length, 1);
    assert.equal(details.body.findings[0].rule_id, "B602");
    assert.equal(details.body.findings[0].blocking, true);
    assert.equal(details.body.verified, false);
});

test("lists recent scans", async () => {
    await postAsUser("/api/scans", validScan);

    const response = await agent.get("/api/scans");

    assert.equal(response.status, 200);
    assert.equal(response.body.scans.length, 1);
    assert.equal(response.body.scans[0].decision, "FAIL");
    assert.deepEqual(response.body.metrics, {
        total: 1,
        pass: 0,
        fail: 0,
        error: 0,
        unverified: 1,
    });
    assert.deepEqual(response.body.pagination, { page: 1, limit: 20, total: 1, pages: 1 });
});

test("empty account history returns zero-valued verified metrics", async () => {
    const response = await agent.get("/api/scans");
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.metrics, {
        total: 0,
        pass: 0,
        fail: 0,
        error: 0,
        unverified: 0,
    });
});

test("scan history pagination, search, decision and verification filters are bounded and owner-scoped", async () => {
    const insert = db.prepare(`
        INSERT INTO scans (target, decision, promotion_allowed, user_id, verified)
        VALUES (?, ?, ?, ?, ?)
    `);
    const otherUserId = Number(db.prepare(`
        INSERT INTO users (email_normalized, password_hash) VALUES ('metrics-other@example.com', 'not-a-login-hash')
    `).run().lastInsertRowid);
    const first = Number(insert.run("repo-alpha", "PASS", 1, currentUser.id, 1).lastInsertRowid);
    insert.run("repo-beta", "FAIL", 0, currentUser.id, 1);
    insert.run("repo-alpha-claimed", "PASS", 1, currentUser.id, 0);
    insert.run("repo-gamma", "ERROR", 0, currentUser.id, 1);
    insert.run("other-user-repo", "ERROR", 0, otherUserId, 1);
    db.prepare(`
        INSERT INTO findings (scan_id, scanner, rule_id, severity, title, message, blocking)
        VALUES (?, 'bandit', 'B101', 'LOW', 'Test finding', 'Message', 0)
    `).run(first);

    const filtered = await agent.get("/api/scans?q=alpha&decision=PASS&verified=true&scanner=bandit&limit=1&page=1");
    assert.equal(filtered.status, 200);
    assert.equal(filtered.body.scans.length, 1);
    assert.equal(filtered.body.scans[0].target, "repo-alpha");
    assert.deepEqual(filtered.body.pagination, { page: 1, limit: 1, total: 1, pages: 1 });
    assert.deepEqual(filtered.body.metrics, {
        total: 4,
        pass: 1,
        fail: 1,
        error: 1,
        unverified: 1,
    });

    const unverified = await agent.get("/api/scans?verified=false");
    assert.equal(unverified.body.scans.length, 1);
    assert.equal(unverified.body.scans[0].verified, false);
    const nextPage = await agent.get("/api/scans?limit=1&page=2");
    assert.equal(nextPage.body.scans.length, 1);
    assert.equal(nextPage.body.pagination.total, 4);
    const errors = await agent.get("/api/scans?decision=ERROR&verified=true");
    assert.equal(errors.body.scans.length, 1);
    assert.equal(errors.body.scans[0].decision, "ERROR");
});

test("scan history rejects invalid and oversized query parameters", async () => {
    for (const query of [
        "?page=0",
        "?page=1000001",
        "?page=1.5",
        "?limit=0",
        "?limit=51",
        "?limit=1&limit=2",
        "?q=abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
        "?decision=UNKNOWN",
        "?verified=yes",
        "?scanner=%20bandit",
        "?scanner=unknown",
    ]) {
        const response = await agent.get(`/api/scans${query}`);
        assert.equal(response.status, 400, query);
    }
});

test("rejects a decision that allows promotion after failure", async () => {
    const response = await postAsUser("/api/scans", { ...validScan, promotion_allowed: true });

    assert.equal(response.status, 400);
});

test("rejects an invalid severity", async () => {
    const badScan = {
        ...validScan,
        findings: [
            { ...validScan.findings[0], severity: "EXTREME" }
        ]
    };

    const response = await postAsUser("/api/scans", badScan);

    assert.equal(response.status, 400);
});

test("rejects path traversal in finding file paths", async () => {
    const badScan = {
        ...validScan,
        findings: [
            { ...validScan.findings[0], file: "../../etc/passwd" }
        ]
    };

    const response = await postAsUser("/api/scans", badScan);

    assert.equal(response.status, 400);
});

test("uses scan IDs as data rather than SQL", async () => {
    const response = await agent
        .get("/api/scans/1%20OR%201=1");

    assert.equal(response.status, 400);
});

test("returns 404 for an unknown scan", async () => {
    const response = await agent.get("/api/scans/999999");

    assert.equal(response.status, 404);
});

test("rejects malformed JSON", async () => {
    const malformed = await agent
        .post("/api/scans")
        .set("Content-Type", "application/json")
        .set("X-CSRF-Token", csrfToken)
        .send('{"decision":');

    assert.equal(malformed.status, 400);
});

test("rejects PASS when a finding is blocking", async () => {
    const contradictoryScan = {
        ...validScan,
        decision: "PASS",
        promotion_allowed: true,
        findings: [
            { ...validScan.findings[0], blocking: true }
        ]
    };

    const response = await postAsUser("/api/scans", contradictoryScan);

    assert.equal(response.status, 400);
});


test("scans safe uploaded Python and allows promotion", async () => {
    const response = await postAsUser("/api/scan-upload", {
        filename: "safe_sample.py",
        content: 'def greet(name):\n    return f"Hello, {name}!"\n',
    });

    assert.equal(response.status, 201);
    assert.equal(response.body.decision, "PASS");
    assert.equal(response.body.promotion_allowed, true);
    assert.equal(response.body.findings.length, 0);

    const details = await agent.get(`/api/scans/${response.body.id}`);

    assert.equal(details.status, 200);
    assert.equal(details.body.decision, "PASS");
    assert.equal(details.body.verified, true);
});


test("blocks vulnerable uploaded Python", async () => {
    const response = await postAsUser("/api/scan-upload", {
        filename: "vulnerable_sample.py",
        content: [
            "import subprocess",
            "",
            "def run_user_command(user_input):",
            "    subprocess.call(user_input, shell=True)",
            "",
        ].join("\n"),
    });

    assert.equal(response.status, 201);
    assert.equal(response.body.decision, "FAIL");
    assert.equal(response.body.promotion_allowed, false);
    assert.ok(
        response.body.findings.some(
            finding => finding.rule_id === "B602" &&
                finding.severity === "HIGH" &&
                finding.blocking
        ),
        JSON.stringify(response.body.findings, null, 2)
    );
});


test("rejects non-Python upload filenames", async () => {
    const response = await postAsUser("/api/scan-upload", {
        filename: "payload.sh",
        content: "echo unsafe",
    });

    assert.equal(response.status, 400);
});

test("rejects oversized uploaded Python source", async () => {
    const response = await postAsUser("/api/scan-upload", {
        filename: "large.py",
        content: "x".repeat(100 * 1024 + 1),
    });

    assert.equal(response.status, 413);
});

test("bounds concurrent uploads and rejects beyond the waiting queue", async () => {
    const previousLimiter = app.locals.scanLimiter;
    const previousPython = process.env.SECUREFLOW_PYTHON;
    const previousStarted = process.env.SECUREFLOW_TEST_SCANNER_STARTED;
    const previousGate = process.env.SECUREFLOW_TEST_SCANNER_GATE;
    const scanner = createControlledScanner();
    const started = path.join(scanner.directory, "started");
    const gate = path.join(scanner.directory, "release");
    const limiter = new ScanLimiter(1, 1);
    let firstRequest;
    let queuedRequest;
    const body = { filename: "queued.py", content: "print('safe')" };

    app.locals.scanLimiter = limiter;
    process.env.SECUREFLOW_PYTHON = scanner.executable;
    process.env.SECUREFLOW_TEST_SCANNER_STARTED = started;
    process.env.SECUREFLOW_TEST_SCANNER_GATE = gate;
    delete process.env.SECUREFLOW_TEST_SCANNER_FAIL;

    try {
        firstRequest = postAsUser("/api/scan-upload", body);
        await waitFor(() => fs.existsSync(started));
        queuedRequest = postAsUser("/api/scan-upload", body);
        await waitFor(() => limiter.queuedCount === 1);

        const beforeSaturation = uploadTempDirectories();
        const rejected = await postAsUser("/api/scan-upload", body);

        assert.equal(rejected.status, 503);
        assert.equal(rejected.headers["retry-after"], "1");
        assert.deepEqual(uploadTempDirectories(), beforeSaturation);
        assert.equal(fs.readFileSync(started, "utf8").trim().split("\n").length, 1);

        fs.writeFileSync(gate, "continue");
        const [first, queued] = await Promise.all([firstRequest, queuedRequest]);
        assert.equal(first.status, 201);
        assert.equal(first.body.decision, "PASS");
        assert.equal(queued.status, 201);
        assert.equal(queued.body.decision, "PASS");
        await waitFor(() => limiter.activeCount === 0);
        assert.equal(limiter.activeCount, 0);
        assert.equal(limiter.queuedCount, 0);
    } finally {
        fs.writeFileSync(gate, "continue");
        if (firstRequest || queuedRequest) {
            await Promise.allSettled([firstRequest, queuedRequest].filter(Boolean));
        }
        app.locals.scanLimiter = previousLimiter;
        if (previousPython === undefined) delete process.env.SECUREFLOW_PYTHON;
        else process.env.SECUREFLOW_PYTHON = previousPython;
        if (previousStarted === undefined) delete process.env.SECUREFLOW_TEST_SCANNER_STARTED;
        else process.env.SECUREFLOW_TEST_SCANNER_STARTED = previousStarted;
        if (previousGate === undefined) delete process.env.SECUREFLOW_TEST_SCANNER_GATE;
        else process.env.SECUREFLOW_TEST_SCANNER_GATE = previousGate;
        delete process.env.SECUREFLOW_TEST_SCANNER_FAIL;
        fs.rmSync(scanner.directory, { recursive: true, force: true });
    }
});

test("scanner failure cleans temporary files and releases upload capacity", async () => {
    const previousLimiter = app.locals.scanLimiter;
    const previousPython = process.env.SECUREFLOW_PYTHON;
    const previousStarted = process.env.SECUREFLOW_TEST_SCANNER_STARTED;
    const previousFailure = process.env.SECUREFLOW_TEST_SCANNER_FAIL;
    const scanner = createControlledScanner();
    const started = path.join(scanner.directory, "started");
    const limiter = new ScanLimiter(1, 0);
    const beforeScan = uploadTempDirectories();

    app.locals.scanLimiter = limiter;
    process.env.SECUREFLOW_PYTHON = scanner.executable;
    process.env.SECUREFLOW_TEST_SCANNER_STARTED = started;
    process.env.SECUREFLOW_TEST_SCANNER_FAIL = "true";

    try {
        const failed = await postAsUser("/api/scan-upload", {
            filename: "failure.py",
            content: "print('scan failure')",
        });

        assert.equal(failed.status, 201);
        assert.equal(failed.body.decision, "ERROR");
        await waitFor(() => limiter.activeCount === 0);
        await waitFor(() => uploadTempDirectories().length === beforeScan.length);
        assert.equal(limiter.activeCount, 0);
        assert.deepEqual(uploadTempDirectories(), beforeScan);

        process.env.SECUREFLOW_TEST_SCANNER_FAIL = "false";
        const recovered = await postAsUser("/api/scan-upload", {
            filename: "recovered.py",
            content: "print('recovered')",
        });
        assert.equal(recovered.status, 201);
        assert.equal(recovered.body.decision, "PASS");
        await waitFor(() => limiter.activeCount === 0);
        await waitFor(() => uploadTempDirectories().length === beforeScan.length);
        assert.equal(limiter.activeCount, 0);
        assert.deepEqual(uploadTempDirectories(), beforeScan);
    } finally {
        app.locals.scanLimiter = previousLimiter;
        if (previousPython === undefined) delete process.env.SECUREFLOW_PYTHON;
        else process.env.SECUREFLOW_PYTHON = previousPython;
        if (previousStarted === undefined) delete process.env.SECUREFLOW_TEST_SCANNER_STARTED;
        else process.env.SECUREFLOW_TEST_SCANNER_STARTED = previousStarted;
        if (previousFailure === undefined) delete process.env.SECUREFLOW_TEST_SCANNER_FAIL;
        else process.env.SECUREFLOW_TEST_SCANNER_FAIL = previousFailure;
        fs.rmSync(scanner.directory, { recursive: true, force: true });
    }
});

test("client disconnect aborts an active scan and releases capacity", async () => {
    const previousLimiter = app.locals.scanLimiter;
    const previousPython = process.env.SECUREFLOW_PYTHON;
    const previousStarted = process.env.SECUREFLOW_TEST_SCANNER_STARTED;
    const previousGate = process.env.SECUREFLOW_TEST_SCANNER_GATE;
    const scanner = createControlledScanner();
    const started = path.join(scanner.directory, "started");
    const gate = path.join(scanner.directory, "release");
    const limiter = new ScanLimiter(1, 0);
    const beforeScan = uploadTempDirectories();
    const server = app.listen(0);
    await new Promise(resolve => server.once("listening", resolve));

    app.locals.scanLimiter = limiter;
    process.env.SECUREFLOW_PYTHON = scanner.executable;
    process.env.SECUREFLOW_TEST_SCANNER_STARTED = started;
    process.env.SECUREFLOW_TEST_SCANNER_GATE = gate;

    try {
        const bootstrap = await request(server).get("/api/auth/me");
        const cookie = bootstrap.headers["set-cookie"][0].split(";")[0];
        const uploadRequest = http.request({
            host: "127.0.0.1",
            port: server.address().port,
            method: "POST",
            path: "/api/scan-upload",
            headers: {
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(JSON.stringify({
                    filename: "disconnect.py",
                    content: "print('disconnect')",
                })),
                Cookie: cookie,
                "X-CSRF-Token": bootstrap.body.csrfToken,
            },
        });
        uploadRequest.on("error", () => { });
        uploadRequest.end(JSON.stringify({
            filename: "disconnect.py",
            content: "print('disconnect')",
        }));

        await waitFor(() => fs.existsSync(started));
        uploadRequest.destroy();
        await waitFor(() => limiter.activeCount === 0);
        await waitFor(() => uploadTempDirectories().length === beforeScan.length);

        const releaseRecovered = await limiter.acquire();
        releaseRecovered();
        assert.equal(limiter.queuedCount, 0);
    } finally {
        fs.writeFileSync(gate, "continue");
        app.locals.scanLimiter = previousLimiter;
        if (previousPython === undefined) delete process.env.SECUREFLOW_PYTHON;
        else process.env.SECUREFLOW_PYTHON = previousPython;
        if (previousStarted === undefined) delete process.env.SECUREFLOW_TEST_SCANNER_STARTED;
        else process.env.SECUREFLOW_TEST_SCANNER_STARTED = previousStarted;
        if (previousGate === undefined) delete process.env.SECUREFLOW_TEST_SCANNER_GATE;
        else process.env.SECUREFLOW_TEST_SCANNER_GATE = previousGate;
        delete process.env.SECUREFLOW_TEST_SCANNER_FAIL;
        await new Promise(resolve => server.close(resolve));
        fs.rmSync(scanner.directory, { recursive: true, force: true });
    }
});


test("scans safe uploaded JavaScript and allows promotion", async () => {
    const response = await postAsUser("/api/scan-upload", {
        filename: "safe_sample.js",
        content: 'console.log("safe");\n',
    });

    assert.equal(response.status, 201);
    assert.equal(response.body.decision, "PASS");
    assert.equal(response.body.promotion_allowed, true);
    assert.deepEqual(response.body.findings, []);
});

test("blocks vulnerable uploaded JavaScript", async () => {
    const response = await postAsUser("/api/scan-upload", {
        filename: "vulnerable_sample.js",
        content: 'eval("console.log(1)");\n',
    });

    assert.equal(response.status, 201);
    assert.equal(response.body.decision, "FAIL");
    assert.equal(response.body.promotion_allowed, false);
    assert.ok(
        response.body.findings.some(
            finding =>
                finding.rule_id.includes("eval") &&
                finding.blocking === true
        ),
        JSON.stringify(response.body.findings, null, 2)
    );
});

test("accepts supported JavaScript module extensions", async () => {
    for (const filename of ["safe.cjs", "safe.mjs"]) {
        const response = await postAsUser("/api/scan-upload", {
            filename,
            content: 'console.log("safe");\n',
        });

        assert.equal(response.status, 201, filename);
        assert.equal(response.body.decision, "PASS", filename);
    }
});
