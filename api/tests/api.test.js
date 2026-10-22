
const { test, before, after, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");
const fs = require("node:fs");
const path = require("node:path");

const testDbPath = path.join(__dirname, "secureflow-test.db");
process.env.SECUREFLOW_DB_PATH = testDbPath;

const db = require("../src/db");
const app = require("../src/app");

before(() => {
  db.exec(`
    DELETE FROM findings;
    DELETE FROM scans;
  `);
});

beforeEach(() => {
  db.exec(`
    DELETE FROM findings;
    DELETE FROM scans;
  `);
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

test("stores a scan and its findings", async () => {
  const created = await request(app)
    .post("/api/scans")
    .send(validScan);

  assert.equal(created.status, 201);
  assert.equal(created.body.decision, "FAIL");
  assert.equal(created.body.promotion_allowed, false);

  const details = await request(app)
    .get(`/api/scans/${created.body.id}`);

  assert.equal(details.status, 200);
  assert.equal(details.body.findings.length, 1);
  assert.equal(details.body.findings[0].rule_id, "B602");
  assert.equal(details.body.findings[0].blocking, true);
});

test("lists recent scans", async () => {
  await request(app).post("/api/scans").send(validScan);

  const response = await request(app).get("/api/scans");

  assert.equal(response.status, 200);
  assert.equal(response.body.scans.length, 1);
  assert.equal(response.body.scans[0].decision, "FAIL");
});

test("rejects a decision that allows promotion after failure", async () => {
  const response = await request(app)
    .post("/api/scans")
    .send({ ...validScan, promotion_allowed: true });

  assert.equal(response.status, 400);
});

test("rejects an invalid severity", async () => {
  const badScan = {
    ...validScan,
    findings: [
      { ...validScan.findings[0], severity: "EXTREME" }
    ]
  };

  const response = await request(app)
    .post("/api/scans")
    .send(badScan);

  assert.equal(response.status, 400);
});

test("rejects path traversal in finding file paths", async () => {
  const badScan = {
    ...validScan,
    findings: [
      { ...validScan.findings[0], file: "../../etc/passwd" }
    ]
  };

  const response = await request(app)
    .post("/api/scans")
    .send(badScan);

  assert.equal(response.status, 400);
});

test("uses scan IDs as data rather than SQL", async () => {
  const response = await request(app)
    .get("/api/scans/1%20OR%201=1");

  assert.equal(response.status, 400);
});

test("returns 404 for an unknown scan", async () => {
  const response = await request(app).get("/api/scans/999999");

  assert.equal(response.status, 404);
});

test("rejects malformed JSON", async () => {
  const response = await request(app)
    .post("/api/scans")
    .set("Content-Type", "application/json")
    .send('{"decision":');

  assert.equal(response.status, 400);
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

  const response = await request(app)
    .post("/api/scans")
    .send(contradictoryScan);

  assert.equal(response.status, 400);
});


test("scans safe uploaded Python and allows promotion", async () => {
  const response = await request(app)
    .post("/api/scan-upload")
    .send({
      filename: "safe_sample.py",
      content: 'def greet(name):\n    return f"Hello, {name}!"\n',
    });

  assert.equal(response.status, 201);
  assert.equal(response.body.decision, "PASS");
  assert.equal(response.body.promotion_allowed, true);
  assert.equal(response.body.findings.length, 0);

  const details = await request(app)
    .get(`/api/scans/${response.body.id}`);

  assert.equal(details.status, 200);
  assert.equal(details.body.decision, "PASS");
});


test("blocks vulnerable uploaded Python", async () => {
  const response = await request(app)
    .post("/api/scan-upload")
    .send({
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
  const response = await request(app)
    .post("/api/scan-upload")
    .send({
      filename: "payload.sh",
      content: "echo unsafe",
    });

  assert.equal(response.status, 400);
});

test("rejects oversized uploaded Python source", async () => {
  const response = await request(app)
    .post("/api/scan-upload")
    .send({
      filename: "large.py",
      content: "x".repeat(100 * 1024 + 1),
    });

  assert.equal(response.status, 413);
});
