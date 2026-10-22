"use strict";

const tableBody = document.getElementById("scan-table");
const statusMessage = document.getElementById("status-message");
const refreshButton = document.getElementById("refresh-button");
const findingsContainer = document.getElementById("findings-container");
const uploadForm = document.getElementById("upload-form");
const pythonFileInput = document.getElementById("python-file");
const uploadButton = document.getElementById("upload-button");
const uploadResult = document.getElementById("upload-result");
const latestDecisionTitle = document.getElementById("latest-decision-title");
const latestDecisionSubtitle = document.getElementById("latest-decision-subtitle");
const latestDecisionBadge = document.getElementById("latest-decision-badge");
const latestDecisionReason = document.getElementById("latest-decision-reason");

let selectedScanId = null;

function makeElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = String(text);
    return element;
}

async function fetchJson(url) {
    const response = await fetch(url, {
        headers: { Accept: "application/json" }
    });

    if (!response.ok) {
        throw new Error(`Request failed with HTTP ${response.status}`);
    }

    return response.json();
}

function formatDate(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime())
        ? "Unknown"
        : date.toLocaleString();
}

function decisionBadge(decision) {
    return makeElement("span", `decision ${decision}`, decision);
}

function updateStatistics(scans) {
    document.getElementById("total-scans").textContent = scans.length;
    document.getElementById("passed-scans").textContent = scans.filter(scan => scan.decision === "PASS").length;
    document.getElementById("failed-scans").textContent = scans.filter(scan => scan.decision === "FAIL").length;
    document.getElementById("error-scans").textContent = scans.filter(scan => scan.decision === "ERROR").length;
}


function renderLatestDecision(scan) {
    if (!scan) {
        latestDecisionTitle.textContent = "No scans recorded";
        latestDecisionSubtitle.textContent = "Run a scan to evaluate whether promotion is allowed.";
        latestDecisionBadge.className = "decision ERROR";
        latestDecisionBadge.textContent = "PENDING";
        latestDecisionReason.textContent = "No security decision is available yet.";
        return;
    }

    latestDecisionTitle.textContent = scan.promotion_allowed ? "Promotion allowed" : "Promotion blocked";

    latestDecisionSubtitle.textContent = `Scan #${scan.id} · ${scan.target} · ${formatDate(scan.created_at)}`;

    latestDecisionBadge.className = `decision ${scan.decision}`;
    latestDecisionBadge.textContent = scan.decision;

    if (scan.decision === "ERROR") {
        latestDecisionReason.textContent = "The scan encountered an error. Resolve the error and rerun the scan.";
    } else if (scan.decision === "FAIL") {
        latestDecisionReason.textContent = "The security policy rejected this scan. Review the findings below before promotion.";
    } else if (scan.promotion_allowed) {
        latestDecisionReason.textContent = "The scan passed the configured security policy. Promotion is allowed.";
    } else {
        latestDecisionReason.textContent = "Promotion is blocked because the scan did not authorize it.";
    }
}

function renderScans(scans) {
    tableBody.replaceChildren();

    if (scans.length === 0) {
        const row = makeElement("tr");
        const cell = makeElement("td", "empty-state", "No scans recorded yet.");
        cell.colSpan = 5;
        row.append(cell);
        tableBody.append(row);
        return;
    }

    for (const scan of scans) {
        const row = makeElement("tr");
        row.dataset.scanId = String(scan.id);
        row.tabIndex = 0;
        row.setAttribute("role", "button");
        row.setAttribute("aria-label", `View scan ${scan.id}`);
        row.setAttribute(
            "aria-selected",
            String(scan.id === selectedScanId)
        );

        const idCell = makeElement("td", "", `#${scan.id}`);
        const targetCell = makeElement("td", "", scan.target);
        const decisionCell = makeElement("td");
        decisionCell.append(decisionBadge(scan.decision));

        const promotionCell = makeElement(
            "td",
            scan.promotion_allowed ? "allowed" : "blocked",
            scan.promotion_allowed ? "Allowed" : "Blocked"
        );

        const dateCell = makeElement("td", "", formatDate(scan.created_at));

        row.append(idCell, targetCell, decisionCell, promotionCell, dateCell);

        row.addEventListener("click", () => loadScanDetails(scan.id));
        row.addEventListener("keydown", event => {
            if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                loadScanDetails(scan.id);
            }
        });

        tableBody.append(row);
    }
}

function renderFindings(scan) {
    findingsContainer.replaceChildren();

    if (scan.findings.length === 0) {
        findingsContainer.append(
            makeElement("p", "empty-state", "No findings recorded for this scan.")
        );
        return;
    }

    for (const finding of scan.findings) {
        const card = makeElement("article", "finding");
        const heading = makeElement("h3", "", finding.title);
        const rule = makeElement(
            "p",
            "",
            `${finding.scanner} · ${finding.rule_id} · ${finding.severity}`
        );
        const location = makeElement(
            "p",
            "",
            `Location: ${finding.file || "Unknown"}${finding.line ? `:${finding.line}` : ""}`
        );
        const message = makeElement("p", "", finding.message);
        const blocking = makeElement(
            "p",
            finding.blocking ? "blocking" : "non-blocking",
            finding.blocking ? "Blocking finding" : "Non-blocking finding"
        );

        card.append(heading, rule, location, message, blocking);
        findingsContainer.append(card);
    }
}

async function loadScanDetails(id) {
    selectedScanId = id;
    statusMessage.textContent = `Loading scan #${id}…`;

    for (const row of tableBody.querySelectorAll("[data-scan-id]")) {
        row.setAttribute(
            "aria-selected",
            String(Number(row.dataset.scanId) === id)
        );
    }

    try {
        const scan = await fetchJson(`/api/scans/${id}`);

        document.getElementById("detail-subtitle").textContent =
            `Scan #${scan.id} · ${scan.target} · ${formatDate(scan.created_at)}`;

        renderFindings(scan);
        statusMessage.textContent =
            `Viewing scan #${id} — ${scan.decision}. ` +
            `Promotion ${scan.promotion_allowed ? "allowed" : "blocked"}.`;
    } catch (error) {
        statusMessage.textContent = `Could not load scan details: ${error.message}`;
        findingsContainer.replaceChildren(
            makeElement("p", "empty-state", "Unable to load findings.")
        );
    }
}

async function loadHistory() {
    refreshButton.disabled = true;
    statusMessage.textContent = "Loading scan history…";

    try {
        const data = await fetchJson("/api/scans?limit=100");
        const scans = data.scans;

        updateStatistics(scans);
        renderLatestDecision(scans[0] || null);
        renderScans(scans);

        statusMessage.textContent = `Loaded ${scans.length} recent scan${scans.length === 1 ? "" : "s"}.`;

        if (selectedScanId !== null && scans.some(scan => scan.id === selectedScanId)) {
            await loadScanDetails(selectedScanId);
        } else if (scans.length > 0) {
            await loadScanDetails(scans[0].id);
        } else {
            selectedScanId = null;
            document.getElementById("detail-subtitle").textContent =
                "No scans available.";
            findingsContainer.replaceChildren(
                makeElement("p", "empty-state", "Run a scan to see findings here.")
            );
        }
    } catch (error) {
        statusMessage.textContent =
            `Could not load scan history: ${error.message}`;
        tableBody.replaceChildren();

        const row = makeElement("tr");
        const cell = makeElement(
            "td",
            "empty-state",
            "API unavailable. Check that the SecureFlow server is running."
        );
        cell.colSpan = 5;
        row.append(cell);
        tableBody.append(row);
    } finally {
        refreshButton.disabled = false;
    }
}


function renderUploadResult(result) {
    uploadResult.replaceChildren();
    uploadResult.hidden = false;

    const heading = makeElement(
        "h3",
        result.decision === "PASS"
            ? "pass-text"
            : result.decision === "FAIL"
                ? "fail-text"
                : "",
        `Scan result: ${result.decision}`
    );

    const summary = makeElement(
        "p",
        "",
        result.promotion_allowed
            ? "Promotion allowed."
            : "Promotion blocked."
    );

    uploadResult.append(heading, summary);

    if (Array.isArray(result.errors)) {
        for (const error of result.errors) {
            uploadResult.append(makeElement("p", "fail-text", error));
        }
    }

    const findings = Array.isArray(result.findings)
        ? result.findings
        : [];

    if (findings.length === 0) {
        uploadResult.append(
            makeElement("p", "empty-state", "No findings returned.")
        );
        return;
    }

    for (const finding of findings) {
        const card = makeElement("article", "finding");
        card.append(
            makeElement("h4", "", finding.title || finding.rule_id),
            makeElement(
                "p",
                "",
                `${finding.scanner} · ${finding.rule_id} · ${finding.severity}`
            ),
            makeElement(
                "p",
                "",
                `Location: ${finding.file || "Unknown"}${finding.line ? `:${finding.line}` : ""
                }`
            ),
            makeElement("p", "", finding.message || ""),
            makeElement(
                "p",
                finding.blocking ? "blocking" : "non-blocking",
                finding.blocking ? "Blocking finding" : "Non-blocking finding"
            )
        );
        uploadResult.append(card);
    }
}

uploadForm.addEventListener("submit", async event => {
    event.preventDefault();

    const file = pythonFileInput.files?.[0];

    if (!file) {
        uploadResult.hidden = false;
        uploadResult.textContent = "Choose a Python file first.";
        return;
    }

    if (!file.name.toLowerCase().endsWith(".py")) {
        uploadResult.hidden = false;
        uploadResult.textContent = "Only .py files are accepted.";
        return;
    }

    if (file.size === 0 || file.size > 100 * 1024) {
        uploadResult.hidden = false;
        uploadResult.textContent =
            "Choose a non-empty file no larger than 100 KiB.";
        return;
    }

    uploadButton.disabled = true;
    uploadResult.hidden = false;
    uploadResult.textContent = "Scanning file…";

    try {
        const content = await file.text();

        const response = await fetch("/api/scan-upload", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Accept: "application/json"
            },
            body: JSON.stringify({
                filename: file.name,
                content
            })
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || `Request failed: HTTP ${response.status}`);
        }

        renderUploadResult(result);
        await loadHistory();
    } catch (error) {
        uploadResult.replaceChildren(
            makeElement("p", "fail-text", `Scan failed: ${error.message}`)
        );
        uploadResult.hidden = false;
    } finally {
        uploadButton.disabled = false;
    }
});

refreshButton.addEventListener("click", loadHistory);
loadHistory();
