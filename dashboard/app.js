"use strict";

const tableBody = document.getElementById("scan-table");
const statusMessage = document.getElementById("status-message");
const refreshButton = document.getElementById("refresh-button");
const findingsContainer = document.getElementById("findings-container");
const uploadForm = document.getElementById("upload-form");
const pythonFileInput = document.getElementById("python-file");
const uploadButton = document.getElementById("upload-button");
const uploadResult = document.getElementById("upload-result");
const filterForm = document.getElementById("history-filters");
const previousButton = document.getElementById("previous-page");
const nextButton = document.getElementById("next-page");
const severityFilter = document.getElementById("severity-filter");
const detailScannerFilter = document.getElementById("detail-scanner-filter");
const detailTrust = document.getElementById("detail-trust");
const detailOutcome = document.getElementById("detail-outcome");
const recentScanList = document.getElementById("recent-scan-list");

const consoleViews = {
    overview: {
        title: "Scan overview",
        description: "Your account's verified scanner outcomes at a glance.",
    },
    history: {
        title: "Scan history",
        description: "Search your reports and inspect scan findings.",
    },
    "new-scan": {
        title: "New scan",
        description: "Upload a supported source file for on-demand analysis.",
    },
};
const routeViews = {
    "/console/overview": "overview",
    "/console/history": "history",
    "/console/new-scan": "new-scan",
};
const requestedView = routeViews[window.location.pathname]
    || new URLSearchParams(window.location.search).get("view");
const activeView = Object.hasOwn(consoleViews, requestedView) ? requestedView : "overview";
const requestedScanId = Number(new URLSearchParams(window.location.search).get("scan"));
document.querySelectorAll("[data-page-section]").forEach((section) => {
    section.hidden = section.dataset.pageSection !== activeView;
});
document.querySelectorAll(".workspace-nav .nav-item").forEach((link) => {
    const isActive = routeViews[new URL(link.href).pathname] === activeView;
    link.classList.toggle("active", isActive);
    if (isActive) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
});
document.getElementById("page-title").textContent = consoleViews[activeView].title;
document.getElementById("page-description").textContent = consoleViews[activeView].description;
if (activeView === "new-scan") refreshButton.hidden = true;

const PAGE_SIZE = 20;
let csrfToken = null;
let page = 1;
let pages = 0;
let scans = [];
let selectedScanId = Number.isSafeInteger(requestedScanId) && requestedScanId > 0 ? requestedScanId : null;
let activeScan = null;
let currentFilters = { q: "", decision: "", verified: "all", scanner: "" };

function makeElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = String(text);
    return element;
}

async function requestJson(url, options = {}) {
    const response = await fetch(url, {
        credentials: "same-origin",
        headers: { Accept: "application/json", ...(options.headers || {}) },
        ...options,
    });
    const data = response.status === 204 ? null : await response.json().catch(() => ({}));
    if (response.status === 401) {
        clearPrivateView();
        window.location.assign("/login?expired=1");
        throw new Error("Your session expired. Sign in again.");
    }
    if (response.status === 403) {
        clearPrivateView();
        throw new Error("This request could not be verified. Refresh the page and try again.");
    }
    if (!response.ok) {
        throw new Error(data?.error || `Request failed with HTTP ${response.status}.`);
    }
    return data;
}

function clearPrivateView() {
    scans = [];
    activeScan = null;
    selectedScanId = null;
    tableBody.replaceChildren();
    findingsContainer.replaceChildren(makeElement("p", "empty-state", "Sign in to view scan details."));
    detailOutcome.hidden = true;
    detailTrust.hidden = true;
    document.getElementById("detail-subtitle").textContent = "Session unavailable.";
    document.querySelectorAll("#total-scans, #passed-scans, #failed-scans, #error-scans, #unverified-count")
        .forEach((element) => { element.textContent = "—"; });
}

function formatDate(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "Unknown date";
    return new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
    }).format(date);
}

function updateMetrics(metrics) {
    document.getElementById("total-scans").textContent = metrics.total;
    document.getElementById("passed-scans").textContent = metrics.pass;
    document.getElementById("failed-scans").textContent = metrics.fail;
    document.getElementById("error-scans").textContent = metrics.error;
    document.getElementById("unverified-count").textContent = `${metrics.unverified} unverified ${metrics.unverified === 1 ? "report" : "reports"} excluded from decisions`;
}

function makeDecisionBadge(scan) {
    if (!scan.verified) return makeElement("span", "decision UNVERIFIED", "Unverified");
    return makeElement("span", `decision ${scan.decision}`, scan.decision);
}

function renderOverviewActivity() {
    recentScanList.replaceChildren();
    if (scans.length === 0) {
        const row = makeElement("tr");
        const cell = makeElement("td", "empty-state", "No scan activity yet. Start a scan to see results here.");
        cell.colSpan = 4;
        row.append(cell);
        recentScanList.append(row);
        return;
    }

    for (const scan of scans.slice(0, 5)) {
        const row = makeElement("tr", "activity-row");
        const targetCell = makeElement("td");
        const targetLink = makeElement("a", "target-link", scan.target);
        targetLink.href = `/console/history?scan=${encodeURIComponent(scan.id)}`;
        targetLink.setAttribute("aria-label", `Inspect scan ${scan.target}`);
        targetCell.append(targetLink);
        const decisionCell = makeElement("td");
        decisionCell.append(makeDecisionBadge(scan));
        const verificationCell = makeElement("td");
        verificationCell.append(makeElement("span", scan.verified ? "verification verified" : "verification unverified",
            scan.verified ? "Scanner output" : "Submitted report"));
        row.append(targetCell, decisionCell, verificationCell, makeElement("td", "date-cell", formatDate(scan.created_at)));
        recentScanList.append(row);
    }
}

function renderHistory() {
    tableBody.replaceChildren();
    document.getElementById("history-count").textContent = `${scans.length} of ${document.getElementById("page-summary").dataset.total || 0}`;

    if (scans.length === 0) {
        const row = makeElement("tr");
        const cell = makeElement("td", "empty-state", currentFilters.q || currentFilters.decision || currentFilters.verified !== "all" || currentFilters.scanner
            ? "No records match these filters. Adjust the search or filters and try again."
            : "No scan activity yet. Upload a supported source file to run your first scan.");
        cell.colSpan = 4;
        row.append(cell);
        tableBody.append(row);
        return;
    }

    for (const scan of scans) {
        const row = makeElement("tr", "activity-row");
        row.setAttribute("aria-selected", String(scan.id === selectedScanId));
        const targetCell = makeElement("td");
        const openButton = makeElement("button", "target-button", scan.target);
        openButton.type = "button";
        openButton.setAttribute("aria-label", `Open ${scan.verified ? "verified scan" : "unverified report"} ${scan.target}`);
        openButton.addEventListener("click", () => loadScanDetails(scan.id));
        targetCell.append(openButton);

        const decisionCell = makeElement("td");
        decisionCell.append(makeDecisionBadge(scan));
        const verificationCell = makeElement("td");
        verificationCell.append(makeElement("span", scan.verified ? "verification verified" : "verification unverified",
            scan.verified ? "Scanner output" : "Submitted report"));
        const dateCell = makeElement("td", "date-cell", formatDate(scan.created_at));
        row.append(targetCell, decisionCell, verificationCell, dateCell);
        tableBody.append(row);
    }
}

function fillScannerFilter(findings) {
    const selected = detailScannerFilter.value;
    const scanners = [...new Set(findings.map((finding) => finding.scanner))].sort();
    detailScannerFilter.replaceChildren(new Option("All scanners", ""));
    for (const scanner of scanners) detailScannerFilter.add(new Option(scanner, scanner));
    if (scanners.includes(selected)) detailScannerFilter.value = selected;
}

function renderFindings(scan) {
    findingsContainer.replaceChildren();
    const severity = severityFilter.value;
    const scanner = detailScannerFilter.value;
    const findings = scan.findings.filter((finding) =>
        (!severity || finding.severity === severity) &&
        (!scanner || finding.scanner === scanner)
    );

    if (findings.length === 0) {
        findingsContainer.append(makeElement("p", "empty-state",
            scan.findings.length ? "No findings match these filters." : "No findings recorded for this scan."));
        return;
    }

    const severityRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    findings.sort((left, right) => severityRank[left.severity] - severityRank[right.severity]);
    for (const finding of findings) {
        const item = makeElement("article", `finding finding-${finding.severity.toLowerCase()}`);
        const metadata = makeElement("p", "finding-meta", `${finding.severity} · ${finding.scanner} · ${finding.rule_id}`);
        const title = makeElement("h3", "", finding.title);
        const location = makeElement("p", "finding-location",
            `${finding.file || "Location unavailable"}${finding.line ? `:${finding.line}` : ""}`);
        const message = makeElement("p", "finding-message", finding.message);
        const blocking = makeElement("span", finding.blocking ? "finding-impact blocking" : "finding-impact non-blocking",
            finding.blocking ? "Blocking" : "Non-blocking");
        item.append(metadata, title, location, message, blocking);
        findingsContainer.append(item);
    }
}

function renderDetails(scan) {
    activeScan = scan;
    selectedScanId = scan.id;
    document.getElementById("detail-subtitle").textContent = `#${scan.id} · ${scan.target} · ${formatDate(scan.created_at)}`;
    detailOutcome.hidden = false;
    detailOutcome.className = scan.verified
        ? `detail-outcome outcome-${scan.decision.toLowerCase()}`
        : "detail-outcome outcome-unverified";
    detailOutcome.textContent = scan.verified
        ? `${scan.decision} · ${scan.promotion_allowed ? "Promotion allowed by configured checks" : "Promotion blocked by configured checks"}`
        : `Submitted decision: ${scan.decision}. Not verified; this report cannot authorize promotion.`;
    detailTrust.hidden = scan.verified;
    detailTrust.textContent = scan.verified
        ? ""
        : "Unverified report. Its submitted decision is not scanner evidence and must not authorize promotion.";
    fillScannerFilter(scan.findings);
    renderFindings(scan);
    renderHistory();
}

async function loadScanDetails(id) {
    statusMessage.textContent = `Loading scan ${id}…`;
    try {
        const scan = await requestJson(`/api/scans/${encodeURIComponent(id)}`);
        renderDetails(scan);
        statusMessage.textContent = scan.verified
            ? `Loaded scanner output for ${scan.target}.`
            : `Loaded unverified submitted report for ${scan.target}.`;
    } catch (error) {
        if (error.message.startsWith("Your session expired")) return;
        activeScan = null;
        detailOutcome.hidden = true;
        detailTrust.hidden = true;
        document.getElementById("detail-subtitle").textContent = "Could not load this scan.";
        findingsContainer.replaceChildren(makeElement("p", "empty-state", error.message));
        statusMessage.textContent = error.message;
    }
}

function renderPageState(pagination) {
    pages = pagination.pages;
    document.getElementById("page-summary").textContent = pages
        ? `Page ${pagination.page} of ${pages}`
        : "No pages";
    document.getElementById("page-summary").dataset.total = String(pagination.total);
    document.getElementById("history-count").textContent = `${scans.length} of ${pagination.total}`;
    previousButton.disabled = pagination.page <= 1;
    nextButton.disabled = pagination.page >= pages;
}

async function loadHistory() {
    refreshButton.disabled = true;
    statusMessage.textContent = "Loading scan history…";
    const parameters = new URLSearchParams({ page: String(page), limit: String(PAGE_SIZE) });
    for (const [key, value] of Object.entries(currentFilters)) {
        if (value && value !== "all") parameters.set(key, value);
    }

    try {
        const data = await requestJson(`/api/scans?${parameters}`);
        scans = data.scans;
        updateMetrics(data.metrics);
        renderPageState(data.pagination);
        renderOverviewActivity();
        renderHistory();
        statusMessage.textContent = data.pagination.total
            ? `Showing ${scans.length} of ${data.pagination.total} matching records.`
            : (Object.values(currentFilters).some((value) => value && value !== "all")
                ? "No records match the current filters."
                : "No scan activity yet. Run a scan to start your history.");

        if (activeView === "history") {
            if (selectedScanId !== null && scans.some((scan) => scan.id === selectedScanId)) {
                await loadScanDetails(selectedScanId);
            } else if (scans.length) {
                await loadScanDetails(scans[0].id);
            } else {
                selectedScanId = null;
                activeScan = null;
                detailOutcome.hidden = true;
                detailTrust.hidden = true;
                document.getElementById("detail-subtitle").textContent = "Select an activity record.";
                findingsContainer.replaceChildren(makeElement("p", "empty-state", "No scan selected."));
            }
        }
    } catch (error) {
        if (error.message.startsWith("Your session expired")) return;
        statusMessage.replaceChildren(document.createTextNode(`Could not load scan history: ${error.message} `));
        const retry = makeElement("button", "inline-retry", "Retry");
        retry.type = "button";
        retry.addEventListener("click", loadHistory, { once: true });
        statusMessage.append(retry);
        scans = [];
        renderOverviewActivity();
        renderHistory();
        updateMetrics({ total: "—", pass: "—", fail: "—", error: "—", unverified: "—" });
    } finally {
        refreshButton.disabled = false;
    }
}

function renderUploadResult(result) {
    uploadResult.replaceChildren();
    uploadResult.hidden = false;
    const verified = result.verified === true;
    const summary = makeElement("div", "upload-summary");
    summary.append(
        makeElement("p", "eyebrow", verified ? "SCANNER OUTPUT" : "UNVERIFIED RESULT"),
        makeElement("h3", `result-heading result-${result.decision.toLowerCase()}`, `${result.decision} · ${result.target || "Upload scan"}`),
        makeElement("p", "muted", verified
            ? (result.promotion_allowed ? "The configured checks completed and allowed promotion." : "The configured checks completed but blocked promotion.")
            : "This result was not verified by the scanner engine.")
    );
    uploadResult.append(summary);
    if (!verified) {
        uploadResult.append(makeElement("p", "trust-note", "Do not use this result to authorize promotion."));
    }
    for (const error of (Array.isArray(result.errors) ? result.errors : [])) {
        uploadResult.append(makeElement("p", "fail-text", error));
    }
    if (Array.isArray(result.findings) && result.findings.length) {
        const resultList = makeElement("div", "upload-findings");
        for (const finding of result.findings) {
            const item = makeElement("article", "finding");
            item.append(
                makeElement("p", "finding-meta", `${finding.severity} · ${finding.scanner} · ${finding.rule_id}`),
                makeElement("h4", "", finding.title || finding.rule_id),
                makeElement("p", "finding-message", finding.message)
            );
            resultList.append(item);
        }
        uploadResult.append(resultList);
    } else {
        uploadResult.append(makeElement("p", "empty-state", "No findings were returned."));
    }
}

filterForm.addEventListener("submit", (event) => {
    event.preventDefault();
    currentFilters = {
        q: document.getElementById("search-input").value.trim(),
        decision: document.getElementById("decision-filter").value,
        verified: document.getElementById("verification-filter").value,
        scanner: document.getElementById("scanner-filter").value,
    };
    page = 1;
    loadHistory();
});

previousButton.addEventListener("click", () => {
    if (page > 1) {
        page -= 1;
        loadHistory();
    }
});
nextButton.addEventListener("click", () => {
    if (page < pages) {
        page += 1;
        loadHistory();
    }
});
refreshButton.addEventListener("click", loadHistory);
severityFilter.addEventListener("change", () => activeScan && renderFindings(activeScan));
detailScannerFilter.addEventListener("change", () => activeScan && renderFindings(activeScan));

document.getElementById("logout-button").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
        await requestJson("/api/auth/logout", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
            body: "{}",
        });
        window.location.assign("/");
    } catch (error) {
        statusMessage.textContent = error.message;
        button.disabled = false;
    }
});

uploadForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const file = pythonFileInput.files?.[0];
    if (!file) {
        uploadResult.hidden = false;
        uploadResult.textContent = "Choose a source file first.";
        return;
    }
    const extension = file.name.slice(file.name.lastIndexOf(".")).toLowerCase();
    if (![".py", ".js", ".cjs", ".mjs"].includes(extension)) {
        uploadResult.hidden = false;
        uploadResult.textContent = "Choose a .py, .js, .cjs, or .mjs source file.";
        return;
    }
    if (file.size === 0 || file.size > 100 * 1024) {
        uploadResult.hidden = false;
        uploadResult.textContent = "Choose a non-empty file no larger than 100 KiB.";
        return;
    }

    uploadButton.disabled = true;
    uploadResult.hidden = false;
    uploadResult.textContent = "Scanning file…";
    try {
        const result = await requestJson("/api/scan-upload", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
            body: JSON.stringify({ filename: file.name, content: await file.text() }),
        });
        renderUploadResult(result);
        page = 1;
        if (activeView !== "new-scan") await loadHistory();
    } catch (error) {
        if (error.message.startsWith("Your session expired")) return;
        uploadResult.replaceChildren(makeElement("p", "fail-text", `Scan failed: ${error.message}`));
        uploadResult.hidden = false;
    } finally {
        uploadButton.disabled = false;
    }
});

pythonFileInput.addEventListener("change", () => {
    const file = pythonFileInput.files?.[0];
    document.getElementById("file-selection").textContent = file
        ? `${file.name} · ${(file.size / 1024).toFixed(file.size < 1024 ? 2 : 1)} KiB`
        : "No file selected";
    uploadResult.hidden = true;
});

async function initializeDashboard() {
    try {
        const auth = await requestJson("/api/auth/me");
        if (!auth.authenticated) {
            window.location.assign("/login");
            return;
        }
        csrfToken = auth.csrfToken;
        document.getElementById("account-email").textContent = auth.user.email;
        if (activeView === "new-scan") statusMessage.textContent = "Ready to scan a source file.";
        else await loadHistory();
    } catch (error) {
        if (error.message.startsWith("Your session expired")) return;
        statusMessage.textContent = `Could not verify the signed-in session: ${error.message}`;
    }
}

initializeDashboard();
