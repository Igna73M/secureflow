import { useEffect, useState } from "react";
import {
    Activity, ArrowLeft, ArrowRight, ArrowUpRight, Check, CircleAlert,
    Clock3, FileCode2, Filter, History, LayoutDashboard, LoaderCircle,
    LogOut, RefreshCw, Search, ShieldCheck, Upload,
} from "lucide-react";

const ROUTES = {
    "/console/overview": { id: "overview", title: "Overview", description: "A clear read on your latest security decisions." },
    "/console/history": { id: "history", title: "Scan history", description: "Search, filter, and inspect your scan records." },
    "/console/new-scan": { id: "new-scan", title: "New scan", description: "Analyze one Python or JavaScript source file." },
};
const NAVIGATION = [
    { href: "/console/overview", label: "Overview", icon: LayoutDashboard },
    { href: "/console/history", label: "Scan history", icon: History },
    { href: "/console/new-scan", label: "New scan", icon: Upload },
];
const PAGE_SIZE = 20;
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

async function requestJson(url, options = {}) {
    const response = await fetch(url, {
        credentials: "same-origin",
        headers: { Accept: "application/json", ...(options.headers || {}) },
        ...options,
    });
    const data = response.status === 204 ? null : await response.json().catch(() => ({}));
    if (response.status === 401) {
        window.location.assign("/login?expired=1");
        throw new Error("Your session expired. Sign in again.");
    }
    if (response.status === 403) throw new Error("This request could not be verified. Refresh and try again.");
    if (!response.ok) throw new Error(data?.error || `Request failed with HTTP ${response.status}.`);
    return data;
}

function formatDate(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "Unknown date";
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function DecisionBadge({ scan }) {
    const decision = scan.verified ? scan.decision : "UNVERIFIED";
    return <span className={`decision-badge decision-${decision.toLowerCase()}`}><span />{scan.verified ? decision : "Unverified"}</span>;
}

function ScanTable({ scans, onInspect, emptyText, selectedId = "", overview = false }) {
    if (!scans.length) return <div className="empty-state"><Activity size={20} /><p>{emptyText}</p></div>;
    return <div className="table-scroll"><table>
        <thead><tr><th>Target</th><th>Decision</th><th>Verification</th><th>Date</th>{!overview && <th aria-label="Inspect" />}</tr></thead>
        <tbody>{scans.map((scan) => <tr key={scan.id} className={String(scan.id) === String(selectedId) ? "selected-scan" : ""}>
            <td><button className="target-link" type="button" onClick={() => onInspect(scan.id)}>{scan.target}<ArrowUpRight size={13} /></button></td>
            <td><DecisionBadge scan={scan} /></td>
            <td><span className={`verification-label ${scan.verified ? "is-verified" : "is-unverified"}`}><span />{scan.verified ? "Scanner output" : "Submitted report"}</span></td>
            <td className="date-cell">{formatDate(scan.created_at)}</td>
            {!overview && <td><button className="inspect-button" type="button" onClick={() => onInspect(scan.id)} aria-label={`Inspect ${scan.target}`}><ArrowRight size={15} /></button></td>}
        </tr>)}</tbody>
    </table></div>;
}

function Finding({ finding }) {
    return <article className={`finding finding-${finding.severity.toLowerCase()}`}>
        <div className="finding-top"><span className="finding-severity">{finding.severity}</span><span>{finding.scanner}</span><code>{finding.rule_id}</code></div>
        <h3>{finding.title}</h3>
        <p className="finding-location"><FileCode2 size={13} />{finding.file || "Location unavailable"}{finding.line ? `:${finding.line}` : ""}</p>
        <p className="finding-message">{finding.message}</p>
        <span className={finding.blocking ? "finding-impact impact-blocking" : "finding-impact"}>{finding.blocking ? "Blocking" : "Non-blocking"}</span>
    </article>;
}

function Metric({ label, value, footnote, tone, icon: Icon }) {
    return <article className={`metric metric-${tone}`}>
        <div className="metric-top"><span>{label}</span><Icon size={16} strokeWidth={1.7} /></div>
        <strong>{value ?? "—"}</strong>
        <span className="metric-footnote">{footnote}</span>
    </article>;
}

function Sidebar({ view, user, onLogout, loggingOut }) {
    return <aside className="sidebar">
        <a href="/" className="brand" aria-label="SecureFlow home"><span className="brand-mark"><ShieldCheck size={19} /></span><span>secureflow</span></a>
        <div className="workspace-label">WORKSPACE</div>
        <nav className="workspace-nav" aria-label="Console pages">{NAVIGATION.map(({ href, label, icon: Icon }) => {
            const active = view === ROUTES[href].id;
            return <a key={href} href={href} className={active ? "nav-item is-active" : "nav-item"} aria-current={active ? "page" : undefined}><Icon size={17} strokeWidth={1.7} /><span>{label}</span>{active && <span className="nav-current" />}</a>;
        })}</nav>
        <div className="sidebar-bottom"><span className="account-indicator" /><span className="account-email" title={user?.email || ""}>{user?.email || "Loading account"}</span><button className="icon-button logout-button" type="button" title="Sign out" aria-label="Sign out" onClick={onLogout} disabled={loggingOut}><LogOut size={16} /></button></div>
    </aside>;
}

function ScanDetails({ scan, loading, error, severity, setSeverity, scanner, setScanner }) {
    const [showAll, setShowAll] = useState(false);
    useEffect(() => setShowAll(false), [scan?.id]);
    if (loading) return <section className="details-panel"><div className="details-loading"><LoaderCircle className="spin" size={20} />Loading scan details</div></section>;
    if (error) return <section className="details-panel"><div className="empty-state"><CircleAlert size={20} /><p>{error}</p></div></section>;
    if (!scan) return <section className="details-panel"><div className="details-heading"><div><span className="eyebrow">INSPECTION</span><h2>Scan details</h2></div><span className="detail-placeholder">Select a record</span></div><div className="empty-state"><FileCode2 size={20} /><p>Choose a scan from the table to inspect its findings.</p></div></section>;
    const scanners = [...new Set(scan.findings.map((finding) => finding.scanner))].sort();
    const findings = scan.findings.filter((finding) => (!severity || finding.severity === severity) && (!scanner || finding.scanner === scanner)).sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
    const visibleFindings = showAll ? findings : findings.slice(0, 5);
    return <section className="details-panel">
        <div className="details-heading"><div><span className="eyebrow">INSPECTION · #{scan.id}</span><h2>{scan.target}</h2><p>{formatDate(scan.created_at)}</p></div></div>
        <div className={`outcome-banner outcome-${scan.verified ? scan.decision.toLowerCase() : "unverified"}`}><DecisionBadge scan={scan} /><span>{scan.verified ? (scan.promotion_allowed ? "Promotion allowed by configured checks" : "Promotion blocked by configured checks") : "Unverified report; cannot authorize promotion"}</span></div>
        {!scan.verified && <div className="trust-note"><CircleAlert size={15} />Submitted decisions are not scanner evidence and must not authorize promotion.</div>}
        <div className="finding-toolbar"><label><Filter size={13} />Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severities</option>{SEVERITIES.map((value) => <option key={value}>{value}</option>)}</select></label><label>Scanner<select value={scanner} onChange={(event) => setScanner(event.target.value)}><option value="">All scanners</option>{scanners.map((value) => <option key={value}>{value}</option>)}</select></label></div>
        {findings.length ? <div className="findings-list">{visibleFindings.map((finding, index) => <Finding key={`${finding.rule_id}-${finding.file}-${finding.line}-${index}`} finding={finding} />)}{findings.length > 5 && <button className="show-more" type="button" onClick={() => setShowAll((value) => !value)}>{showAll ? "Show fewer findings" : `Show all ${findings.length} findings`}<ArrowRight size={14} /></button>}</div> : <div className="empty-state"><Check size={19} /><p>{scan.findings.length ? "No findings match these filters." : "No findings recorded for this scan."}</p></div>}
    </section>;
}

function App() {
    const route = ROUTES[window.location.pathname] || ROUTES["/console/overview"];
    const view = route.id;
    const initialScan = new URLSearchParams(window.location.search).get("scan") || "";
    const [user, setUser] = useState(null);
    const [csrfToken, setCsrfToken] = useState(null);
    const [authReady, setAuthReady] = useState(false);
    const [status, setStatus] = useState("Checking your session…");
    const [metrics, setMetrics] = useState(null);
    const [scans, setScans] = useState([]);
    const [page, setPage] = useState(1);
    const [pages, setPages] = useState(0);
    const [total, setTotal] = useState(0);
    const [searchDraft, setSearchDraft] = useState("");
    const [draftFilters, setDraftFilters] = useState({ decision: "", verified: "all", scanner: "" });
    const [filters, setFilters] = useState({ q: "", decision: "", verified: "all", scanner: "" });
    const [selectedId, setSelectedId] = useState(initialScan);
    const [selectedScan, setSelectedScan] = useState(null);
    const [detailLoading, setDetailLoading] = useState(false);
    const [detailError, setDetailError] = useState("");
    const [severity, setSeverity] = useState("");
    const [scanner, setScanner] = useState("");
    const [loading, setLoading] = useState(false);
    const [refreshKey, setRefreshKey] = useState(0);
    const [pageError, setPageError] = useState("");
    const [loggingOut, setLoggingOut] = useState(false);
    const [file, setFile] = useState(null);
    const [dragging, setDragging] = useState(false);
    const [uploading, setUploading] = useState(false);
    const [uploadResult, setUploadResult] = useState(null);
    const [uploadError, setUploadError] = useState("");

    useEffect(() => {
        let active = true;
        requestJson("/api/auth/me").then((auth) => {
            if (!active) return;
            if (!auth.authenticated) { window.location.assign("/login"); return; }
            setUser(auth.user);
            setCsrfToken(auth.csrfToken);
            setAuthReady(true);
            setStatus(view === "new-scan" ? "Ready to scan a source file." : "Loading scan history…");
        }).catch((error) => { if (active) { setPageError(error.message); setAuthReady(true); } });
        return () => { active = false; };
    }, [view]);

    useEffect(() => {
        if (!authReady || view === "new-scan") return undefined;
        const controller = new AbortController();
        let active = true;
        async function load() {
            setLoading(true);
            setPageError("");
            setStatus("Loading scan history…");
            const parameters = new URLSearchParams({ page: String(page), limit: String(view === "overview" ? 5 : PAGE_SIZE) });
            for (const [key, value] of Object.entries(filters)) if (value && value !== "all") parameters.set(key, value);
            try {
                const result = await requestJson(`/api/scans?${parameters}`, { signal: controller.signal });
                if (!active) return;
                setScans(result.scans);
                setMetrics(result.metrics);
                setPages(result.pagination.pages);
                setTotal(result.pagination.total);
                setStatus(result.pagination.total ? `Showing ${result.scans.length} of ${result.pagination.total} matching records.` : "No scan activity yet.");
                if (view === "history") {
                    const preferred = selectedId || initialScan;
                    const id = preferred && result.scans.some((item) => String(item.id) === String(preferred)) ? String(preferred) : String(result.scans[0]?.id || "");
                    setSelectedId(id);
                    if (id) {
                        setDetailLoading(true);
                        const detail = await requestJson(`/api/scans/${encodeURIComponent(id)}`, { signal: controller.signal });
                        if (!active) return;
                        setSelectedScan(detail);
                        setDetailError("");
                    } else setSelectedScan(null);
                }
            } catch (error) {
                if (!active || error.name === "AbortError") return;
                setPageError(error.message);
                setStatus("Could not load scan history.");
                setScans([]);
            } finally {
                if (active) { setLoading(false); setDetailLoading(false); }
            }
        }
        load();
        return () => { active = false; controller.abort(); };
    }, [authReady, view, page, filters, refreshKey]);

    async function inspectScan(id) {
        setSelectedId(String(id));
        if (view !== "history") { window.location.assign(`/console/history?scan=${encodeURIComponent(id)}`); return; }
        setDetailLoading(true);
        setDetailError("");
        try {
            const result = await requestJson(`/api/scans/${encodeURIComponent(id)}`);
            setSelectedScan(result);
            setSeverity("");
            setScanner("");
            window.history.replaceState({}, "", `/console/history?scan=${encodeURIComponent(id)}`);
        } catch (error) {
            setDetailError(error.message);
            setSelectedScan(null);
        } finally { setDetailLoading(false); }
    }

    function submitFilters(event) {
        event.preventDefault();
        setFilters({ q: searchDraft.trim(), ...draftFilters });
        setPage(1);
    }

    function clearFilters() {
        setSearchDraft("");
        setDraftFilters({ decision: "", verified: "all", scanner: "" });
        setFilters({ q: "", decision: "", verified: "all", scanner: "" });
        setPage(1);
    }

    async function submitUpload(event) {
        event.preventDefault();
        setUploadError("");
        setUploadResult(null);
        if (!file) { setUploadError("Choose a source file first."); return; }
        const extension = file.name.slice(file.name.lastIndexOf(".")).toLowerCase();
        if (![".py", ".js", ".cjs", ".mjs"].includes(extension)) { setUploadError("Choose a .py, .js, .cjs, or .mjs source file."); return; }
        if (file.size === 0 || file.size > 100 * 1024) { setUploadError("Choose a non-empty file no larger than 100 KiB."); return; }
        setUploading(true);
        setStatus("Scanning source file…");
        try {
            const result = await requestJson("/api/scan-upload", {
                method: "POST",
                headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
                body: JSON.stringify({ filename: file.name, content: await file.text() }),
            });
            setUploadResult(result);
            setStatus(`${result.decision} · Scan result recorded.`);
        } catch (error) {
            setUploadError(error.message);
            setStatus("Scan could not be completed.");
        } finally { setUploading(false); }
    }

    async function logout() {
        setLoggingOut(true);
        try {
            await requestJson("/api/auth/logout", { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken }, body: "{}" });
            window.location.assign("/");
        } catch (error) { setPageError(error.message); setLoggingOut(false); }
    }

    const refresh = () => setRefreshKey((value) => value + 1);
    const hasActiveFilters = Boolean(filters.q || filters.decision || filters.scanner || filters.verified !== "all");
    const scanTarget = uploadResult?.target || `upload:${file?.name || "source file"}`;

    return <div className="app-shell">
        <Sidebar view={view} user={user} onLogout={logout} loggingOut={loggingOut} />
        <main className="main-content">
            <header className="topbar"><div className="mobile-brand"><span className="brand-mark"><ShieldCheck size={18} /></span><span>secureflow</span></div><div className="breadcrumbs"><span>Workspace</span><span>/</span><strong>{route.title}</strong></div><div className="topbar-actions"><span className="live-indicator"><span /> Private workspace</span>{view !== "new-scan" && <button className="refresh-button" type="button" onClick={refresh} disabled={loading}><RefreshCw size={15} className={loading ? "spin" : ""} />Refresh</button>}</div></header>
            <div className="page-wrap">
                <div className="page-heading"><div><p className="eyebrow">SECURITY OPERATIONS</p><h1>{route.title}</h1><p className="page-description">{route.description}</p></div>{view === "overview" && <a className="primary-link" href="/console/new-scan"><Upload size={15} />New scan</a>}</div>
                <div className={`status-line ${pageError ? "status-error" : ""}`} role="status" aria-live="polite"><span className="status-dot" />{pageError || status}{pageError && <button type="button" onClick={refresh}>Retry</button>}</div>

                {view === "overview" && <>
                    <section className="metrics-grid" aria-label="Verified scan metrics">
                        <Metric label="Total records" value={metrics?.total} footnote={`${metrics?.unverified ?? "—"} unverified excluded from decisions`} tone="total" icon={Activity} />
                        <Metric label="Verified pass" value={metrics?.pass} footnote="Scanner-confirmed outcomes" tone="pass" icon={Check} />
                        <Metric label="Verified fail" value={metrics?.fail} footnote="Blocking decision" tone="fail" icon={CircleAlert} />
                        <Metric label="Verified error" value={metrics?.error} footnote="Incomplete checks" tone="error" icon={Clock3} />
                    </section>
                    <section className="section-panel overview-panel"><div className="section-header"><div><span className="eyebrow">LATEST ACTIVITY</span><h2>Recent scans</h2></div><a className="inline-link" href="/console/history">View history<ArrowRight size={14} /></a></div>
                        {loading && !scans.length ? <div className="empty-state"><LoaderCircle className="spin" size={19} /><p>Loading recent scans…</p></div> : <ScanTable scans={scans.slice(0, 5)} overview onInspect={inspectScan} emptyText="No scan activity yet. Start a scan to see results here." />}
                    </section>
                    <section className="trust-strip"><ShieldCheck size={18} /><p><strong>Verified means scanner-run, not vulnerability-free.</strong><span>Submitted reports are kept separate from verified policy decisions.</span></p><a href="/console/history">Review records <ArrowRight size={14} /></a></section>
                </>}

                {view === "history" && <>
                    <section className="section-panel history-panel"><div className="section-header"><div><span className="eyebrow">RECORDS</span><h2>All scans <span className="heading-count">{total}</span></h2></div><span className="page-count"><History size={14} />Page {page} of {Math.max(pages, 1)}</span></div>
                        <form className="filters" onSubmit={submitFilters}><label className="search-control"><Search size={16} /><input type="search" maxLength={100} placeholder="Search targets" value={searchDraft} onChange={(event) => setSearchDraft(event.target.value)} /></label><label><span className="sr-only">Decision</span><select value={draftFilters.decision} onChange={(event) => setDraftFilters((value) => ({ ...value, decision: event.target.value }))}><option value="">All decisions</option><option value="PASS">Pass</option><option value="FAIL">Fail</option><option value="ERROR">Error</option></select></label><label><span className="sr-only">Verification</span><select value={draftFilters.verified} onChange={(event) => setDraftFilters((value) => ({ ...value, verified: event.target.value }))}><option value="all">All records</option><option value="true">Verified only</option><option value="false">Unverified only</option></select></label><label><span className="sr-only">Scanner</span><select value={draftFilters.scanner} onChange={(event) => setDraftFilters((value) => ({ ...value, scanner: event.target.value }))}><option value="">All scanners</option><option value="bandit">Bandit</option><option value="semgrep">Semgrep</option><option value="eslint">ESLint</option></select></label><button className="filter-button" type="submit"><Filter size={14} />Apply</button><button className="clear-filters" type="button" onClick={clearFilters} disabled={!hasActiveFilters}>Clear</button></form>
                        {loading && !scans.length ? <div className="empty-state"><LoaderCircle className="spin" size={19} /><p>Loading scans…</p></div> : <ScanTable scans={scans} onInspect={inspectScan} selectedId={selectedId} emptyText={pageError ? "Scan history could not be loaded." : "No records match these filters."} />}
                        <div className="pagination"><span>Showing {scans.length ? (page - 1) * PAGE_SIZE + 1 : 0}–{Math.min(page * PAGE_SIZE, total)} of {total}</span><div><button type="button" aria-label="Previous page" disabled={page <= 1 || loading} onClick={() => setPage((value) => value - 1)}><ArrowLeft size={15} /></button><button type="button" aria-label="Next page" disabled={page >= pages || loading} onClick={() => setPage((value) => value + 1)}><ArrowRight size={15} /></button></div></div>
                    </section>
                    <ScanDetails scan={selectedScan} loading={detailLoading} error={detailError} severity={severity} setSeverity={setSeverity} scanner={scanner} setScanner={setScanner} />
                </>}

                {view === "new-scan" && <section className="upload-layout">
                    <div className="upload-copy"><span className="upload-icon"><FileCode2 size={22} /></span><span className="eyebrow">ON-DEMAND ANALYSIS</span><h2>Run a focused source check.</h2><p>Upload one source file. SecureFlow scans its contents without executing the file, then records the scanner result in your private history.</p><ul className="upload-facts"><li><Check size={15} />Python and JavaScript source</li><li><Check size={15} />Up to 100 KiB per file</li><li><Check size={15} />Temporary file removed after analysis</li></ul></div>
                    <form className="upload-form" onSubmit={submitUpload}><div className="upload-form-heading"><div><span className="eyebrow">SOURCE FILE</span><h2>Choose what to scan</h2></div><span className="file-types">.py · .js · .cjs · .mjs</span></div><label className={`drop-zone ${file ? "has-file" : ""} ${dragging ? "is-dragging" : ""}`} htmlFor="source-file" onDragEnter={(event) => { event.preventDefault(); setDragging(true); }} onDragOver={(event) => event.preventDefault()} onDragLeave={(event) => { if (!event.currentTarget.contains(event.relatedTarget)) setDragging(false); }} onDrop={(event) => { event.preventDefault(); setDragging(false); const dropped = event.dataTransfer.files?.[0]; if (dropped) { setFile(dropped); setUploadResult(null); setUploadError(""); } }}><input id="source-file" type="file" accept=".py,.js,.cjs,.mjs,text/x-python,text/javascript" onChange={(event) => { setFile(event.target.files?.[0] || null); setUploadResult(null); setUploadError(""); }} /><span className="drop-icon"><Upload size={20} /></span><strong>{file ? file.name : "Choose a source file"}</strong><span>{file ? `${(file.size / 1024).toFixed(file.size < 1024 ? 2 : 1)} KiB · Click to replace` : "or drag it into this area"}</span></label><button className="primary-link upload-submit" type="submit" disabled={uploading || !file}>{uploading ? <LoaderCircle className="spin" size={16} /> : <ShieldCheck size={16} />}{uploading ? "Scanning…" : "Run security scan"}</button>{uploadError && <p className="form-error" role="alert"><CircleAlert size={15} />{uploadError}</p>}{uploadResult && <div className={`upload-result result-${uploadResult.decision.toLowerCase()}`}><div className="result-title"><span className="result-icon">{uploadResult.decision === "PASS" ? <Check size={17} /> : <CircleAlert size={17} />}</span><div><span className="eyebrow">{uploadResult.verified ? "SCANNER OUTPUT" : "UNVERIFIED RESULT"}</span><h3>{uploadResult.decision} · {scanTarget}</h3></div></div><p>{uploadResult.verified ? (uploadResult.promotion_allowed ? "Configured checks completed and allowed promotion." : "Configured checks completed but blocked promotion.") : "This result was not verified by the scanner engine."}</p>{uploadResult.errors?.map((error) => <p key={error} className="form-error">{error}</p>)}{uploadResult.findings?.length > 0 && <div className="result-findings">{uploadResult.findings.slice(0, 5).map((finding, index) => <Finding key={`${finding.rule_id}-${index}`} finding={finding} />)}{uploadResult.findings.length > 5 && <span className="muted">Showing 5 of {uploadResult.findings.length} findings. See history for full details.</span>}</div>}<a className="inline-link" href={`/console/history?scan=${encodeURIComponent(uploadResult.id)}`}>Open scan history<ArrowRight size={14} /></a></div>}</form>
                </section>}
                <footer className="page-footer">SecureFlow results describe configured scanner checks; they do not prove source code is free of vulnerabilities.</footer>
            </div>
        </main>
    </div>;
}

export default App;
