import { useEffect, useState, type CSSProperties } from "react";
import {
  Activity,
  ArrowUpRight,
  BarChart3,
  ChevronDown,
  FileText,
  Globe2,
  History,
  MailCheck,
  Menu,
  MessageSquare,
  Network,
  Radar,
  ShieldCheck,
  Users,
  X,
} from "lucide-react";
import { api } from "../lib/api";
import DomainIntelligenceDashboard from "./components/DomainIntelligenceDashboard";
import InfrastructureHealthPanel from "./components/InfrastructureHealthPanel";
import CampaignInvestigationPanel from "./components/CampaignInvestigationPanel";
import SecurityFindingsPanel from "./components/SecurityFindingsPanel";
import SecurityAuthorizationPanel from "./components/SecurityAuthorizationPanel";
import WalletIntegrationPanel from "./components/WalletIntegrationPanel";
import EvidenceManagementPanel from "./components/EvidenceManagementPanel";
import EmailSecurityPanel from "./components/EmailSecurityPanel";
import MessageHistoryPanel from "./components/MessageHistoryPanel";
import MessageReportsPanel from "./components/MessageReportsPanel";
import MLLifecycleStatusPanel from "./components/MLLifecycleStatusPanel";

const nav = [
  ["Overview", BarChart3],
  ["Threat scanner", Radar],
  ["Website security", ShieldCheck],
  ["Message analysis", MessageSquare],
  ["Email analysis", MailCheck],
  ["Message analysis history", History],
  ["Message analysis reports", FileText],
  ["ML lifecycle status", Activity],
  ["Scan history", History],
  ["Community intel", Users],
  ["Threat correlation", Network],
] as const;
const serviceNav = nav.slice(1, 9);
export default function App() {
  const [tab, setTab] = useState("Overview");
  const [theme, setTheme] = useState<"dark" | "light">(() =>
    window.localStorage.getItem("cybernexus-theme") === "light" ? "light" : "dark",
  );
  const [servicesOpen, setServicesOpen] = useState(false);
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<any>();
  const [history, setHistory] = useState<any[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    api("/scans")
      .then(setHistory)
      .catch(() => {});
  }, []);
  useEffect(() => {
    document.body.classList.toggle("cybernexus-light", theme === "light");
    return () => document.body.classList.remove("cybernexus-light");
  }, [theme]);
  useEffect(() => {
    const close = () => setServicesOpen(false);
    const escape = (event: KeyboardEvent) => event.key === "Escape" && close();
    window.addEventListener("click", close);
    window.addEventListener("keydown", escape);
    return () => { window.removeEventListener("click", close); window.removeEventListener("keydown", escape); };
  }, []);
  async function scan(e: any) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const x = await api("/scans", {
        method: "POST",
        body: JSON.stringify({ url }),
      });
      setResult(x);
      setHistory((h) => [x, ...h]);
      setTab("Threat scanner");
    } catch (x: any) {
      setError(x.message);
    } finally {
      setBusy(false);
    }
  }
  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    window.localStorage.setItem("cybernexus-theme", next);
  }
  return (
    <main className={`min-h-screen grid-bg cinematic-app ${theme === "light" ? "light-app" : "dark-app"}`}>
      <div className="cinematic-video" aria-hidden="true"><video autoPlay muted loop playsInline preload="auto" src="https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260809_132544_b6ef0174-ed95-45ad-9a2f-ccb8acfbdce8.mp4" /><video className="cinematic-video-lift" autoPlay muted loop playsInline preload="auto" src="https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260809_132544_b6ef0174-ed95-45ad-9a2f-ccb8acfbdce8.mp4" /></div>
      <div className="mx-auto flex max-w-[1500px]">
        <aside className="hidden min-h-screen w-64 shrink-0 border-r border-line bg-panel/70 p-6 lg:block">
          <div className="mb-12 flex items-center gap-3">
            <div className="grid h-9 w-9 place-items-center rounded-xl bg-cyan text-ink">
              <ShieldCheck size={20} />
            </div>
            <div>
              <div className="text-sm font-bold">CYBERNEXUS</div>
              <div className="text-[10px] tracking-[.3em] text-cyan">
                TRUST INTELLIGENCE
              </div>
            </div>
          </div>
          <div className="cinematic-nav-row">
            <button type="button" onClick={() => setTab("Overview")} className={`top-nav-link ${tab === "Overview" ? "active" : ""}`}>Overview</button>
            <div className={`services-menu ${servicesOpen ? "open" : ""} ${serviceNav.some(([name]) => name === tab) ? "active" : ""}`} onClick={(event) => event.stopPropagation()}><button type="button" className="services-select" onClick={() => setServicesOpen((open) => !open)} aria-expanded={servicesOpen} aria-haspopup="menu"><span>Services</span><ChevronDown size={14} /></button>{servicesOpen && <div className="services-dropdown" role="menu">{serviceNav.map(([name]) => <button type="button" role="menuitem" key={name} className={tab === name ? "selected" : ""} onClick={() => { setTab(name); setServicesOpen(false); }}>{name}</button>)}</div>}</div>
            <button type="button" onClick={() => setTab("Community intel")} className={`top-nav-link ${tab === "Community intel" ? "active" : ""}`}>Community intel</button>
            <button type="button" onClick={() => setTab("Threat correlation")} className={`top-nav-link ${tab === "Threat correlation" ? "active" : ""}`}>Threat correlation</button>
          </div>
          <div className="mt-12 rounded-2xl border border-line p-4 text-xs text-slate-400">
            <Activity size={14} className="mb-2 text-cyan" />
            Passive analysis systems operational.
            <button type="button" onClick={toggleTheme} className="theme-toggle mt-3" role="switch" aria-checked={theme === "light"} aria-label="Toggle light and dark mode"><span className="theme-toggle-track"><span className="theme-toggle-thumb" /></span><span>{theme === "dark" ? "Dark mode" : "Light mode"}</span></button>
          </div>
        </aside>
        <section className="min-w-0 flex-1 p-5 md:p-8">
          {tab !== "Overview" && <header className="mb-9">
            <div className="mb-2 text-xs uppercase tracking-[.2em] text-cyan">Security operations</div>
            <h1 className="text-3xl font-semibold">{tab}</h1>
          </header>}
          {tab === "Overview" && <OverviewLanding history={history} result={result} url={url} setUrl={setUrl} scan={scan} busy={busy} error={error} setTab={setTab} />}
          {tab === "Threat scanner" && (
            <>
              <div className="glass mb-7 rounded-3xl p-6">
                <h2 className="mb-2 text-lg">Scan a website</h2>
                <p className="mb-5 text-sm text-slate-400">
                  URL, DNS, redirect, TLS, certificate, security header, and
                  threat intelligence analysis.
                </p>
                <form
                  onSubmit={scan}
                  className="flex flex-col gap-3 md:flex-row"
                >
                  <input
                    required
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://example.com"
                    className="flex-1 rounded-xl border border-line bg-ink/70 p-4 text-sm outline-none focus:border-cyan"
                  />
                  <button
                    disabled={busy}
                    className="rounded-xl bg-cyan px-6 py-4 text-sm font-bold text-ink"
                  >
                    {busy ? "Analyzing..." : "Run trust scan"}
                  </button>
                </form>
                {error && <p className="mt-3 text-sm text-danger">{error}</p>}
              </div>
              <div className="mb-7 grid gap-4 sm:grid-cols-3">
                <Stat label="Scans completed" value={history.length} />
                <Stat
                  label="High risk detected"
                  value={
                    history.filter((x) =>
                      ["High", "Critical"].includes(x.risk_level),
                    ).length
                  }
                />
                <Stat label="Analysis modules" value="8" />
              </div>
              <InfrastructureHealthPanel />
              {result && <ScanResult data={result} />}
            </>
          )}
          {tab === "Website security" && <Module5Panel scan={result} />}
          {tab === "Message analysis" && <Message />}
          {tab === "Email analysis" && <EmailSecurityPanel />}
          {tab === "Message analysis history" && <MessageHistoryPanel />}
          {tab === "Message analysis reports" && <MessageReportsPanel />}
          {tab === "ML lifecycle status" && <MLLifecycleStatusPanel />}
          {tab === "Scan history" && <HistoryPanel items={history} />}{" "}
          {tab === "Community intel" && <Community />}
          {tab === "Threat correlation" && <Module4Panel />}
        </section>
      </div>
    </main>
  );
}

function OverviewLanding({ history, result, url, setUrl, scan, busy, error, setTab }: any) {
  const latest = result || history[0];
  const score = Number(latest?.risk?.score ?? latest?.risk_score ?? 0);
  const highRisk = history.filter((x: any) => ["High", "Critical"].includes(x.risk_level || x.risk?.level)).length;
  const validTls = history.filter((x: any) => x.network?.tls?.status === "valid").length;
  const tlsPercent = history.length ? Math.round((validTls / history.length) * 100) : 0;
  const levels = ["Low", "Medium", "High", "Critical"].map((level) => ({ level, count: history.filter((x: any) => (x.risk_level || x.risk?.level) === level).length }));
  const maxLevel = Math.max(1, ...levels.map((x) => x.count));
  const go = (next: string) => () => setTab(next);
  return <div className="overview-landing">
    <section className="overview-hero">
      <div><div className="overview-eyebrow">DIGITAL TRUST INTELLIGENCE / LIVE OVERVIEW</div><h2>Security built into<br /><span>every system layer</span></h2><p>See risk signals, certificate trust, threat relationships, and investigation activity in one operational view.</p></div>
      <form onSubmit={scan} className="overview-scan"><label>Start a live trust scan</label><div><Globe2 size={17} /><input required value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com" /><button aria-label="Run trust scan" disabled={busy}>{busy ? "Scanning" : "Scan"}<ArrowUpRight size={16} /></button></div>{error && <small>{error}</small>}</form>
    </section>
    <section className="overview-metrics">
      <button type="button" className="overview-card score-card overview-card-button" onClick={go("Threat scanner")}><div className="overview-card-title">Real-time security score <ArrowUpRight size={14} /></div><div className="score-gauge" style={{ "--score": `${score * 3.6}deg` } as CSSProperties}><div><strong>{score}</strong><span>/100</span></div></div><div className="score-state">{latest ? (latest.risk?.level || latest.risk_level || "Analyzed") : "Awaiting scan"}</div><small>Open threat scanner</small></button>
      <button type="button" className="overview-card certificate-card overview-card-button" onClick={go("Threat scanner")}><div className="overview-card-title">Digital certificate validity <ArrowUpRight size={14} /></div><div className="chart-legend"><span><i className="legend-cyan" /> Valid coverage</span><b>{tlsPercent}%</b></div><div className="certificate-bars">{(history.slice(0, 6).length ? history.slice(0, 6) : [{ domain: "No scans yet" }]).map((item: any, index: number) => { const valid = item.network?.tls?.status === "valid"; const width = history.length ? Math.max(18, valid ? 86 - index * 7 : 36) : 12; return <div className="certificate-row" key={item.id || index}><span>{item.domain || "Awaiting scan"}</span><div><i style={{ width: `${width}%` }} /></div><time>{valid ? "VALID" : item.domain ? "REVIEW" : "—"}</time></div>; })}</div></button>
      <button type="button" className="overview-card events-card overview-card-button" onClick={go("Scan history")}><div className="overview-card-title">Recent security events <span>LIVE</span><ArrowUpRight size={14} /></div>{(history.slice(0, 4).length ? history.slice(0, 4) : [{ domain: "Workspace initialized", created_at: new Date().toISOString(), risk_level: "LOW" }]).map((item: any, index: number) => <div className="event-row" key={item.id || index}><span className={`event-icon event-${String(item.risk_level || item.risk?.level || "low").toLowerCase()}`}><ShieldCheck size={13} /></span><div><b>{item.domain || "Security event"}</b><small>{item.risk_level || item.risk?.level || "System ready"} · {item.created_at ? new Date(item.created_at).toLocaleDateString() : "Now"}</small></div></div>)}</button>
    </section>
    <section className="overview-lower">
      <button type="button" className="overview-card phishing-card overview-card-button" onClick={go("Threat scanner")}><div className="overview-card-title">Phishing detection metrics <span className="filter-label">ALL SCANS <ChevronDown size={13} /></span></div><div className="metric-chart">{levels.map((item, index) => <div className="metric-column" key={item.level}><div className={`metric-bar metric-${index}`} style={{ height: `${Math.max(10, (item.count / maxLevel) * 100)}%` }} /><span>{item.level}</span><b>{item.count}</b></div>)}</div><div className="chart-foot"><span>Open threat scanner</span><strong>{highRisk} high-risk finding{highRisk === 1 ? "" : "s"}</strong></div></button>
      <button type="button" className="overview-card graph-card overview-card-button" onClick={go("Threat correlation")}><div className="overview-card-title">Threat aggregator nodes <span className="filter-label">LIVE GRAPH</span><ArrowUpRight size={14} /></div><div className="node-graph"><svg className="node-graph-svg" viewBox="0 0 620 220" role="img" aria-label="Threat aggregator relationship graph"><defs><filter id="node-glow"><feGaussianBlur stdDeviation="5" result="blur" /><feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge></filter><linearGradient id="link-gradient" x1="0" x2="1"><stop offset="0" stopColor="#c81b1c" stopOpacity=".82" /><stop offset="1" stopColor="#aaa" stopOpacity=".28" /></linearGradient></defs><g className="graph-links" stroke="url(#link-gradient)" strokeWidth="2"><line x1="310" y1="110" x2="145" y2="42" /><line x1="310" y1="110" x2="478" y2="54" /><line x1="310" y1="110" x2="102" y2="164" /><line x1="310" y1="110" x2="486" y2="164" /><line x1="310" y1="110" x2="76" y2="99" /></g><g className="graph-nodes" textAnchor="middle" dominantBaseline="middle"><g className="graph-node-svg-item"><circle cx="145" cy="42" r="24" /><text x="145" y="42">DNS</text></g><g className="graph-node-svg-item"><circle cx="478" cy="54" r="24" /><text x="478" y="54">TLS</text></g><g className="graph-node-svg-item"><circle cx="102" cy="164" r="24" /><text x="102" y="164">IP</text></g><g className="graph-node-svg-item"><circle cx="486" cy="164" r="24" /><text x="486" y="164">URL</text></g><g className="graph-node-svg-item"><circle cx="76" cy="99" r="24" /><text x="76" y="99">ML</text></g><g className="graph-node-svg-center" filter="url(#node-glow)"><circle cx="310" cy="110" r="35" /><text x="310" y="108">{history.length}</text><text x="310" y="126" className="graph-node-unit">SCANS</text></g></g></svg><div className="graph-caption"><b>{history.length ? `${history.length} scan nodes` : "Ready for scan data"}</b><small>Open threat correlation</small></div></div></button>
      <button type="button" className="overview-card activity-card overview-card-button" onClick={go("Website security")}><div className="overview-card-title">Workspace telemetry <span>24H</span><ArrowUpRight size={14} /></div><div className="activity-ring"><div><strong>{history.length}</strong><small>scans</small></div></div><div className="activity-list"><span><i className="dot-red" />High risk <b>{highRisk}</b></span><span><i className="dot-cyan" />TLS valid <b>{validTls}</b></span><span><i className="dot-white" />Modules <b>8</b></span></div></button>
    </section>
    <InfrastructureHealthPanel />
    {result && <ScanResult data={result} />}
  </div>;
}
function Module4Panel() {
  return (
    <div className="space-y-6">
      <div className="glass rounded-3xl border border-cyan/20 p-6">
        <h2 className="mt-1 text-2xl font-semibold">Intelligent threat correlation</h2>
        <p className="mt-2 max-w-3xl text-sm text-slate-400">
          Explore evidence-backed relationships across messages, indicators, infrastructure,
          incidents and campaigns. Correlation is separate from a confirmed malicious verdict.
        </p>
      </div>
      <WalletIntegrationPanel />
      <EvidenceManagementPanel />
      <Correlation />
    </div>
  );
}
function Module5Panel({ scan }: { scan?: any }) {
  return (
    <div className="space-y-6">
      <div className="glass rounded-3xl border border-cyan/20 p-6">
        <h2 className="mt-1 text-2xl font-semibold">Website security assessment</h2>
        <p className="mt-2 max-w-3xl text-sm text-slate-400">
          Review normalized security findings, remediation history, assessment reports and
          authorization controls. Passive checks are the default; active checks require approval.
        </p>
      </div>
      <SecurityAuthorizationPanel />
      <SecurityFindingsPanel scan={scan} />
    </div>
  );
}
function Stat({ label, value }: any) {
  return (
    <div className="glass rounded-2xl p-5">
      <div className="text-2xl font-semibold">{value}</div>
      <div className="mt-1 text-sm text-slate-400">{label}</div>
    </div>
  );
}
function InfrastructurePanel({ data }: any) {
  const rows = data?.providers || [];
  const field = (label: string, value: any, detail?: string) => (
    <div className="flex items-center justify-between gap-4 border-b border-line py-3 last:border-0">
      <span className="text-sm text-slate-400">{label}</span>
      <span className="text-right text-sm font-semibold">
        {value || "Unavailable"}
        {detail && (
          <>
            <br />
            <span className="text-xs font-normal text-slate-500">{detail}</span>
          </>
        )}
      </span>
    </div>
  );
  return (
    <div className="mt-5 rounded-2xl border border-line bg-black/20 p-4">
      <div className="flex items-center justify-between">
        <h3 className="text-base font-semibold">
          ASN and Hosting Intelligence
        </h3>
        <span className="rounded-full bg-slate-800 px-2 py-1 text-xs text-slate-400">
          {data?.provider?.name || "IPinfo"} · {data?.status || "unavailable"}
        </span>
      </div>
      {!rows.length ? (
        <div className="mt-4 text-sm text-slate-500">
          {data?.provider_status === "missing_credentials"
            ? "IPinfo is not configured. Add IPINFO_TOKEN to enable live infrastructure intelligence."
            : "IPinfo data is unavailable; no network result was inferred."}
        </div>
      ) : (
        rows.map((x: any) => (
          <div key={x.ip} className="mt-4 rounded-xl border border-line px-4">
            {field("IP address", x.ip)}
            {field("ASN", x.asn_number, x.asn_organization || undefined)}
            {field("Network domain", x.asn_domain)}
            {field("Country", x.country_name || x.country)}
            {field(
              "Hosting classification",
              x.hosting === undefined || x.hosting === null
                ? "Plan dependent"
                : String(x.hosting),
            )}
          </div>
        ))
      )}
    </div>
  );
}
function RdapPanel({ data }: any) {
  const events = data?.events || {};
  const field = (label: string, value: any) => (
    <div className="flex items-center justify-between gap-4 border-b border-line py-3 last:border-0">
      <span className="text-sm text-slate-400">{label}</span>
      <span className="max-w-[70%] text-right text-sm font-semibold">
        {value || "Unavailable"}
      </span>
    </div>
  );
  return (
    <div className="mt-5 rounded-2xl border border-line bg-black/20 p-4">
      <div className="flex items-center justify-between">
        <h3 className="text-base font-semibold">RDAP domain intelligence</h3>
        <span
          className={`rounded-full px-2 py-1 text-xs ${data?.status === "available" ? "bg-emerald-950 text-emerald-300" : "bg-slate-800 text-slate-400"}`}
        >
          {data?.status || "unavailable"}
        </span>
      </div>
      {data?.status !== "available" ? (
        <div className="mt-4 text-sm text-slate-500">
          {data?.reason || "RDAP information is unavailable for this domain."}
        </div>
      ) : (
        <>
          <div className="mt-3 rounded-xl border border-line px-4">
            {field("Domain", data.ldh_name || data.domain)}
            {field("Registration date", events.registration)}
            {field("Expiration date", events.expiration)}
            {field("Last updated", events["last changed"])}
            {field("Registrar", data.registrar)}
            {field("RDAP server", data.final_url)}
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <div className="rounded-xl border border-line p-4">
              <div className="text-xs uppercase tracking-widest text-slate-500">
                Nameservers
              </div>
              {data.nameservers?.length ? (
                data.nameservers.map((name: string) => (
                  <div key={name} className="mt-2 text-sm text-slate-300">
                    {name}
                  </div>
                ))
              ) : (
                <div className="mt-2 text-sm text-slate-500">Unavailable</div>
              )}
            </div>
            <div className="rounded-xl border border-line p-4">
              <div className="text-xs uppercase tracking-widest text-slate-500">
                Domain status
              </div>
              {data.status_codes?.length ? (
                data.status_codes.map((status: string) => (
                  <div key={status} className="mt-2 text-sm text-slate-300">
                    {status}
                  </div>
                ))
              ) : (
                <div className="mt-2 text-sm text-slate-500">Unavailable</div>
              )}
            </div>
          </div>
          {data.redirects?.length ? (
            <div className="mt-4 text-xs text-slate-500">
              Discovery redirects:{" "}
              {data.redirects
                .map((x: any) => `${x.status_code} ${x.to}`)
                .join(" → ")}
            </div>
          ) : null}
        </>
      )}
    </div>
  );
}
function RedirectPanel({ data }: any) {
  const http = data.network?.http || {};
  const hops = http.redirects || [];
  const analysis = data.network?.redirect_analysis || {};
  const risk = analysis.risk || {};
  const [retrying, setRetrying] = useState<number | null>(null);
  const [local, setLocal] = useState(analysis.destinations || {});
  async function retry(hop: any) {
    if (!data.id) return;
    setRetrying(hop.sequence);
    try {
      const refreshed = await api(
        `/scans/${data.id}/redirects/${hop.sequence}/retry`,
        { method: "POST" },
      );
      setLocal((current: any) => ({
        ...current,
        [hop.destination_domain]: refreshed,
      }));
    } finally {
      setRetrying(null);
    }
  }
  return (
    <div className="mt-5 rounded-2xl border border-line bg-black/20 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold">Redirect intelligence</h3>
          <p className="mt-1 text-xs text-slate-400">
            Observed hops are validated before each request; unavailable
            intelligence is not treated as clean.
          </p>
        </div>
        <div className="text-right">
          <div className="text-xl font-bold text-cyan">
            {risk.score || 0}/100
          </div>
          <div className="text-xs text-slate-400">
            {risk.level || "Informational"} · {hops.length} hops
          </div>
        </div>
      </div>
      {!hops.length ? (
        <p className="mt-4 text-sm text-slate-500">
          No HTTP redirects were observed. Final URL:{" "}
          {http.final_url || data.normalized_url}
        </p>
      ) : (
        <>
          <div className="mt-4 grid gap-3 md:grid-cols-3">
            <Card
              title="Unique destinations"
              value={analysis.comparison?.destination_count ?? "Unavailable"}
            />
            <Card
              title="Final destination"
              value={analysis.comparison?.final_domain || "Unavailable"}
            />
            <Card
              title="Completeness"
              value={risk.complete ? "Complete" : "Incomplete"}
            />
          </div>
          <div className="mt-4 space-y-2">
            {hops.map((hop: any) => {
              const destination = local[hop.destination_domain] || {};
              const providers = (destination.provider_results || []).filter(
                (provider: any) =>
                  !["Google Safe Browsing", "VirusTotal", "PhishTank"].includes(
                    provider.provider,
                  ),
              );
              return (
                <details
                  key={hop.sequence}
                  className="rounded-xl border border-line p-3"
                >
                  <summary className="cursor-pointer list-none text-sm">
                    <span className="mr-3 text-cyan">Hop {hop.sequence}</span>
                    <span>
                      {hop.status_code} · {hop.source_domain} →{" "}
                      {hop.destination_domain}
                    </span>
                    <span className="float-right text-xs text-slate-500">
                      {hop.https_downgrade
                        ? "HTTPS downgrade"
                        : "HTTPS " + (hop.https ? "yes" : "no")}
                    </span>
                  </summary>
                  <div className="mt-3 grid gap-2 text-xs text-slate-400 md:grid-cols-2">
                    <span>From: {hop.source_url}</span>
                    <span>To: {hop.destination_url}</span>
                    <span>
                      IPs: {hop.destination_ips?.join(", ") || "Unavailable"}
                    </span>
                    <span>
                      Destination: {destination.verdict || "UNKNOWN"} · checked{" "}
                      {providers[0]?.checked_at
                        ? new Date(providers[0].checked_at).toLocaleString()
                        : "Unavailable"}
                    </span>
                  </div>
                  <div className="mt-3 rounded-lg border border-line p-3">
                    <div className="mb-2 text-xs font-semibold text-cyan">
                      Provider intelligence for {hop.destination_domain}
                    </div>
                    {providers.length ? (
                      providers.map((provider: any, i: number) => (
                        <div
                          key={`${provider.provider}-${provider.ip || i}`}
                          className="mb-2 rounded-md bg-ink/60 p-2 text-xs"
                        >
                          <div className="flex justify-between gap-2">
                            <span className="font-semibold">
                              {provider.provider}
                              {provider.ip && ` · ${provider.ip}`}
                            </span>
                            <span
                              className={
                                provider.state === "THREAT_DETECTED"
                                  ? "text-danger"
                                  : "text-slate-400"
                              }
                            >
                              {provider.state || "UNKNOWN"}
                            </span>
                          </div>
                          <div className="mt-1 text-slate-400">
                            Verdict: {provider.verdict || "UNKNOWN"} ·{" "}
                            {provider.evidence_available
                              ? "Evidence available"
                              : "No evidence returned"}
                            {provider.cache && ` · cache: ${provider.cache}`}
                          </div>
                          {provider.reason && (
                            <div className="mt-1 text-danger">
                              {provider.reason}
                            </div>
                          )}
                          {provider.threat_categories?.length && (
                            <div className="mt-1">
                              Categories:{" "}
                              {provider.threat_categories.join(", ")}
                            </div>
                          )}
                          {provider.detected_by !== undefined && (
                            <div className="mt-1">
                              Detections: {provider.detected_by}
                            </div>
                          )}
                        </div>
                      ))
                    ) : (
                      <div className="text-xs text-slate-500">
                        Provider intelligence unavailable; this is not a clean
                        result.
                      </div>
                    )}
                    <button
                      type="button"
                      onClick={() => retry(hop)}
                      disabled={retrying === hop.sequence}
                      className="mt-1 rounded-md border border-cyan/30 px-2 py-1 text-xs text-cyan"
                    >
                      {retrying === hop.sequence
                        ? "Retrying..."
                        : "Retry provider lookups"}
                    </button>
                  </div>
                </details>
              );
            })}
          </div>
          {risk.evidence?.length ? (
            <div className="mt-4 space-y-2">
              {risk.evidence.map((x: any, i: number) => (
                <div
                  key={i}
                  className="rounded-lg bg-danger/10 p-2 text-xs text-danger"
                >
                  {x.message} (+{x.points})
                </div>
              ))}
            </div>
          ) : (
            <p className="mt-4 text-xs text-slate-500">
              No positive redirect-risk evidence detected.
            </p>
          )}
        </>
      )}
    </div>
  );
}
function ScanResult({ data }: any) {
  return (
    <div className="glass rounded-3xl p-6">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="text-xs uppercase tracking-widest text-slate-500">
            Latest investigation
          </div>
          <div className="mt-2 text-lg">{data.domain}</div>
        </div>
        <div className="text-right">
          <div className="text-3xl font-bold text-cyan">
            {data.risk.score}/100
          </div>
          <div className="text-xs">
            {data.risk.level} · {data.risk.confidence} confidence
          </div>
        </div>
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        <Card
          title="Phishing"
          value={`${data.phishing.evidence.length} signals`}
        />
        <Card title="TLS certificate" value={data.certificate.status} />
        <Card
          title="Threat matches"
          value={data.threat_intelligence.findings.length}
        />
      </div>
      <div className="mt-5 text-sm text-slate-400">
        Redirects: {data.network.http.redirects.length} · CT records:{" "}
        {data.certificate.ct_records.length} · DNS records:{" "}
        {Object.keys(data.network.dns.records || {}).length}
      </div>
      <DomainIntelligenceDashboard data={data} />
      <RedirectPanel data={data} />
      <BrandPanel data={data.domain_intelligence?.domain} />
      <RdapPanel data={data.domain_intelligence?.rdap} />
      <InfrastructurePanel data={data.domain_intelligence?.infrastructure} />
      <ExternalProvidersPanel />
      <UrlhausPanel />
      {(data.phishing.evidence || []).map((x: any, i: number) => (
        <div
          key={i}
          className="mt-2 rounded-xl bg-ink/50 p-3 text-sm text-danger"
        >
          {x.message}
        </div>
      ))}
      {data.precautions?.map((x: string, i: number) => (
        <div key={i} className="mt-2 text-xs text-slate-400">
          Precaution: {x}
        </div>
      ))}
    </div>
  );
}
function BrandPanel({ data }: any) {
  const matches = data?.brand_matches || [];
  return (
    <div className="mt-5 rounded-2xl border border-line bg-black/20 p-4">
      <div className="flex items-center justify-between">
        <h3 className="text-base font-semibold">
          Typosquatting and brand impersonation
        </h3>
        <span className="text-xs text-slate-400">
          {matches.length
            ? `${matches.length} candidate${matches.length === 1 ? "" : "s"}`
            : "No match detected"}
        </span>
      </div>
      {!matches.length ? (
        <p className="mt-3 text-sm text-slate-500">
          No configured brand similarity candidate was detected. This is not
          proof that the domain is safe.
        </p>
      ) : (
        matches.map((match: any, i: number) => (
          <div
            key={`${match.brand}-${i}`}
            className="mt-3 rounded-xl border border-line p-4 text-sm"
          >
            <div className="flex items-center justify-between">
              <span className="font-semibold text-danger">
                Possible {match.brand} impersonation
              </span>
              <span className="text-xs text-slate-400">{match.risk} risk</span>
            </div>
            <div className="mt-2 grid gap-2 text-xs text-slate-400 md:grid-cols-2">
              <span>Suspected: {match.suspected_domain}</span>
              <span>Official: {match.official_domain}</span>
              <span>Similarity: {match.similarity_percent}%</span>
              <span>Edit distance: {match.edit_distance}</span>
              <span className="md:col-span-2">
                Technique: {match.manipulation}
              </span>
            </div>
          </div>
        ))
      )}
    </div>
  );
}
function VirusTotalInfo() {
  const [status, setStatus] = useState<any>();
  const [latest, setLatest] = useState<any>();
  const [busy, setBusy] = useState(false);
  async function load() {
    setBusy(true);
    try {
      const [config, scan] = await Promise.all([
        api("/providers/virustotal/status"),
        api("/providers/virustotal/latest"),
      ]);
      setStatus(config);
      setLatest(scan);
    } catch (error: any) {
      setStatus({ connection_status: "UNKNOWN", error: error.message });
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    load();
  }, []);
  const evidence = latest?.evidence || {};
  const stats = evidence.detection_stats || {};
  return (
    <div className="mt-3 rounded-lg border border-purple-400/20 bg-purple-400/5 p-3 text-[11px] leading-relaxed text-slate-400">
      <div className="flex items-center justify-between gap-2">
        <div className="font-semibold text-purple-300">VirusTotal API v3</div>
        <span className="rounded-full bg-slate-800 px-2 py-1 text-[10px] text-slate-300">
          {latest?.status || status?.connection_status || "UNKNOWN"}
        </span>
      </div>
      <p className="mt-1">
        Existing public reports are checked first. URLs are not submitted
        automatically.
      </p>
      <p className="mt-2">
        Verdict:{" "}
        <span className="font-semibold text-slate-200">
          {latest?.verdict || "Unknown"}
        </span>{" "}
        · engines: {evidence.total_engines ?? "Unavailable"} · malicious:{" "}
        {stats.malicious ?? "—"} · suspicious: {stats.suspicious ?? "—"}
      </p>
      {latest?.checked_at && (
        <p>Checked: {new Date(latest.checked_at).toLocaleString()}</p>
      )}
      {evidence.engines?.slice(0, 5).map((engine: any, i: number) => (
        <div key={i} className="mt-1">
          {engine.engine}: {engine.category || "unknown"}
          {engine.result ? ` (${engine.result})` : ""}
        </div>
      ))}
      {status?.api_key_configured === false && (
        <p className="mt-2 text-danger">
          VirusTotal API key is not configured. This is unknown, not clean.
        </p>
      )}
      {status?.error && <p className="mt-2 text-danger">{status.error}</p>}
      {busy && <p className="mt-2">Loading provider status...</p>}
    </div>
  );
}
function VirusTotalPanel({ data }: any) {
  const stats = data?.detection_stats || {};
  const engines = data?.engines || [];
  const status = data?.status || "unavailable";
  return (
    <div className="mt-5 rounded-2xl border border-purple-400/20 bg-purple-400/5 p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold text-purple-200">
            VirusTotal intelligence
          </h3>
          <p className="mt-1 text-xs text-slate-400">
            Existing public URL reports are checked first. Submission is
            explicit and never automatic.
          </p>
        </div>
        <span className="rounded-full bg-slate-800 px-3 py-1 text-xs text-slate-300">
          {status}
        </span>
      </div>
      {status === "not_configured" ? (
        <p className="mt-4 text-sm text-slate-500">
          VIRUSTOTAL_API_KEY is not configured. This provider is unknown, not
          clean.
        </p>
      ) : (
        <>
          <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            <Card title="Verdict" value={data?.verdict || "Unknown"} />
            <Card
              title="Total engines"
              value={data?.total_engines ?? "Unavailable"}
            />
            <Card
              title="Malicious"
              value={data?.malicious_detections ?? stats.malicious ?? "—"}
            />
            <Card
              title="Suspicious"
              value={data?.suspicious_detections ?? stats.suspicious ?? "—"}
            />
            <Card
              title="Undetected"
              value={data?.undetected_results ?? stats.undetected ?? "—"}
            />
          </div>
          <div className="mt-4 grid gap-3 text-xs text-slate-400 md:grid-cols-3">
            <span>
              Harmless: {data?.harmless_detections ?? stats.harmless ?? "—"}
            </span>
            <span>Analysis: {data?.analysis_status || "Unavailable"}</span>
            <span>
              Last analysis: {data?.last_analysis_date || "Unavailable"}
            </span>
          </div>
          {data?.threat_categories && (
            <div className="mt-3 text-xs text-slate-400">
              Categories:{" "}
              {Object.entries(data.threat_categories)
                .map(([source, value]: any) => `${source}: ${value}`)
                .join(" · ") || "None reported"}
            </div>
          )}
          {engines.length ? (
            <div className="mt-4 rounded-xl border border-purple-400/10 p-4">
              <div className="mb-2 text-xs uppercase tracking-widest text-slate-500">
                Engine evidence
              </div>
              {engines.slice(0, 12).map((engine: any, i: number) => (
                <div
                  key={`${engine.engine}-${i}`}
                  className="flex justify-between border-t border-line py-2 text-xs"
                >
                  <span>{engine.engine}</span>
                  <span className="text-slate-400">
                    {engine.category || "unknown"}
                    {engine.result ? ` · ${engine.result}` : ""}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="mt-4 text-sm text-slate-500">
              Individual engine results are unavailable.
            </p>
          )}
          {data?.reason && (
            <p className="mt-3 text-sm text-danger">{data.reason}</p>
          )}
        </>
      )}
    </div>
  );
}
function Card({ title, value }: any) {
  return (
    <div className="rounded-2xl border border-line bg-ink/40 p-4">
      <div className="text-xs text-slate-400">{title}</div>
      <div className="mt-3 text-sm font-medium capitalize">{value}</div>
    </div>
  );
}
function Message() {
  const [text, setText] = useState("");
  const [result, setResult] = useState<any>();
  async function submit(e: any) {
    e.preventDefault();
    setResult(
      await api("/message-analysis", {
        method: "POST",
        body: JSON.stringify({ text }),
      }),
    );
  }
  return (
    <div className="glass max-w-3xl rounded-3xl p-6">
      <MessageSquare className="mb-3 text-cyan" />
      <h2 className="text-xl">Message analysis</h2>
      <p className="my-2 text-sm text-slate-400">
        Deterministic signals, trained dataset model, indicator extraction, and
        resilient AI explanation.
      </p>
      <form onSubmit={submit}>
        <textarea
          required
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={8}
          className="my-4 w-full rounded-xl border border-line bg-ink/60 p-4 text-sm"
          placeholder="Paste a suspicious message..."
        />
        <button className="rounded-xl bg-cyan px-5 py-3 text-sm font-bold text-ink">
          Analyze message
        </button>
      </form>
      {result && (
        <div className="mt-5 border-t border-line pt-5">
          <div className="text-lg capitalize">
            {result.classification} · {result.score}/100
          </div>
          {result.evidence.map((x: any, i: number) => (
            <div key={i} className="mt-2 text-sm text-danger">
              {x.severity}: {x.issue}
            </div>
          ))}
          <div className="mt-4 text-xs text-slate-400">
            URLs: {result.indicators.urls.length} · emails:{" "}
            {result.indicators.emails.length} · phones:{" "}
            {result.indicators.phones.length}
          </div>
          <div className="mt-4 rounded-xl border border-line p-3 text-sm">
            Dataset model:{" "}
            {result.ml.available
              ? `${Math.round(result.ml.malicious_probability * 100)}% malicious probability`
              : "not trained"}
          </div>
          <div className="mt-3 rounded-xl border border-cyan/20 bg-cyan/5 p-3 text-sm text-cyan">
            <div className="flex items-center justify-between">
              <span>LLM Phase 1 explanation</span>
              <span className="rounded-full bg-slate-800 px-2 py-1 text-xs">
                {result.llm.available
                  ? "CONNECTED"
                  : result.llm.fallback_type === "template"
                    ? "TEMPLATE FALLBACK"
                    : result.llm.status || "UNAVAILABLE"}
              </span>
            </div>
            {result.llm.provider && (
              <div className="mt-2 text-xs text-slate-400">
                Provider: {result.llm.provider}
                {result.llm.model && ` · Model: ${result.llm.model}`}
              </div>
            )}
            {result.llm.fallback_used && (
              <div className="mt-1 text-xs text-amber-300">
                Fallback used: {result.llm.fallback_type || "provider fallback"}
              </div>
            )}
            {result.llm.reason && (
              <div className="mt-1 text-xs text-amber-300">
                {result.llm.reason}
              </div>
            )}
            {result.llm.failures?.length && (
              <div className="mt-1 text-xs text-slate-500">
                Provider attempts:{" "}
                {result.llm.failures
                  .map((x: any) => `${x.provider || "provider"}=${x.status}`)
                  .join(" · ")}
              </div>
            )}
            {result.llm.explanation && (
              <p className="mt-3 whitespace-pre-wrap text-slate-300">
                {result.llm.explanation}
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
function HistoryPanel({ items }: any) {
  return (
    <div className="glass rounded-3xl p-6">
      <h2 className="mb-5 text-xl">Investigation history</h2>
      {items.length ? (
        items.map((x: any) => (
          <div
            key={x.id}
            className="flex justify-between border-t border-line py-4 text-sm"
          >
            <span>{x.domain}</span>
            <span className="text-cyan">
              {x.risk_score}/100 · {x.risk_level}
            </span>
          </div>
        ))
      ) : (
        <p className="text-sm text-slate-500">No scans yet.</p>
      )}
    </div>
  );
}
function Community() {
  const [url, setUrl] = useState("");
  const [reason, setReason] = useState("");
  const [sent, setSent] = useState(false);
  async function submit(e: any) {
    e.preventDefault();
    await api("/reports", {
      method: "POST",
      body: JSON.stringify({ url, reason }),
    });
    setSent(true);
  }
  return (
    <div className="glass max-w-2xl rounded-3xl p-6">
      <Users className="mb-3 text-cyan" />
      <h2 className="text-xl">Community report</h2>
      {sent ? (
        <p className="mt-5 text-cyan">Report queued for moderation.</p>
      ) : (
        <form onSubmit={submit} className="mt-5 space-y-3">
          <input
            required
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Suspicious URL"
            className="w-full rounded-xl border border-line bg-ink/60 p-4 text-sm"
          />
          <input
            required
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Reason"
            className="w-full rounded-xl border border-line bg-ink/60 p-4 text-sm"
          />
          <button className="rounded-xl bg-cyan px-5 py-3 text-sm font-bold text-ink">
            Submit report
          </button>
        </form>
      )}
    </div>
  );
}
function Correlation() {
  const [data, setData] = useState<any>();
  useEffect(() => {
    api("/correlation")
      .then(setData)
      .catch(() => {});
  }, []);
  return (
    <div>
      <div className="glass max-w-3xl rounded-3xl p-6">
        <Network className="mb-3 text-cyan" />
        <h2 className="text-xl">Threat correlation</h2>
        <p className="my-2 text-sm text-slate-400">
          Exact-domain compatibility view and evidence-backed campaign
          investigation.
        </p>
        {data?.clusters?.length ? (
          data.clusters.map((x: any) => (
            <div key={x.key} className="mt-3 rounded-xl border border-line p-4">
              <span className="text-cyan">{x.key}</span>
              <div className="text-xs text-slate-400">
                {x.indicators.length} related indicators
              </div>
            </div>
          ))
        ) : (
          <p className="mt-5 text-sm text-slate-500">
            No repeated exact-domain infrastructure found yet.
          </p>
        )}
      </div>
      <CampaignInvestigationPanel />
    </div>
  );
}
function SafeBrowsingInfo() {
  const [status, setStatus] = useState<any>();
  const [latest, setLatest] = useState<any>();
  const [busy, setBusy] = useState(false);
  async function load(force = false) {
    setBusy(true);
    try {
      const [config, scan] = await Promise.all([
        api(
          `/providers/google-safe-browsing/${force ? "verify" : "status"}${force ? "?force=true" : ""}`,
          { method: force ? "POST" : "GET" },
        ),
        api("/providers/google-safe-browsing/latest"),
      ]);
      setStatus(config);
      setLatest(scan);
    } catch (error: any) {
      setStatus({ connection_status: "UNKNOWN", error: error.message });
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    load();
  }, []);
  const state = status?.connection_status || "UNKNOWN";
  const evidence = latest?.evidence || {};
  const categories = evidence.threat_categories || [];
  const matches = evidence.matches || [];
  return (
    <div className="mt-3 rounded-lg border border-cyan/20 bg-cyan/5 p-3 text-[11px] leading-relaxed text-slate-400">
      <div className="flex items-center justify-between gap-2">
        <div className="font-semibold text-cyan">Google Safe Browsing</div>
        <span className="rounded-full bg-slate-800 px-2 py-1 text-[10px] text-slate-300">
          {state}
        </span>
      </div>
      <p className="mt-1">
        Checks the submitted URL against Google’s threat lists for malware,
        phishing/social engineering, unwanted software, and potentially harmful
        applications.
      </p>
      <p className="mt-1">
        A clean result means no match was returned by Google; it does not prove
        the website is safe. Missing credentials or provider errors remain
        unknown, not clean.
      </p>
      {status?.provider && (
        <p className="mt-2">
          API {status.api_version} · key{" "}
          {status.api_key_configured ? "configured" : "missing"} · project{" "}
          {status.project_id_configured ? "identified" : "not identified"}
        </p>
      )}
      <div className="mt-2 border-t border-cyan/10 pt-2">
        Latest scan:{" "}
        <span className="font-semibold">{latest?.verdict || "Unknown"}</span>
        {categories.length > 0 && <> · categories: {categories.join(", ")}</>}
        {latest?.checked_at && (
          <>
            <br />
            Checked: {new Date(latest.checked_at).toLocaleString()}
          </>
        )}
        {matches.map((match: any, i: number) => (
          <div key={i} className="mt-1 text-danger">
            {match.threat_type} ·{" "}
            {match.platform_type || "platform unavailable"}
          </div>
        ))}
      </div>
      {status?.error && <p className="mt-2 text-danger">{status.error}</p>}
      <button
        type="button"
        onClick={() => load(true)}
        disabled={busy}
        className="mt-2 rounded-md border border-cyan/30 px-2 py-1 text-cyan"
      >
        {busy ? "Checking..." : "Check connection"}
      </button>
    </div>
  );
}
function ExternalProvidersPanel() {
  const [state, setState] = useState<any>();
  const [latest, setLatest] = useState<any>();
  const [busy, setBusy] = useState(false);
  async function refresh() {
    setBusy(true);
    try {
      const [connectivity, scan] = await Promise.all([
        api("/providers/external/status"),
        api("/providers/external/latest"),
      ]);
      setState(connectivity);
      setLatest(scan);
    } catch (error: any) {
      setState({
        providers: [
          {
            provider: "External intelligence",
            status: "unavailable",
            error: error.message,
          },
        ],
      });
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    refresh();
  }, []);
  const latestBy = (name: string) =>
    (latest?.providers || []).find((item: any) => item.provider === name);
  return (
    <div className="mt-5 rounded-2xl border border-amber-400/20 bg-amber-400/5 p-5">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-semibold text-amber-200">
            External threat intelligence
          </h3>
          <p className="mt-1 text-xs text-slate-400">
            OTX and MetaDefender results for the latest stored scan.
          </p>
        </div>
        <button
          type="button"
          onClick={refresh}
          disabled={busy}
          className="rounded-md border border-amber-300/30 px-3 py-1 text-xs text-amber-200"
        >
          {busy ? "Checking..." : "Refresh"}
        </button>
      </div>
      <div className="mt-4 grid gap-3 md:grid-cols-2">
        {(state?.providers || []).map((item: any) => {
          const result = latestBy(item.provider);
          return (
            <div
              key={item.provider}
              className="rounded-xl border border-line p-4"
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-semibold">{item.provider}</span>
                <span className="text-xs text-slate-400">{item.status}</span>
              </div>
              <div className="mt-2 text-xs text-slate-500">
                {item.configured
                  ? "Backend credential loaded"
                  : "Credential not configured"}{" "}
                ·{" "}
                {item.checked_at
                  ? new Date(item.checked_at).toLocaleString()
                  : "Not checked"}
              </div>
              <div className="mt-2 text-sm">
                Latest scan:{" "}
                <span className="font-semibold">
                  {result?.verdict || "Unknown"}
                </span>
              </div>
              {result?.evidence?.pulse_count !== undefined && (
                <div className="mt-1 text-xs text-slate-500">
                  OTX pulse reports: {result.evidence.pulse_count}
                </div>
              )}
              {result?.evidence?.detected_by !== undefined && (
                <div className="mt-1 text-xs text-slate-500">
                  MetaDefender detections: {result.evidence.detected_by}
                </div>
              )}
              {item.error && (
                <div className="mt-2 text-xs text-danger">{item.error}</div>
              )}
            </div>
          );
        })}
      </div>
      <p className="mt-3 text-xs text-slate-500">
        Unavailable providers do not create clean or malicious findings.
      </p>
    </div>
  );
}
function UrlhausPanel() {
  const [status, setStatus] = useState<any>();
  const [latest, setLatest] = useState<any>();
  const [busy, setBusy] = useState(false);
  async function refresh() {
    setBusy(true);
    try {
      const [connection, scan] = await Promise.all([
        api("/providers/urlhaus/status"),
        api("/providers/urlhaus/latest"),
      ]);
      setStatus(connection);
      setLatest(scan);
    } catch (error: any) {
      setStatus({ status: "unavailable", error: error.message });
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    refresh();
  }, []);
  return (
    <div className="mt-5 rounded-2xl border border-orange-400/20 bg-orange-400/5 p-5">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-semibold text-orange-200">
            URLhaus intelligence
          </h3>
          <p className="mt-1 text-xs text-slate-400">
            Authenticated URL reputation lookup through abuse.ch.
          </p>
        </div>
        <button
          type="button"
          onClick={refresh}
          disabled={busy}
          className="rounded-md border border-orange-300/30 px-3 py-1 text-xs text-orange-200"
        >
          {busy ? "Checking..." : "Refresh"}
        </button>
      </div>
      <div className="mt-4 grid gap-3 md:grid-cols-3">
        <div className="rounded-xl border border-line p-4">
          <div className="text-xs text-slate-500">Connection</div>
          <div className="mt-2 text-sm font-semibold">
            {status?.status || "Unknown"}
          </div>
        </div>
        <div className="rounded-xl border border-line p-4">
          <div className="text-xs text-slate-500">Latest verdict</div>
          <div className="mt-2 text-sm font-semibold">
            {latest?.verdict || "Unknown"}
          </div>
        </div>
        <div className="rounded-xl border border-line p-4">
          <div className="text-xs text-slate-500">Query status</div>
          <div className="mt-2 text-sm font-semibold">
            {latest?.evidence?.query_status || latest?.status || "Unavailable"}
          </div>
        </div>
      </div>
      {latest?.checked_at && (
        <p className="mt-3 text-xs text-slate-500">
          Checked: {new Date(latest.checked_at).toLocaleString()}
        </p>
      )}
      {status?.status === "not_configured" && (
        <p className="mt-3 text-sm text-danger">
          URLHAUS_AUTH_KEY is not configured. This is unknown, not clean.
        </p>
      )}
      {status?.error && (
        <p className="mt-3 text-sm text-danger">{status.error}</p>
      )}
    </div>
  );
}
