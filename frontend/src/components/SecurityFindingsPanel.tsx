import { useEffect, useMemo, useState } from "react";
import { api, downloadFile } from "../../lib/api";

const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const categories = ["SECURITY_HEADERS", "COOKIES", "TLS", "DNS", "HTTP", "OTHER"];
const remediationStatuses = [
  "OPEN",
  "ACKNOWLEDGED",
  "IN_PROGRESS",
  "FIXED",
  "ACCEPTED_RISK",
  "FALSE_POSITIVE",
  "REOPENED",
];
const tone = (value: string) =>
  value === "CRITICAL" || value === "HIGH" || value === "FAIL"
    ? "text-red-300"
    : value === "MEDIUM" || value === "WARNING"
      ? "text-amber-300"
      : value === "PASS"
        ? "text-emerald-300"
        : "text-slate-400";

export default function SecurityFindingsPanel({ scan }: { scan?: any }) {
  const [data, setData] = useState<any>({ items: [], counts: {} });
  const [filters, setFilters] = useState<any>({
    severity: "",
    category: "",
    status: "",
    remediation_status: "",
    confidence: "",
    hostname: "",
    assessment_id: "",
    date_from: "",
    date_to: "",
    search: "",
    sort: "newest",
  });
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [assessment, setAssessment] = useState<any>();
  const [assessmentMode, setAssessmentMode] = useState("PASSIVE");
  const [authorizationId, setAuthorizationId] = useState("");
  const [reportHistory, setReportHistory] = useState<any[]>([]);
  const [reportPreview, setReportPreview] = useState<any>();
  const [selected, setSelected] = useState<any>();
  const [busy, setBusy] = useState<number | null>(null);
  const query = useMemo(() => {
    const params = new URLSearchParams({ page: String(page), page_size: "15" });
    Object.entries(filters).forEach(([key, value]) => {
      if (value) params.set(key, String(value));
    });
    return params.toString();
  }, [filters, page]);
  const load = () => {
    setLoading(true);
    setError("");
    api("/security-findings?" + query)
      .then(setData)
      .catch((err: any) =>
        setError(err.message || "Finding search unavailable"),
      )
      .finally(() => setLoading(false));
  };
  useEffect(() => {
    load();
  }, [query]);
  const createAssessment = async () => {
    if (!scan?.id) return;
    setBusy(-1);
    try {
      const value = await api("/security-assessments", {
        method: "POST",
        body: JSON.stringify({
          scan_id: scan.id,
          target_url: scan.url || "https://" + scan.domain + "/",
          assessment_mode: assessmentMode,
          ...(assessmentMode === "ACTIVE" ? { authorization_id: authorizationId, allowed_categories: ["TLS", "REDIRECTS", "SECURITY_HEADERS"] } : {}),
        }),
      });
      setAssessment(value);
      setReportHistory((await api(`/security-assessments/${value.id}/reports`)).items || []);
      load();
    } catch (err: any) {
      setError(err.message || "Unable to create assessment");
    } finally {
      setBusy(null);
    }
  };
  const executeAssessment = async () => {
    if (!assessment?.id || !window.confirm("Execute the authorized active assessment within its recorded scope?")) return;
    setBusy(-2);
    try { setAssessment(await api(`/security-assessments/${assessment.id}/execute`, { method: "POST", body: JSON.stringify({ allowed_categories: ["TLS", "REDIRECTS", "SECURITY_HEADERS"] }) })); load(); }
    catch (err: any) { setError(err.message || "Authorized assessment execution failed"); }
    finally { setBusy(null); }
  };
  const previewReport = async () => {
    if (!assessment?.id) return;
    try { setReportPreview(await api(`/security-assessments/${assessment.id}/report?format=json`)); }
    catch (err: any) { setError(err.message || "Report preview unavailable"); }
  };
  const downloadReport = async (format: string) => {
    if (!assessment?.id) return;
    try {
      const result = await downloadFile(`/security-assessments/${assessment.id}/report?format=${format}`);
      const url = URL.createObjectURL(result.blob);
      const link = document.createElement("a"); link.href = url; link.download = `security-assessment-${assessment.id}.${format}`; link.click(); URL.revokeObjectURL(url);
      setReportHistory((await api(`/security-assessments/${assessment.id}/reports`)).items || []);
    } catch (err: any) { setError(err.message || "Report download failed"); }
  };
  const open = async (item: any) => {
    try {
      setSelected(await api("/security-findings/" + item.id));
    } catch (err: any) {
      setError(err.message || "Finding details unavailable");
    }
  };
  const change = async (item: any, payload: any, confirmText?: string) => {
    if (confirmText && !window.confirm(confirmText)) return;
    setBusy(item.id);
    try {
      const value = await api(
        "/security-findings/" + item.id + "/remediation",
        { method: "PATCH", body: JSON.stringify(payload) },
      );
      setSelected(value);
      load();
    } catch (err: any) {
      setError(err.message || "Remediation action failed");
    } finally {
      setBusy(null);
    }
  };
  const verify = async (item: any, passed: boolean) => {
    if (
      !window.confirm(
        passed
          ? "Confirm that the issue was technically rechecked and fixed?"
          : "Confirm that verification failed and the finding should be reopened?",
      )
    )
      return;
    setBusy(item.id);
    try {
      const value = await api("/security-findings/" + item.id + "/verify", {
        method: "POST",
        body: JSON.stringify({
          verified: passed,
          note: passed
            ? "Verified in findings dashboard"
            : "Verification failed in findings dashboard",
        }),
      });
      setSelected(value);
      load();
    } catch (err: any) {
      setError(err.message || "Verification failed");
    } finally {
      setBusy(null);
    }
  };
  const counts = data.counts || {};
  const severityCounts = counts.severity || {};
  const statusCounts = counts.status || {};
  const remediationCounts = counts.remediation || {};
  const update = (key: string, value: string) => {
    setPage(1);
    setFilters({ ...filters, [key]: value });
  };
  return (
    <section className="glass rounded-3xl p-5 md:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-xs uppercase tracking-[.2em] text-cyan">
            Website security assessment
          </div>
          <h2 className="mt-1 text-xl font-semibold">
            Security findings and remediation
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Status changes are audited. FIXED requires a separate technical
            verification.
          </p>
        </div>
        {scan?.id && <div className="flex flex-wrap items-center gap-2"><select value={assessmentMode} onChange={e => setAssessmentMode(e.target.value)} className="rounded-lg border border-line bg-ink p-2 text-xs"><option value="PASSIVE">Passive assessment</option><option value="ACTIVE">Active (authorization required)</option></select>{assessmentMode === "ACTIVE" && <input value={authorizationId} onChange={e => setAuthorizationId(e.target.value)} placeholder="Authorization ID" inputMode="numeric" className="w-32 rounded-lg border border-line bg-ink p-2 text-xs" />}<button onClick={createAssessment} disabled={busy === -1} className="rounded-lg border border-cyan/30 px-3 py-2 text-xs text-cyan">{busy === -1 ? "Creating..." : "Create assessment"}</button></div>}
      </div>
      {assessment && (
        <div className="mt-3 rounded-lg border border-emerald-300/20 bg-emerald-300/5 p-3 text-xs text-emerald-300">
          <div>Assessment #{assessment.id} created from scan evidence.</div>
          {assessment.assessment_mode === "ACTIVE" && <button onClick={executeAssessment} disabled={busy === -2} className="mt-2 rounded border border-amber-300/30 px-2 py-1 text-amber-300">{busy === -2 ? "Executing..." : "Execute authorized active checks"}</button>}
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <button onClick={previewReport} className="rounded border border-cyan/30 px-2 py-1 text-cyan">Preview report</button>
            {['json', 'csv', 'pdf'].map(format => <button key={format} onClick={() => downloadReport(format)} className="rounded border border-line px-2 py-1 uppercase">Download {format}</button>)}
            <span className="text-slate-500">Reports are generated from persisted findings.</span>
          </div>
          {reportHistory.length > 0 && <div className="mt-2 text-slate-500">Previous exports: {reportHistory.map(item => `${item.format.toUpperCase()} ${item.generated_at ? new Date(item.generated_at).toLocaleString() : ''}`).join(' · ')}</div>}
        </div>
      )}
      {reportPreview && <div className="mt-3 rounded-lg border border-cyan/20 bg-black/20 p-3 text-xs"><div className="flex justify-between"><b>Report preview</b><button onClick={() => setReportPreview(undefined)} className="text-slate-500">Close</button></div><div className="mt-2 grid gap-1 sm:grid-cols-3"><span>Checks: {reportPreview.executive_summary?.total_checks ?? 0}</span><span>Failed: {reportPreview.executive_summary?.failed ?? 0}</span><span>Warnings: {reportPreview.executive_summary?.warnings ?? 0}</span></div><pre className="mt-2 max-h-48 overflow-auto rounded bg-ink p-2 text-[10px] text-slate-400">{JSON.stringify(reportPreview.executive_summary, null, 2)}</pre></div>}
      <div className="mt-5 grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-8">
        {[
          ["Total", data.total || 0],
          ...severities.map((item) => [item, severityCounts[item] || 0]),
          ["PASS", statusCounts.PASS || 0],
          ["FAIL", statusCounts.FAIL || 0],
          ["WARN", statusCounts.WARNING || 0],
          [
            "Unknown",
            (statusCounts.UNKNOWN || 0) + (statusCounts.NOT_APPLICABLE || 0),
          ],
          ["Fixed", remediationCounts.FIXED || 0],
        ].map(([label, value]) => (
          <div
            key={String(label)}
            className="rounded-xl border border-line p-2"
          >
            <div className="text-[10px] text-slate-500">{label}</div>
            <div
              className={"mt-1 text-lg font-semibold " + tone(String(label))}
            >
              {value}
            </div>
          </div>
        ))}
      </div>
      <div className="mt-5 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        <input
          value={filters.search}
          onChange={(e) => update("search", e.target.value)}
          placeholder="Search title, hostname, category or ID"
          className="rounded-lg border border-line bg-ink/60 p-2 text-xs"
        />
        <input
          value={filters.hostname}
          onChange={(e) => update("hostname", e.target.value)}
          placeholder="Hostname"
          className="rounded-lg border border-line bg-ink/60 p-2 text-xs"
        />
        <input
          value={filters.assessment_id}
          onChange={(e) => update("assessment_id", e.target.value)}
          placeholder="Assessment ID"
          inputMode="numeric"
          className="rounded-lg border border-line bg-ink/60 p-2 text-xs"
        />
        <input
          type="datetime-local"
          value={filters.date_from}
          onChange={(e) => update("date_from", e.target.value)}
          aria-label="Detected from"
          className="rounded-lg border border-line bg-ink/60 p-2 text-xs"
        />
        <input
          type="datetime-local"
          value={filters.date_to}
          onChange={(e) => update("date_to", e.target.value)}
          aria-label="Detected to"
          className="rounded-lg border border-line bg-ink/60 p-2 text-xs"
        />
        {[
          ["severity", "Severity", severities],
          ["category", "Category", categories],
          [
            "status",
            "Finding status",
            ["PASS", "FAIL", "WARNING", "UNKNOWN", "NOT_APPLICABLE"],
          ],
          ["remediation_status", "Remediation", remediationStatuses],
          ["confidence", "Confidence", ["HIGH", "MEDIUM", "LOW", "UNKNOWN"]],
        ].map(([key, label, options]: any) => (
          <select
            key={key}
            value={filters[key]}
            onChange={(e) => update(key, e.target.value)}
            className="rounded-lg border border-line bg-ink/60 p-2 text-xs"
          >
            <option value="">{label}</option>
            {options.map((item: string) => (
              <option key={item}>{item}</option>
            ))}
          </select>
        ))}
        <select
          value={filters.sort}
          onChange={(e) => setFilters({ ...filters, sort: e.target.value })}
          className="rounded-lg border border-line bg-ink/60 p-2 text-xs"
        >
          <option value="newest">Newest</option>
          <option value="oldest">Oldest</option>
          <option value="severity">Severity</option>
          <option value="confidence">Confidence</option>
          <option value="remediation">Remediation</option>
          <option value="alphabetical">Alphabetical</option>
        </select>
      </div>
      {error && (
        <div className="mt-4 rounded-lg border border-red-300/20 p-3 text-xs text-red-300">
          {error}
        </div>
      )}
      {loading && (
        <div className="mt-4 text-xs text-slate-500">Loading findings...</div>
      )}
      <div className="mt-4 space-y-2">
        {!loading && data.items?.length
          ? data.items.map((item: any) => (
              <div key={item.id} className="rounded-xl border border-line p-3">
                <button className="w-full text-left" onClick={() => open(item)}>
                  <div className="flex flex-wrap justify-between gap-2">
                    <span className={"font-semibold " + tone(item.severity)}>
                      #{item.id} · {item.title}
                    </span>
                    <span className="text-xs">
                      {item.severity} · {item.status}
                    </span>
                  </div>
                  <div className="mt-1 text-xs text-slate-500">
                    {item.hostname} · {item.category} · {item.confidence}{" "}
                    confidence · {item.remediation?.status || "OPEN"}
                  </div>
                </button>
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <select
                    value={item.remediation?.status || "OPEN"}
                    disabled={busy === item.id}
                    onChange={(e) =>
                      change(
                        item,
                        {
                          status: e.target.value,
                          note: "Updated in findings dashboard",
                        },
                        "Change remediation status?",
                      )
                    }
                    className="rounded border border-line bg-ink p-1 text-[11px]"
                  >
                    {remediationStatuses.map((status) => (
                      <option key={status}>{status}</option>
                    ))}
                  </select>
                  <button
                    onClick={() =>
                      change(item, {
                        request_verification: true,
                        note: "Verification requested",
                      })
                    }
                    className="rounded border border-cyan/30 px-2 py-1 text-[11px] text-cyan"
                  >
                    Request verification
                  </button>
                </div>
              </div>
            ))
          : !loading && (
              <div className="rounded-xl border border-line p-5 text-sm text-slate-500">
                No findings match the selected filters.
              </div>
            )}
      </div>
      {data.pages > 1 && (
        <div className="mt-4 flex items-center justify-between text-xs">
          <button
            disabled={page <= 1}
            onClick={() => setPage(page - 1)}
            className="rounded border border-line px-3 py-2 disabled:opacity-40"
          >
            Previous
          </button>
          <span>
            Page {page} of {data.pages}
          </span>
          <button
            disabled={page >= data.pages}
            onClick={() => setPage(page + 1)}
            className="rounded border border-line px-3 py-2 disabled:opacity-40"
          >
            Next
          </button>
        </div>
      )}
      {selected && (
        <div className="mt-5 rounded-2xl border border-cyan/20 bg-black/20 p-4">
          <div className="flex justify-between gap-3">
            <div>
              <h3 className={"font-semibold " + tone(selected.severity)}>
                {selected.title}
              </h3>
              <p className="mt-1 text-xs text-slate-500">
                {selected.hostname} · {selected.target_url} ·{" "}
                {selected.category}
              </p>
            </div>
            <button
              onClick={() => setSelected(undefined)}
              className="text-xs text-slate-500"
            >
              Close
            </button>
          </div>
          <div className="mt-4 grid gap-2 text-xs md:grid-cols-2">
            <div>
              <b>Description:</b> {selected.description || "Unavailable"}
            </div>
            <div>
              <b>Observed:</b>{" "}
              {String(selected.observed_value || "Unavailable")}
            </div>
            <div>
              <b>Expected:</b>{" "}
              {String(selected.expected_value || "Unavailable")}
            </div>
            <div>
              <b>Confidence:</b> {selected.confidence}
            </div>
            <div>
              <b>Impact:</b> {selected.security_impact || "Unavailable"}
            </div>
            <div>
              <b>Remediation:</b> {selected.remediation?.status || "OPEN"}
            </div>
            <div>
              <b>Limitations:</b>{" "}
              {selected.verification_limitations || "None recorded"}
            </div>
            <div>
              <b>Detected:</b>{" "}
              {selected.first_detected
                ? new Date(selected.first_detected).toLocaleString()
                : "Unavailable"}
            </div>
          </div>
          <pre className="mt-3 max-h-40 overflow-auto rounded-lg bg-ink p-3 text-[10px] text-slate-400">
            {JSON.stringify(selected.evidence, null, 2)}
          </pre>
          <div className="mt-4 rounded-xl border border-line p-3">
            <div className="text-xs font-semibold">Remediation workflow</div>
            <div className="mt-2 grid gap-2 md:grid-cols-2">
              <input
                defaultValue={selected.remediation?.assigned_to || ""}
                onBlur={(e) =>
                  change(selected, {
                    assigned_to: e.target.value,
                    note: "Assignment updated",
                  })
                }
                placeholder="Assign to user ID"
                className="rounded border border-line bg-ink p-2 text-xs"
              />
              <input
                defaultValue={selected.remediation?.proposed_fix || ""}
                onBlur={(e) =>
                  change(selected, {
                    proposed_fix: e.target.value,
                    note: "Proposed fix updated",
                  })
                }
                placeholder="Proposed fix"
                className="rounded border border-line bg-ink p-2 text-xs"
              />
              <input
                defaultValue={selected.remediation?.applied_fix || ""}
                onBlur={(e) =>
                  change(selected, {
                    applied_fix: e.target.value,
                    note: "Applied fix updated",
                  })
                }
                placeholder="Applied fix"
                className="rounded border border-line bg-ink p-2 text-xs"
              />
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              <button
                onClick={() => verify(selected, true)}
                className="rounded border border-emerald-300/30 px-2 py-1 text-xs text-emerald-300"
              >
                Verify fixed
              </button>
              <button
                onClick={() => verify(selected, false)}
                className="rounded border border-amber-300/30 px-2 py-1 text-xs text-amber-300"
              >
                Verification failed / reopen
              </button>
            </div>
          </div>
          <div className="mt-4">
            <h4 className="text-xs font-semibold">Audit history</h4>
            {selected.remediation?.history?.length ? (
              selected.remediation.history.map((event: any) => (
                <div
                  key={event.id}
                  className="mt-2 rounded border border-line p-2 text-[11px]"
                >
                  <span className="text-cyan">{event.action}</span> ·{" "}
                  {event.actor} · {event.previous_status || "—"} →{" "}
                  {event.new_status || "—"} ·{" "}
                  {event.created_at
                    ? new Date(event.created_at).toLocaleString()
                    : ""}
                  <div className="text-slate-500">{event.note}</div>
                </div>
              ))
            ) : (
              <div className="mt-2 text-xs text-slate-500">
                No remediation actions recorded.
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
