import { useEffect, useState } from "react";
import { api } from "../../lib/api";

const categories = ["FULL_SCAN", "TLS", "REDIRECTS", "SECURITY_HEADERS", "COOKIES", "DNS"];

export default function SecurityAuthorizationPanel() {
  const [items, setItems] = useState<any[]>([]);
  const [form, setForm] = useState({ target_hostname: "", authorized_organization: "", permitted_scope: "", expiration_time: "", supporting_reference: "", authorization_confirmation: false });
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const load = () => api("/security-authorizations").then(value => setItems(value.items || [])).catch((err: any) => setError(err.message || "Authorization records unavailable"));
  useEffect(() => { load(); }, []);
  const submit = async (event: any) => {
    event.preventDefault(); setBusy(true); setError(""); setMessage("");
    try {
      await api("/security-authorizations", { method: "POST", body: JSON.stringify({ ...form, permitted_scope: form.permitted_scope.split(",").map(x => x.trim()).filter(Boolean), allowed_categories: categories, expiration_time: new Date(form.expiration_time).toISOString() }) });
      setMessage("Authorization request submitted for administrator review."); setForm({ target_hostname: "", authorized_organization: "", permitted_scope: "", expiration_time: "", supporting_reference: "", authorization_confirmation: false }); load();
    } catch (err: any) { setError(err.message || "Authorization request failed"); } finally { setBusy(false); }
  };
  const action = async (id: number, operation: string) => { if (!window.confirm(`Confirm authorization ${operation}?`)) return; try { await api(`/security-authorizations/${id}/${operation}`, { method: "POST" }); load(); } catch (err: any) { setError(err.message || `Unable to ${operation} authorization`); } };
  return <section className="glass max-w-5xl rounded-3xl p-5 md:p-6">
    <div className="text-xs uppercase tracking-[.2em] text-cyan">Active testing controls</div>
    <h2 className="mt-1 text-xl font-semibold">Assessment authorization</h2>
    <p className="mt-1 text-sm text-slate-400">Passive analysis remains the default. Active checks require an approved, time-bounded authorization and stay within the recorded scope.</p>
    <form onSubmit={submit} className="mt-5 grid gap-2 md:grid-cols-2">
      <input required value={form.target_hostname} onChange={e => setForm({ ...form, target_hostname: e.target.value })} placeholder="Target hostname" className="rounded-lg border border-line bg-ink/60 p-3 text-sm" />
      <input required value={form.authorized_organization} onChange={e => setForm({ ...form, authorized_organization: e.target.value })} placeholder="Authorized organization or owner" className="rounded-lg border border-line bg-ink/60 p-3 text-sm" />
      <input required value={form.permitted_scope} onChange={e => setForm({ ...form, permitted_scope: e.target.value })} placeholder="Permitted hostnames (comma separated)" className="rounded-lg border border-line bg-ink/60 p-3 text-sm" />
      <input required type="datetime-local" value={form.expiration_time} onChange={e => setForm({ ...form, expiration_time: e.target.value })} aria-label="Authorization expiration" className="rounded-lg border border-line bg-ink/60 p-3 text-sm" />
      <input value={form.supporting_reference} onChange={e => setForm({ ...form, supporting_reference: e.target.value })} placeholder="Supporting authorization reference (optional)" className="rounded-lg border border-line bg-ink/60 p-3 text-sm md:col-span-2" />
      <label className="flex items-center gap-2 text-xs text-slate-400 md:col-span-2"><input type="checkbox" checked={form.authorization_confirmation} onChange={e => setForm({ ...form, authorization_confirmation: e.target.checked })} /> I confirm I am authorized to request these checks for the listed scope.</label>
      <button disabled={busy} className="rounded-lg bg-cyan px-4 py-3 text-sm font-semibold text-ink md:w-fit">{busy ? "Submitting..." : "Request active authorization"}</button>
    </form>
    {message && <div className="mt-4 rounded-lg border border-emerald-300/20 p-3 text-xs text-emerald-300">{message}</div>}
    {error && <div className="mt-4 rounded-lg border border-red-300/20 p-3 text-xs text-red-300">{error}</div>}
    <div className="mt-6 space-y-2">{items.length ? items.map(item => <div key={item.id} className="rounded-xl border border-line p-3 text-xs"><div className="flex flex-wrap justify-between gap-2"><span className="font-semibold text-cyan">#{item.id} · {item.target_hostname}</span><span>{item.approval_status}</span></div><div className="mt-1 text-slate-500">{item.authorized_organization} · Expires {item.expires_at ? new Date(item.expires_at).toLocaleString() : "Unavailable"}</div><div className="mt-2 text-slate-500">Scope: {(item.permitted_scope || []).join(", ")} · Checks: {(item.allowed_categories || []).join(", ")}</div><div className="mt-2 flex gap-2">{item.approval_status === "PENDING" && <><button onClick={() => action(item.id, "approve")} className="rounded border border-emerald-300/30 px-2 py-1 text-emerald-300">Approve</button><button onClick={() => action(item.id, "reject")} className="rounded border border-red-300/30 px-2 py-1 text-red-300">Reject</button></>}{item.approval_status === "APPROVED" && <button onClick={() => action(item.id, "revoke")} className="rounded border border-amber-300/30 px-2 py-1 text-amber-300">Revoke</button>}</div><details className="mt-2"><summary className="cursor-pointer text-slate-400">Authorization history</summary>{(item.history || []).map((event: any) => <div key={event.id} className="mt-1 text-slate-500">{event.action} · {event.actor} · {event.created_at ? new Date(event.created_at).toLocaleString() : ""}</div>)}</details></div>) : <div className="rounded-xl border border-line p-4 text-sm text-slate-500">No authorization requests found.</div>}</div>
  </section>;
}
