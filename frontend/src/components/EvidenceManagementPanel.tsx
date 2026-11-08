import { useState } from "react";
import { api } from "../../lib/api";

export default function EvidenceManagementPanel() {
  const [reportId, setReportId] = useState("");
  const [revisionId, setRevisionId] = useState("");
  const [items, setItems] = useState<any[]>([]);
  const [manifests, setManifests] = useState<any[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    if (!reportId || !revisionId) {
      setError("Enter a report ID and revision ID.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const result = await api(`/threat-intelligence/reports/${reportId}/revisions/${revisionId}/evidence`);
      setItems(result.items || []);
      setManifests(result.manifests || []);
    } catch (err: any) {
      setError(err.message || "Evidence could not be loaded");
    } finally {
      setBusy(false);
    }
  }

  async function verify(id: number) {
    try {
      const result = await api(`/threat-intelligence/evidence/${id}/verify`, { method: "POST" });
      setItems((current) => current.map((item) => item.id === id ? { ...item, integrity: result } : item));
    } catch (err: any) {
      setError(err.message || "Evidence verification failed");
    }
  }

  async function pin(id: number) {
    try {
      const result = await api(`/threat-intelligence/evidence/${id}/ipfs`, { method: "POST" });
      setItems((current) => current.map((item) => item.id === id ? { ...item, ipfs_status: result.status, ipfs_cid: result.cid } : item));
    } catch (err: any) {
      setError(err.message || "IPFS pinning failed");
    }
  }

  return <section className="glass rounded-3xl border border-cyan/20 p-6">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><h2 className="text-xl font-semibold">Off-chain evidence integrity</h2><p className="mt-1 text-sm text-slate-400">Private evidence remains off-chain. Hashes, manifests and verification provenance are exposed; storage paths and secrets are not.</p></div>
      <span className="text-xs text-cyan">SHA-256 manifests</span>
    </div>
    <div className="mt-4 flex flex-wrap gap-2">
      <input value={reportId} onChange={(e) => setReportId(e.target.value)} placeholder="Report ID" className="rounded border border-line bg-black/20 px-3 py-2 text-sm" />
      <input value={revisionId} onChange={(e) => setRevisionId(e.target.value)} placeholder="Revision ID" className="rounded border border-line bg-black/20 px-3 py-2 text-sm" />
      <button type="button" onClick={load} disabled={busy} className="rounded bg-cyan px-3 py-2 text-sm font-semibold text-ink">{busy ? "Loading..." : "Load evidence"}</button>
    </div>
    {error && <p className="mt-3 text-sm text-red-300">{error}</p>}
    {!items.length ? <p className="mt-5 text-sm text-slate-500">No evidence loaded. Evidence is private by default and requires report ownership or administrator access.</p> : <div className="mt-5 space-y-3">{items.map((item) => <div key={item.id} className="rounded-xl border border-line p-4"><div className="flex flex-wrap items-center justify-between gap-2"><div className="text-sm font-semibold">Evidence #{item.id} · {item.content_type || "unknown type"}</div><span className={`text-xs ${item.integrity?.status === "VERIFIED" ? "text-emerald-300" : "text-amber-300"}`}>{item.integrity?.status || "UNKNOWN"}</span></div><div className="mt-2 break-all text-xs text-slate-500">SHA-256: {item.object_hash}</div><div className="mt-2 grid gap-1 text-xs text-slate-400 sm:grid-cols-3"><span>Encryption: {item.encryption_status}</span><span>Malware scan: {item.malware_scan_status}</span><span>IPFS: {item.ipfs_status}</span></div><div className="mt-3 flex flex-wrap gap-2"><button type="button" onClick={() => verify(item.id)} className="rounded border border-cyan px-2 py-1 text-xs text-cyan">Verify hash</button><button type="button" onClick={() => pin(item.id)} className="rounded border border-line px-2 py-1 text-xs">Pin encrypted object</button><a href={`/api/threat-intelligence/evidence/${item.id}/content`} className="rounded border border-line px-2 py-1 text-xs">Download verified content</a></div></div>)}</div>}
    {manifests.length > 0 && <div className="mt-5"><h3 className="text-sm font-semibold">Manifest history</h3><div className="mt-2 space-y-1 text-xs text-slate-400">{manifests.map((manifest) => <div key={manifest.id} className="rounded border border-line p-2">Version {manifest.version} · {manifest.manifest_hash} · {manifest.created_at}</div>)}</div></div>}
  </section>;
}
