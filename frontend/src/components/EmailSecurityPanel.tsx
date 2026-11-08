import { useState } from 'react';
import { MailCheck, Upload } from 'lucide-react';
import { upload } from '../../lib/api';

export default function EmailSecurityPanel() {
  const [result, setResult] = useState<any>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function handleUpload(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setBusy(true); setError('');
    try { setResult(await upload('/message-analysis/email', file)); }
    catch (err: any) { setError(err.message || 'Email analysis failed'); }
    finally { setBusy(false); }
  }

  const auth = result?.authentication || [];
  return <section className="fixed bottom-4 right-4 z-40 w-[min(92vw,560px)] rounded-2xl border border-cyan/30 bg-panel p-5 shadow-2xl shadow-black/50">
    <div className="flex items-center gap-3"><MailCheck className="text-cyan"/><div><h2 className="font-semibold">Email Security Analysis</h2><p className="text-xs text-slate-400">Upload an RFC-compliant .eml file for sender, header and authentication analysis.</p></div></div>
    <label className="mt-4 flex cursor-pointer items-center justify-center gap-2 rounded-xl border border-dashed border-cyan/40 bg-cyan/5 p-3 text-sm text-cyan"><Upload size={16}/>{busy ? 'Analyzing email…' : 'Choose .eml file'}<input type="file" accept=".eml,message/rfc822" onChange={handleUpload} className="hidden"/></label>
    <p className="mt-2 text-[11px] text-slate-500">Maximum 10 MB. Attachments are metadata-only; scripts and external resources are not executed or downloaded.</p>
    {error && <p className="mt-3 text-xs text-red-300">{error}</p>}
    {result && <div className="mt-4 max-h-[55vh] overflow-y-auto rounded-xl border border-line p-3">
      <div className="flex items-center justify-between"><span className="text-sm font-semibold">{result.sender?.subject || 'Untitled message'}</span><span className="rounded-full bg-emerald-400/10 px-2 py-1 text-[11px] text-emerald-300">{result.status}</span></div>
      <div className="mt-3 grid gap-2 text-xs text-slate-300"><div>From: {result.sender?.from || 'Unavailable'}</div><div>Reply-To: {result.sender?.reply_to || 'Unavailable'}</div><div>Return-Path: {result.sender?.return_path || 'Unavailable'}</div><div>Message-ID: {result.sender?.message_id || 'Unavailable'}</div></div>
      <div className="mt-4 rounded-lg border border-line p-3"><div className="mb-2 text-xs font-semibold text-cyan">Authentication status</div>{auth.map((item: any) => <div key={item.mechanism} className="flex justify-between border-b border-line py-2 text-xs last:border-0"><span>{item.mechanism}{item.evidence?.reported_status && <span className="ml-2 text-slate-500">reported {item.evidence.reported_status}</span>}</span><span className={item.status === 'PASS' ? 'text-emerald-300' : item.status === 'UNKNOWN' ? 'text-amber-300' : 'text-red-300'}>{item.status}</span></div>)}<p className="mt-2 text-[11px] text-slate-500">Uploaded Authentication-Results are not independently trusted. UNKNOWN is not SAFE.</p></div>
      {result.anomalies?.length ? <div className="mt-3 rounded-lg border border-amber-400/20 bg-amber-400/5 p-3"><div className="text-xs font-semibold text-amber-200">Header anomalies</div>{result.anomalies.map((item: any, index: number) => <div key={index} className="mt-2 text-xs text-amber-100">{item.severity.toUpperCase()} · {item.type}: {item.evidence}</div>)}</div> : <p className="mt-3 text-xs text-slate-500">No header anomalies detected; this is not proof the message is safe.</p>}
      <details className="mt-3 rounded-lg border border-line p-3"><summary className="cursor-pointer text-xs">Parsed headers ({result.headers?.length || 0})</summary>{result.headers?.map((header: any, index: number) => <div key={index} className="border-b border-line py-2 text-xs"><span className="font-semibold text-cyan">{header.name}</span>: {header.value}</div>)}</details>
    </div>}
  </section>;
}
