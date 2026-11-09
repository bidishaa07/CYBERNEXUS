import { useEffect, useState } from 'react';
import { api } from '../../lib/api';

type HistoryItem = { analysis_id: number; kind: string; classification?: string; risk_score?: number; created_at?: string };
const API = import.meta.env.VITE_API_URL || '/api';

export default function MessageReportsPanel() {
  const [items, setItems] = useState<HistoryItem[]>([]);
  const [selected, setSelected] = useState('');
  const [error, setError] = useState('');
  useEffect(() => { api('/message-analysis/history?page=1&page_size=8').then(data => setItems(data.items || [])).catch(err => setError(err.message || 'Reports unavailable')); }, []);
  const current = items.find(item => `${item.kind}-${item.analysis_id}` === selected);
  const path = current ? `/message-analysis/reports/${current.kind === 'EML' ? 'email' : 'text'}/${current.analysis_id}` : '';
  return <section className="glass mt-5 rounded-3xl p-6"><div><h2 className="text-xl">Message analysis reports</h2><p className="mt-1 text-xs text-slate-500">Export the persisted analysis exactly as stored. Reports separate verified evidence from model interpretation.</p></div>{error && <p className="mt-4 text-sm text-red-300">{error}</p>}{items.length ? <><select value={selected} onChange={event => setSelected(event.target.value)} className="mt-4 w-full rounded-lg border border-line bg-ink/60 p-3 text-sm"><option value="">Choose an analysis</option>{items.map(item => <option key={`${item.kind}-${item.analysis_id}`} value={`${item.kind}-${item.analysis_id}`}>{item.kind} #{item.analysis_id} · {item.classification || 'UNKNOWN'} · {item.risk_score ?? 'UNKNOWN'}/100</option>)}</select>{current && <div className="mt-4 flex flex-wrap items-center gap-2"><span className="text-xs text-slate-400">{current.created_at ? new Date(current.created_at).toLocaleString() : 'Timestamp unavailable'}</span>{(['json', 'csv', 'pdf'] as const).map(format => <a key={format} href={`${API}${path}?format=${format}`} target="_blank" rel="noreferrer" className="rounded border border-line px-3 py-2 text-xs text-cyan hover:bg-cyan/10">Download {format.toUpperCase()}</a>)}</div>}</> : !error && <p className="mt-4 text-sm text-slate-500">No persisted analyses are available for reporting.</p>}</section>;
}
