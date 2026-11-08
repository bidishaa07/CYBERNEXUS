import { useEffect, useState } from 'react';
import { api } from '../../lib/api';

export default function InfrastructureHealthPanel() {
  const [health, setHealth] = useState<any>();
  const [error, setError] = useState('');
  useEffect(() => { api('/intelligence/providers/health').then(setHealth).catch((err: any) => setError(err.message || 'Health unavailable')); }, []);
  const items = health ? [
    ['Database', health.database?.status],
  ] : [];
  return <section className="mt-5 rounded-2xl border border-line bg-black/20 p-4"><div className="flex items-center justify-between"><div><h3 className="text-base font-semibold">Intelligence infrastructure</h3><p className="mt-1 text-xs text-slate-500">Operational status only; provider failures are not clean verdicts.</p></div><span className="text-xs text-slate-500">{error ? 'UNAVAILABLE' : health ? 'CHECKED' : 'CHECKING'}</span></div><div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">{(items.length ? items : [['Database', 'CHECKING']]).map(([label, status]) => <div key={label} className="rounded-xl border border-line p-3"><div className="text-xs text-slate-500">{label}</div><div className={`mt-2 text-sm font-semibold ${status === 'CONNECTED' || status === 'ok' ? 'text-emerald-300' : status === 'NOT_CONFIGURED' ? 'text-amber-300' : 'text-slate-300'}`}>{status || 'UNKNOWN'}</div></div>)}</div></section>;
}
