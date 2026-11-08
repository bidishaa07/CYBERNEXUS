import { useEffect, useState } from 'react';
import { api } from '../../lib/api';

function State({ value }: { value?: string }) {
  const text = value || 'UNKNOWN';
  const good = ['ok', 'CONNECTED', 'available', 'CONFIGURED'].includes(text);
  return <span className={good ? 'text-cyan' : 'text-amber-300'}>{text}</span>;
}

export default function MLLifecycleStatusPanel() {
  const [model, setModel] = useState<any>(null); const [health, setHealth] = useState<any>(null); const [error, setError] = useState('');
  const refresh = async () => { try { const [active, runtime] = await Promise.all([api('/ml/status'), api('/health')]); setModel(active); setHealth(runtime); setError(''); } catch (err: any) { setError(err.message || 'ML lifecycle status unavailable'); } };
  useEffect(() => { refresh(); }, []);
  return <section className="glass mt-5 rounded-3xl p-6"><div className="flex items-center justify-between gap-3"><div><h2 className="text-xl">ML lifecycle status</h2><p className="mt-1 text-xs text-slate-500">Live provenance and runtime state for the deployed message-classification model.</p></div><button onClick={refresh} className="rounded border border-line px-3 py-2 text-xs">Refresh</button></div>{error && <p className="mt-4 text-sm text-red-300">{error}</p>}{model && <div className="mt-4 grid gap-3 sm:grid-cols-2"><div className="rounded-xl border border-line p-4"><div className="text-xs text-slate-500">Production model</div><div className="mt-2 font-semibold text-cyan">{model.model_version || 'UNKNOWN'}</div><div className="mt-1 text-xs text-slate-400">Algorithm: {model.model || 'UNKNOWN'}</div></div><div className="rounded-xl border border-line p-4"><div className="text-xs text-slate-500">Training dataset</div><div className="mt-2 font-semibold text-cyan">{model.dataset_version || 'UNKNOWN'}</div><div className="mt-1 text-xs text-slate-400">Provenance: {model.dataset_version ? 'verified in deployed artifact' : 'not embedded'}</div></div><div className="rounded-xl border border-line p-4"><div className="text-xs text-slate-500">Evaluation</div><div className="mt-2">F1: <span className="text-cyan">{model.metrics?.test?.f1 ?? model.metrics?.f1 ?? 'UNKNOWN'}</span></div><div className="mt-1 text-xs text-slate-400">ROC-AUC: {model.metrics?.test?.roc_auc ?? model.metrics?.roc_auc ?? 'UNKNOWN'} · PR-AUC: {model.metrics?.test?.pr_auc ?? model.metrics?.pr_auc ?? 'UNKNOWN'}</div></div><div className="rounded-xl border border-line p-4"><div className="text-xs text-slate-500">Runtime</div><div className="mt-2">API: <State value={health?.status} /> · Database: <State value={health?.database} /></div><div className="mt-1 text-xs text-slate-400">Cache: <State value={health?.cache?.status} /> · retraining jobs persist in the database</div></div></div>}</section>;
}
