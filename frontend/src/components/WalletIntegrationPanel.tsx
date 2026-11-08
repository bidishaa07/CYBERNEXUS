import { useEffect, useState } from 'react';
import { api } from '../../lib/api';

declare global {
  interface Window { ethereum?: { request: (args: { method: string; params?: any[] }) => Promise<any>; on?: (event: string, handler: (...args: any[]) => void) => void; removeListener?: (event: string, handler: (...args: any[]) => void) => void } }
}

const SEPOLIA = '0xaa36a7';
const short = (value: string) => `${value.slice(0, 6)}...${value.slice(-4)}`;

export default function WalletIntegrationPanel() {
  const [address, setAddress] = useState('');
  const [chainId, setChainId] = useState('');
  const [error, setError] = useState('');
  const [status, setStatus] = useState('DISCONNECTED');
  const [ownership, setOwnership] = useState<any>();
  const [signature, setSignature] = useState<any>();
  const [reportId, setReportId] = useState('');
  const [revisionId, setRevisionId] = useState('');

  const refresh = async (accounts?: string[]) => {
    if (!window.ethereum) { setStatus('UNSUPPORTED_WALLET'); return; }
    const current = accounts || await window.ethereum.request({ method: 'eth_accounts' });
    const selected = current?.[0] || '';
    setAddress(selected); setChainId(await window.ethereum.request({ method: 'eth_chainId' })); setStatus(selected ? 'CONNECTED' : 'DISCONNECTED');
  };
  useEffect(() => {
    refresh().catch((err: any) => { setError(err.message || 'Wallet state unavailable'); setStatus('ERROR'); });
    const accountsChanged = (accounts: string[]) => { refresh(accounts).catch(() => setStatus('ERROR')); };
    const chainChanged = (chain: string) => { setChainId(chain); setStatus(address ? 'CONNECTED' : 'DISCONNECTED'); };
    window.ethereum?.on?.('accountsChanged', accountsChanged); window.ethereum?.on?.('chainChanged', chainChanged);
    return () => { window.ethereum?.removeListener?.('accountsChanged', accountsChanged); window.ethereum?.removeListener?.('chainChanged', chainChanged); };
  }, [address]);

  async function connect() { setError(''); try { if (!window.ethereum) throw new Error('An EIP-1193 wallet was not detected'); await window.ethereum.request({ method: 'eth_requestAccounts' }); await refresh(); } catch (err: any) { setError(err.message || 'Wallet connection failed'); } }
  function disconnect() { setAddress(''); setChainId(''); setStatus('DISCONNECTED'); setOwnership(undefined); setSignature(undefined); }
  async function verifyOwnership() {
    try { setError(''); if (!address || chainId !== SEPOLIA) throw new Error('Connect a wallet on Sepolia first'); const challenge = await api('/threat-intelligence/wallet/challenges', { method: 'POST', body: JSON.stringify({ address, action: 'WALLET_OWNERSHIP' }) }); const signed = await window.ethereum!.request({ method: 'personal_sign', params: [challenge.message, address] }); setOwnership(await api(`/threat-intelligence/wallet/challenges/${challenge.challenge_id}/verify`, { method: 'POST', body: JSON.stringify({ address, signature: signed, chain_id: parseInt(chainId, 16) }) })); } catch (err: any) { setError(err.message || 'Wallet ownership verification failed'); }
  }
  async function signRevision() {
    try { setError(''); if (!reportId || !revisionId) throw new Error('Enter a report ID and revision ID'); const challenge = await api(`/threat-intelligence/reports/${reportId}/revisions/${revisionId}/signature/challenge`, { method: 'POST', body: JSON.stringify({ address }) }); const approved = window.confirm('This is an off-chain EIP-712 report signature request. It will not submit a blockchain transaction. Continue?'); if (!approved) return; const signed = await window.ethereum!.request({ method: 'eth_signTypedData_v4', params: [address, JSON.stringify(challenge.typed_data)] }); setSignature(await api(`/threat-intelligence/signatures/${challenge.challenge_id}/verify`, { method: 'POST', body: JSON.stringify({ signature: signed }) })); } catch (err: any) { setError(err.message || 'Report signature failed'); }
  }
  const supported = chainId === SEPOLIA;
  return <section className="glass mt-5 rounded-3xl border border-cyan/20 p-6"><div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="text-xl font-semibold">Wallet identity and report signatures</h2><p className="mt-1 text-sm text-slate-400">Wallet identity is separate from application login. Signatures prove control of a wallet; they do not authenticate your account.</p></div><span className={`text-xs ${supported ? 'text-emerald-300' : 'text-amber-300'}`}>{status}</span></div><div className="mt-4 grid gap-3 sm:grid-cols-3"><div className="rounded-xl border border-line p-3"><div className="text-xs text-slate-500">Wallet</div><div className="mt-2 text-sm">{address ? short(address) : 'Not connected'}</div></div><div className="rounded-xl border border-line p-3"><div className="text-xs text-slate-500">Network</div><div className="mt-2 text-sm">{chainId ? `${chainId === SEPOLIA ? 'Sepolia' : 'Unsupported'} (${parseInt(chainId, 16)})` : 'Unknown'}</div></div><div className="flex items-end gap-2"><button onClick={connect} className="rounded border border-cyan px-3 py-2 text-sm text-cyan">Connect</button><button onClick={disconnect} className="rounded border border-line px-3 py-2 text-sm">Disconnect</button></div></div>{!supported && address && <p className="mt-3 text-sm text-amber-300">Switch to Sepolia (chain ID 11155111). Network changes are detected automatically.</p>}<div className="mt-4 flex flex-wrap gap-2"><button disabled={!supported} onClick={verifyOwnership} className="rounded border border-cyan px-3 py-2 text-sm text-cyan disabled:opacity-40">Verify wallet ownership</button>{ownership && <span className="rounded border border-emerald-400/30 px-3 py-2 text-sm text-emerald-300">Ownership verified</span>}</div><div className="mt-5 rounded-xl border border-line p-4"><div className="text-sm font-semibold">Sign a report revision</div><p className="mt-1 text-xs text-slate-500">Requires verified wallet ownership and creates an off-chain EIP-712 signature record.</p><div className="mt-3 grid gap-2 sm:grid-cols-2"><input value={reportId} onChange={e => setReportId(e.target.value)} placeholder="Report ID" className="rounded border border-line bg-black/20 px-3 py-2 text-sm" /><input value={revisionId} onChange={e => setRevisionId(e.target.value)} placeholder="Revision ID" className="rounded border border-line bg-black/20 px-3 py-2 text-sm" /></div><button disabled={!supported || !ownership} onClick={signRevision} className="mt-3 rounded border border-cyan px-3 py-2 text-sm text-cyan disabled:opacity-40">Request signature</button>{signature && <p className="mt-2 text-sm text-emerald-300">Signature verified for revision {signature.revision_id}.</p>}</div>{error && <p className="mt-3 text-sm text-red-300">{error}</p>}</section>;
}
