import { useEffect, useState } from 'react';
import { LogIn, LogOut, UserRound } from 'lucide-react';
import { api } from '../../lib/api';

export default function AuthPanel() {
  const [config, setConfig] = useState<any>(); const [me, setMe] = useState<any>(); const [error, setError] = useState('');
  useEffect(() => { Promise.all([api('/auth/config'), api('/auth/me')]).then(([c, user]) => { setConfig(c); setMe(user); }).catch((err: any) => setError(err.message || 'Authentication unavailable')); }, []);
  async function logout() { await api('/auth/logout', { method: 'POST' }); setMe({ authenticated: false }); }
  const login = () => { if (config?.authorization_url) window.location.assign(config.authorization_url); else setError('OIDC authorization URL is not configured'); };
  return <div className="fixed right-4 top-4 z-50 rounded-xl border border-line bg-panel/95 p-3 text-xs shadow-xl"><div className="flex items-center gap-2"><UserRound size={15} className="text-cyan"/><span>{me?.authenticated ? `${me.role} · ${me.user_id}` : config?.required ? 'Sign in required' : 'Development session'}</span>{me?.authenticated ? <button onClick={logout} title="Log out" className="ml-2 text-slate-400 hover:text-cyan"><LogOut size={15}/></button> : config?.required ? <button onClick={login} title="Sign in" className="ml-2 text-cyan"><LogIn size={15}/></button> : null}</div>{error && <div className="mt-2 max-w-64 text-red-300">{error}</div>}</div>;
}
