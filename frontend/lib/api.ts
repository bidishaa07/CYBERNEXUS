// The FastAPI development server runs on port 8001. Keep the override for
// deployments, but make the local default match the documented backend.
const API = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8001/api';
export async function api(path:string, options?:RequestInit) { const res = await fetch(`${API}${path}`, { ...options, headers: {'Content-Type':'application/json', ...(options?.headers||{})} }); if (!res.ok) { let detail = `Request failed (${res.status})`; try { const body = await res.json(); detail = body.detail || detail; } catch {} throw new Error(detail); } return res.json(); }
