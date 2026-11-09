// The browser session uses HttpOnly cookies; credentials are never stored in JS storage.
const API = import.meta.env.VITE_API_URL || '/api';
export async function api(path: string, options?: RequestInit) {
  const res = await fetch(`${API}${path}`, { ...options, credentials: 'include', headers: { 'Content-Type': 'application/json', ...(options?.headers || {}) } });
  if (!res.ok) { let detail = `Request failed (${res.status})`; try { const body = await res.json(); detail = body.detail || detail; } catch {} throw new Error(detail); }
  return res.json();
}
export async function upload(path: string, file: File) {
  const form = new FormData(); form.append('file', file);
  const res = await fetch(`${API}${path}`, { method: 'POST', body: form, credentials: 'include' });
  if (!res.ok) { let detail = `Upload failed (${res.status})`; try { const body = await res.json(); detail = body.detail || detail; } catch {} throw new Error(detail); }
  return res.json();
}

export async function downloadFile(path: string) {
  const res = await fetch(`${API}${path}`, { credentials: 'include' });
  if (!res.ok) {
    let detail = `Download failed (${res.status})`;
    try { const body = await res.json(); detail = body.detail || detail; } catch {}
    throw new Error(detail);
  }
  return { blob: await res.blob(), disposition: res.headers.get('content-disposition') || '' };
}
