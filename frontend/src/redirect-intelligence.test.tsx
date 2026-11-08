import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import App from './App';

const fixture = {
  id: 501, domain: 'start.example', normalized_url: 'https://start.example/',
  phishing: { evidence: [] }, certificate: { status: 'valid', ct_records: [] },
  threat_intelligence: { findings: [], providers: [] }, precautions: [],
  domain_intelligence: { domain: { brand_matches: [] }, rdap: { status: 'unavailable' }, infrastructure: { providers: [] } },
  network: { http: { status: 200, final_url: 'https://suspicious.test/login', redirects: [{ sequence: 1, source_url: 'https://start.example/', destination_url: 'https://suspicious.test/login', source_domain: 'start.example', destination_domain: 'suspicious.test', status_code: 302, https: true, https_downgrade: false, destination_ips: ['203.0.113.10'] }] }, dns: { records: {} },
    redirect_analysis: { risk: { score: 45, level: 'High', confidence: 'medium', complete: true, evidence: [{ message: 'Known malicious destination detected', points: 45 }] }, comparison: { destination_count: 1, final_domain: 'suspicious.test' }, destinations: { 'suspicious.test': { verdict: 'malicious', provider_results: [{ provider: 'Google Safe Browsing', state: 'THREAT_DETECTED', verdict: 'malicious', threat_categories: ['SOCIAL_ENGINEERING'], evidence_available: true }, { provider: 'VirusTotal', state: 'UNAVAILABLE', verdict: 'unknown', reason: 'API key not configured', evidence_available: false }] } } } },
  risk: { score: 45, level: 'High', confidence: 'medium' }
};

describe('redirect intelligence UI', () => {
  beforeEach(() => {
    global.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/scans') && !init?.method) return { ok: true, json: async () => [] } as Response;
      if (url.endsWith('/scans')) return { ok: true, json: async () => fixture } as Response;
      return { ok: true, json: async () => ({}) } as Response;
    }) as typeof fetch;
  });

  it('renders hop-specific providers, risk evidence, and unavailable states', async () => {
    render(<App />);
    fireEvent.change(screen.getByPlaceholderText('https://example.com'), { target: { value: 'https://start.example' } });
    fireEvent.click(screen.getByRole('button', { name: 'Run trust scan' }));
    expect(await screen.findByText('Redirect intelligence')).toBeInTheDocument();
    expect(screen.getByText(/Hop 1/)).toBeInTheDocument();
    fireEvent.click(screen.getByText(/Hop 1/));
    const hop = screen.getByText(/Hop 1/).closest('details')!;
    expect(within(hop).getByText('Google Safe Browsing')).toBeInTheDocument();
    expect(within(hop).getByText('THREAT_DETECTED')).toBeInTheDocument();
    expect(within(hop).getByText('UNAVAILABLE')).toBeInTheDocument();
    expect(screen.getByText('Known malicious destination detected (+45)')).toBeInTheDocument();
  });
});
