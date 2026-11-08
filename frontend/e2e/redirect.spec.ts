import { test, expect } from '@playwright/test';

test('redirect timeline shows hop-specific provider states', async ({ page }) => {
  const fixture = {
    id: 701, domain: 'start.example', normalized_url: 'https://start.example/',
    phishing: { evidence: [] }, certificate: { status: 'valid', ct_records: [] }, threat_intelligence: { findings: [], providers: [] }, precautions: [],
    domain_intelligence: { domain: { brand_matches: [] }, rdap: { status: 'unavailable' }, infrastructure: { providers: [] } },
    network: { http: { status: 200, final_url: 'https://suspicious.test/', redirects: [{ sequence: 1, source_url: 'https://start.example/', destination_url: 'https://suspicious.test/', source_domain: 'start.example', destination_domain: 'suspicious.test', status_code: 302, https: true, https_downgrade: false, destination_ips: ['198.51.100.10'] }] }, dns: { records: {} }, redirect_analysis: { risk: { score: 45, level: 'High', confidence: 'medium', complete: true, evidence: [{ message: 'Known malicious destination detected', points: 45 }] }, comparison: { destination_count: 1, final_domain: 'suspicious.test' }, destinations: { 'suspicious.test': { verdict: 'malicious', provider_results: [{ provider: 'Google Safe Browsing', state: 'THREAT_DETECTED', verdict: 'malicious', evidence_available: true }, { provider: 'VirusTotal', state: 'NOT_CONFIGURED', verdict: 'unknown', evidence_available: false }] } } } },
    risk: { score: 45, level: 'High', confidence: 'medium' }
  };
  await page.route('**/api/scans**', async route => {
    if (route.request().method() === 'GET') await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
    else await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fixture) });
  });
  await page.goto('/');
  await page.getByPlaceholder('https://example.com').fill('https://start.example');
  await page.getByRole('button', { name: 'Run trust scan' }).click();
  await expect(page.getByText('Redirect intelligence')).toBeVisible();
  await page.getByText(/Hop 1/).click();
  await expect(page.locator('details').getByText('Google Safe Browsing')).toBeVisible();
  await expect(page.getByText('THREAT_DETECTED')).toBeVisible();
  await expect(page.locator('details').getByText('NOT_CONFIGURED')).toBeVisible();
  expect((await page.locator('body').textContent()) || '').not.toContain('console.error');
});
