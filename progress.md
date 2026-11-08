# Digital Trust Intelligence Progress

Last verified: 2026-11-08

## Latest audit evidence

- Backend tests: `96 passed, 1 skipped` using the project virtual environment.
- Frontend build: Vite production build succeeded.
- Frontend runtime: Vite served `http://localhost:5173/` with HTTP 200.
- Live API health: `/api/health` returned `ok`.
- Live OTX status: connected, HTTP 200.
- Live OPSWAT MetaDefender Cloud status: connected, HTTP 200.
- Live URLhaus status: connected, HTTP 200.
- Google Safe Browsing: `NOT_CONFIGURED`; no usable backend key is loaded.
- VirusTotal: `NOT_CONFIGURED`; no usable backend key is loaded.
- Kimi: `CONFIGURED_NOT_TESTED`; live verification remains blocked by HTTP 429.
- TLS Phase 5 live certificate risk verification: certificate score and bounded overall-risk influence verified on scan `106`.
- `.gitignore` exists, but this workspace root is not a Git checkout, so Git status/ignore behavior was not independently verifiable.

This checklist records repository implementation and observed runtime state. A checked item means it was implemented and verified locally or through a live provider check. An unchecked item is incomplete, credential-dependent, or not yet verified.

## Runtime baseline

- [x] Backend starts on `127.0.0.1:8001`.
- [x] Vite frontend starts on `localhost:5173`.
- [x] Backend health endpoint returns `ok`.
- [x] Backend test suite passes: `96 passed, 1 skipped`.
- [x] Frontend production build succeeds with Vite.
- [x] `.env` is ignored by Git.
- [x] Credentials are kept out of frontend source and provider result payloads.

## Core scanning

- [x] URL normalization and HTTP(S) validation.
- [x] Private, loopback, link-local, reserved, and metadata destination blocking.
- [x] Passive HTTP, redirect, DNS, cookie, and security-header inspection.
- [x] TLS certificate and hostname inspection.
- [x] Certificate Transparency lookup path.
- [x] Persistent scan history and JSON result storage.
- [x] Explainable risk score and risk classification.
- [x] Redirect hop collection with status, source/destination domains, HTTPS state, IPs, timestamps, loops, depth limits, and blocked destinations.
- [x] Dedicated redirect risk score with explainable contributions and confidence.
- [x] Original-versus-final registered-domain comparison.
- [x] Redirect hops persisted in `redirect_hops` with migration `002_redirect_intelligence.sql`.
- [x] Redirect chain and individual-hop API endpoints.
- [x] Frontend redirect summary, expandable timeline, destination reputation, and evidence panel.
- [x] Provider-by-provider results, status, evidence, timestamps, cache state, and retry action displayed inside each redirect hop.
- [x] Unknown, unavailable, unconfigured, threat, no-match, timeout, rate-limit, quota, credential, and provider-error states remain distinct.
- [x] Redirect fetching pins a validated public IP while preserving hostname TLS SNI and Host header.
- [x] Redirect DNS protections cover IPv4/IPv6, mapped IPv6, private, loopback, link-local, reserved, multicast, unspecified, metadata, and mixed answers.
- [ ] Long-running scans moved to a production queue/worker; the current MVP scan route is synchronous.

## Domain and identity intelligence

- [x] RDAP lookup with IANA bootstrap discovery.
- [x] HTTPS-only RDAP redirect validation.
- [x] RDAP timeout, malformed JSON, rate-limit, redirect-loop, and unavailable states.
- [x] Registration events, registrar, nameservers, domain status, and final RDAP server display.
- [ ] Historical WHOIS provider integration.
- [x] Public IPv4 and IPv6 DNS resolution.
- [x] IPinfo Lite Bearer-token lookup.
- [x] FreeIPAPI fallback when no IPinfo token is available.
- [x] ASN number, ASN organization, country, region, and city parsing.
- [ ] Full hosting/reputation fields when the configured IPinfo plan does not provide them.
- [x] Website title, content hash, login/payment indicators, favicon URL, and script-source collection.
- [ ] Full favicon/logo image comparison and visual brand similarity.

## Typosquatting and brand impersonation

- [x] Levenshtein distance.
- [x] Damerau-Levenshtein distance.
- [x] Character insertion, deletion, substitution, and transposition detection.
- [x] Digit/lookalike substitutions such as `amaz0n.com`.
- [x] IDN/Punycode indicator detection.
- [x] Brand-like subdomain detection.
- [x] TLD variation detection.
- [x] Visible frontend brand-match panel with official domain, similarity, edit distance, technique, and risk.
- [ ] Public Suffix List integration for every possible delegated suffix.
- [ ] Large verified brand ownership dataset and legal/trademark verification.

## Threat intelligence providers

### Google Safe Browsing v4

- [x] v4 endpoint and request schema.
- [x] Supported threat categories and match parsing.
- [x] Clean/no-match versus unknown/provider failure distinction.
- [x] Retry, timeout, rate-limit, quota, malformed-response, and credential handling.
- [x] Secret-safe configuration and verification endpoints.
- [x] Frontend provider explanation/status display.
- [ ] Valid API key currently configured.
- [ ] Live authenticated connection currently verified.
- [ ] Google Cloud API enablement independently verified.

### VirusTotal API v3

- [x] Existing URL report lookup.
- [x] Documented URL identifier generation.
- [x] URL/domain/IP lookup helpers.
- [x] Explicit URL submission requiring confirmation.
- [x] Analysis ID polling.
- [x] Engine statistics, categories, reputation, timestamps, and individual results.
- [x] Cache, timeout, retry, quota, rate-limit, pending, and unavailable states.
- [x] Dedicated frontend evidence panel.
- [ ] Valid API key currently configured.
- [ ] Live authenticated connection currently verified.

### AlienVault OTX

- [x] Backend credential loading.
- [x] Live connectivity check returned HTTP 200.
- [x] Domain pulse lookup.
- [x] Pulse evidence and timestamps preserved.
- [x] Findings connected to risk scoring.
- [x] Latest-result dashboard display.

### OPSWAT MetaDefender Cloud

- [x] Backend credential loading.
- [x] Live connectivity check returned HTTP 200.
- [x] Domain reputation lookup.
- [x] Detection count and source evidence parsing.
- [x] Findings connected to risk scoring.
- [x] Latest-result dashboard display.

### URLhaus and PhishTank

- [x] URLhaus endpoint configuration.
- [x] URLhaus `Auth-Key` header support.
- [x] Live URLhaus authenticated request returned HTTP 200.
- [x] URLhaus no-result, invalid-auth, rate-limit, and provider-error handling.
- [x] URLhaus findings connected to risk scoring.
- [ ] PhishTank endpoint/key configured and live verified.
- [x] URLhaus is not mislabeled as PhishTank.

## AI and message analysis

- [x] URL, email, and phone indicator extraction.
- [x] Deterministic social-engineering evidence.
- [x] Dataset-backed classifier integration.
- [x] Model evaluation metadata path.
- [x] Kimi model configuration loaded from backend environment.
- [x] Kimi retries and explicit rate-limit/credential/timeout states.
- [ ] Successful Kimi explanation request verified; current live verification returns HTTP 429.
- [ ] Automated frontend tests for message-analysis rendering.

## Persistence and administration

- [x] SQLite persistence for immediate local use.
- [x] Versioned SQL migration file and migration runner.
- [x] Domain intelligence persistence.
- [x] Provider verdict persistence.
- [x] Threat indicator persistence.
- [x] Community report persistence.
- [x] Community moderation endpoint with administrator token.
- [x] Threat correlation endpoint.
- [ ] Full production RBAC/user/session management.
- [ ] PostgreSQL migration tested against production-sized data.

## Frontend

- [x] Dark-first responsive security dashboard.
- [x] URL scanner and loading/error states.
- [x] RDAP panel.
- [x] ASN/hosting/IP intelligence panel.
- [x] Typosquatting/brand impersonation panel.
- [x] Google Safe Browsing explanation/status section.
- [x] VirusTotal evidence panel.
- [x] OTX and MetaDefender external intelligence panel.
- [x] URLhaus panel with connection and latest-result states.
- [x] Unknown/unavailable states do not render as clean.
- [x] Dedicated automated browser/component test suite for redirect intelligence.
- [x] Frontend Vitest component test and Playwright Chromium redirect workflow test.

## Testing evidence

- [x] Domain intelligence tests.
- [x] RDAP redirect/security tests.
- [x] IPinfo/FreeIPAPI tests.
- [x] Google Safe Browsing mocked tests.
- [x] VirusTotal mocked tests.
- [x] OTX/MetaDefender mocked tests.
- [x] Phishing tests.
- [x] Full backend suite: `96 passed, 1 skipped` using the project virtual environment.
- [x] Frontend `npm run build` succeeds.
- [x] Frontend component test: `1 passed`.
- [x] Frontend Playwright test: `1 passed`.
- [x] Frontend TypeScript typecheck passes.
- [x] Redirect security/provider-state tests included in backend suite.
- [ ] Full live verification of every provider; Google Safe Browsing and VirusTotal are not configured in the current environment.

## TLS certificate and web trust phases

### Phase 1 — certificate chains and alternative paths

- [x] Presented leaf and intermediate certificate collection using pinned public-IP TLS connections.
- [x] Certificate metadata extraction: issuer, subject, serial, validity, SAN, key usage, EKU, identifiers, AIA, CRL points, policies, constraints, algorithms, and preserved DER.
- [x] Cryptographic signature/path validation and system trust-anchor checks.
- [x] AIA issuer discovery with HTTPS-only SSRF-safe fetching.
- [x] Bounded alternative-path enumeration for cross-signed/intermediate paths.
- [x] Missing, incomplete, circular, invalid, expired, not-yet-valid, untrusted and hostname-mismatch states.
- [x] Migration `007_certificate_chain.sql`, certificate APIs, chain panel, and controlled fixtures.

### Phase 2 — revocation and CA trust

- [x] Cryptographic OCSP request/response processing with signature, serial, responder and freshness checks.
- [x] CRL retrieval and signature, issuer, freshness and revoked-serial validation.
- [x] Conservative OCSP/CRL aggregation; unavailable/conflicting data remains unknown.
- [x] System trust-store and explicit certificate distrust fingerprint checks.
- [x] Configurable CA advisory feed adapter with source/effective-date/evidence provenance.
- [x] Persistent revocation cache and background refresh jobs.
- [x] Migration `008_certificate_revocation.sql`, `009_revocation_cache_ca_feed.sql`, APIs and frontend panel.
- [ ] Authoritative CA advisory feed configured in the current environment; `CA_REPUTATION_FEED_URL` is currently empty.

### Phase 3 — TLS configuration and SAN validation

- [x] Actual TLS 1.0, 1.1, 1.2 and 1.3 version probes.
- [x] Negotiated cipher, encryption, key exchange, AEAD and forward-secrecy analysis.
- [x] Configurable minimum TLS version, cipher strength and handshake timeout.
- [x] Certificate public-key/signature algorithm grading.
- [x] Exact, wildcard, IDN, IPv4, IPv6, missing and mismatched SAN validation.
- [x] TLS configuration frontend reporting and controlled tests.

### Phase 4 — Certificate Transparency

- [x] crt.sh response normalization with fingerprints, issuers, subjects, SANs, serials, validity and observation timestamps.
- [x] CT history timeline and source attribution.
- [x] Evidence-backed duplicate, wildcard, issuer-change, SAN-addition and multiple-issuer observations.
- [x] Persistent CT entries and anomaly findings through migration `010_certificate_transparency.sql`.
- [x] CT API endpoint, frontend timeline panel and deterministic malformed/unavailable tests.
- [ ] Live CT provider availability is environment-dependent; the last live check returned `UNAVAILABLE` and was not treated as clean.

### Phase 5 — independent certificate risk

- [x] Separate certificate score and category from overall website risk.
- [x] Configurable documented weights through `CERTIFICATE_RISK_WEIGHTS_JSON`.
- [x] Chain, trust, expiry, revocation, CA, key, signature, TLS, SAN and CT evidence inputs.
- [x] Evidence deduplication and confidence-aware findings.
- [x] Unknown/unavailable data excluded from clean and malicious conclusions.
- [x] Bounded maximum 25-point influence on overall risk with explanation.
- [x] Persistent assessments through migration `011_certificate_risk.sql`.
- [x] Certificate risk API and dashboard card.
- [x] Live scan `106`: certificate score `25/100`, TLS grade `A`, overall influence `+6`.

### TLS testing evidence

- [x] Certificate chain fixture tests.
- [x] Cross-signed alternative-path fixture test.
- [x] OCSP/CRL and distrust fixture tests.
- [x] TLS version, cipher and SAN fixture tests.
- [x] CT normalization and anomaly fixture tests.
- [x] Certificate risk fixture tests.
- [x] Full backend suite: `96 passed, 1 skipped`.
- [x] Frontend typecheck, component test and production build pass.
- [ ] Phase 6 certificate report/chain visualization enhancements not started.

### Current TLS implementation boundary

- [x] Phases 1–5 are implemented in the existing scanner, persisted through migrations, exposed through the certificate APIs, and represented in the scan results dashboard.
- [x] The Phase 5 live check was performed against scan `106`: certificate risk `25/100` (`Medium`), TLS grade `A`, and bounded overall-risk influence `+6`.
- [x] Unknown, unavailable, stale, or failed certificate evidence remains explicitly non-clean and is excluded from clean-provider conclusions.
- [ ] Phase 6 certificate report/chain visualization enhancements are not started; the current dashboard uses the existing certificate panels and risk card.
- [ ] `CA_REPUTATION_FEED_URL` is not configured, so external CA advisory intelligence remains `UNKNOWN` unless explicit distrust fingerprints or a feed are supplied.
- [ ] Live CT availability remains provider-dependent; the last live `crt.sh` check returned `UNAVAILABLE` and produced no fabricated CT records.

## Current manual actions

- [ ] Add and verify `GOOGLE_SAFE_BROWSING_API_KEY` and enable the API in Google Cloud.
- [ ] Add and verify `VIRUSTOTAL_API_KEY` under an account permitted for the intended use.
- [ ] Resolve Kimi HTTP 429 quota/rate-limit state.
- [ ] Configure PhishTank only if a genuine endpoint/key is available.
- [ ] Use PostgreSQL, a job queue, rate limiting, secret management, and HTTPS for production deployment.

### Phone abuse and email reputation upgrade

- [x] Added libphonenumber-backed international phone parsing, including E.164, national/international formats, country code, region, carrier and number type.
- [x] Added a configurable phone reputation adapter with backend-only credentials, timeout/error states, bounded retry with jitter, in-memory TTL caching and no-provider UNKNOWN behavior.
- [x] Added an explicit IPQualityScore Phone Validation adapter using its configured API key and preserving returned fraud/abuse/VOIP/carrier fields without fabrication.
- [x] Added transparent phone risk scoring; validity alone never produces a SAFE or malicious verdict.
- [x] Added SQLAlchemy model and migration `015_contact_intelligence.sql` for provider registry and persisted contact risk assessments.
- [x] Seeded a traceable registry for Gmail, Outlook, Hotmail, Yahoo, iCloud, Proton, Zoho and selected disposable providers; disposable status is not treated as confirmed fraud.
- [x] Added configurable `DISPOSABLE_EMAIL_DOMAINS` additions and database-backed provider classification.
- [x] Added email domain MX, SPF and DMARC presence checks plus existing threat-provider correlation for extracted email indicators.
- [x] Added contact evidence to the existing text and `.eml` analysis persistence pipeline and dedicated email-security panel.
- [x] Added tests for Indian/international numbers, invalid numbers, provider timeout, abuse result, legitimate free providers, disposable providers, malicious domain evidence and unknown providers.
- [x] Verification: focused contact/message tests `11 passed`; full backend suite `120 passed, 1 skipped`; frontend typecheck and production build passed.
- [ ] A concrete phone-abuse provider URL/key is not configured in the current environment; live abuse reputation remains UNKNOWN until `PHONE_REPUTATION_API_URL` and its credential are supplied.
- [ ] SPF/DKIM/DMARC checks remain evidence-aware: uploaded messages without trusted SMTP context or independent DKIM evidence remain UNKNOWN.
- [ ] The current architecture uses SQLAlchemy migrations and an in-memory cache; PostgreSQL/Redis/background refresh remain production deployment work.

### Production phone, email authentication and infrastructure upgrade

- [x] Added independent DNS SPF inspection with syntax, multiple-record, lookup-count, permissive-policy and DNS-failure states.
- [x] Added independent DNS DMARC inspection with policy, subdomain policy, alignment, reporting tags and monitoring-only warnings.
- [x] Added selector-aware DKIM DNS inspection; DNS key presence is never reported as a cryptographic signature PASS.
- [x] Reused the preserved-byte DKIM verifier for genuine message evidence through the new authentication service.
- [x] Added `POST /api/intelligence/phone/analyze` and `POST /api/intelligence/email/authentication`.
- [x] Added provider/database/cache/worker health endpoint and persisted verification/task models via migration `016_production_intelligence.sql`.
- [x] Added SQLAlchemy PostgreSQL pooling, pre-ping and connection timeout configuration while preserving SQLite development support.
- [x] Added Redis cache service with TTL, namespace, health status and explicit production fail-closed behavior.
- [x] Added optional Celery task module with retry/backoff configuration for phone and email-authentication refreshes.
- [x] Added Docker Compose deployment definitions for API, frontend, PostgreSQL, Redis, worker and beat.
- [x] Verification: full backend suite `125 passed, 1 skipped`; frontend typecheck and production build passed.
- [ ] A live IPQualityScore or equivalent phone provider is not configured; phone abuse verdicts remain UNKNOWN until a real endpoint/key is supplied.
- [ ] Redis/Celery/PostgreSQL live service integration was not executed in this environment; Compose configuration is present but requires Docker and service credentials.

### Phase 4 - persistent message analysis and history

- [x] Added migration `017_message_history.sql` with metadata, protected text content and audit-event tables.
- [x] Persisted owner, input type, sender/subject, risk, ML prediction/confidence, LLM status, model version, status and duplicate linkage for text and `.eml` analyses.
- [x] Preserved original text content for authorized re-analysis and existing raw `.eml` preservation.
- [x] Added paginated history search/filter endpoint with risk, type and provider filtering.
- [x] Added ownership-protected report retrieval, deletion and re-analysis endpoints; re-analysis creates a new historical record.
- [x] Added Message Analysis History frontend panel with search, pagination, model and provider status.
- [x] Added deterministic API tests for persistence, detail retrieval, re-analysis and ownership isolation.
- [x] Verification: full backend suite `126 passed, 1 skipped`; frontend typecheck and production build passed.
- [ ] Full account/session authentication is not present in the existing application; `X-User-ID` is an ownership boundary pending integration with a real identity provider.

### Phase 4 final - OIDC authentication and identity

- [x] Added OIDC-compatible JWT/JWKS validation with issuer, audience, expiration, subject and signing-key rotation support through PyJWT.
- [x] Added SQLAlchemy `app_users` and `legacy_identity_links` with migration `018_oidc_identity.sql`.
- [x] Added identity synchronization, account-status checks and role claim mapping for admin RBAC.
- [x] Connected create, history, detail, deletion and re-analysis ownership to verified principals in production mode.
- [x] Production mode rejects missing authentication and ignores client-supplied `X-User-ID` ownership.
- [x] Added explicit audited legacy identity-link workflow; unclaimed historical records remain protected.
- [x] Added HttpOnly cookie session creation/logout and frontend authentication status panel.
- [x] Added restricted CORS methods/headers and cookie credentials handling.
- [x] Authentication regression tests: missing auth, verified subject synchronization and User A/User B isolation pass.
- [x] Full backend suite: `128 passed, 1 skipped`; frontend typecheck and production build pass.
- [ ] A real Keycloak/Auth0/Clerk issuer, JWKS URL, audience and client configuration must still be supplied in the deployment environment; tests use controlled identity fixtures and do not claim live provider connectivity.
