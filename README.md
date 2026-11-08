# Digital Trust Intelligence

Digital Trust Intelligence is a Vite/React and FastAPI application for passive, explainable website and message risk analysis. It combines URL heuristics, domain intelligence, DNS/HTTP/TLS checks, certificate transparency, external reputation providers, community intelligence, ML-assisted message analysis, and configurable LLM explanations.

## Run locally

The application does not require Docker.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt

# Backend, from the repository root
$env:PYTHONPATH=(Get-Location).Path
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8001

# Frontend, in another terminal
cd frontend
npm install
npm run dev -- --host 0.0.0.0
```

Open `http://localhost:5173`. The API is available at `http://127.0.0.1:8001`; API documentation is at `/docs`.

The default database is SQLite. Set `DATABASE_URL` to a PostgreSQL SQLAlchemy URL for production. Existing schema changes are applied by the migration runner in `backend/migrations/`.

## Configuration

Copy `.env.example` to `.env`. Never commit `.env`; secrets are backend-only and are not exposed to Vite.

Important provider variables:

```env
GOOGLE_SAFE_BROWSING_API_KEY=
GOOGLE_CLOUD_PROJECT_ID=
VIRUSTOTAL_API_KEY=
OTX_API_KEY=
OPSWAT_API_KEY=
URLHAUS_API_URL=https://urlhaus-api.abuse.ch/v1/url/
URLHAUS_AUTH_KEY=
IPINFO_TOKEN=
IPINFO_BASE_URL=https://api.ipinfo.io/lite
IP_INTELLIGENCE_PROVIDER=freeipapi
FREEIPAPI_BASE_URL=https://freeipapi.com/api/json/
LLM_API_KEY=
LLM_MODEL=kimi-k3
LLM_BASE_URL=https://api.moonshot.ai/v1
```

Provider status endpoints:

- `GET http://127.0.0.1:8001/api/providers/google-safe-browsing/status`
- `POST http://127.0.0.1:8001/api/providers/google-safe-browsing/verify`
- `GET http://127.0.0.1:8001/api/providers/virustotal/status`
- `GET http://127.0.0.1:8001/api/providers/external/status`
- `GET http://127.0.0.1:8001/api/providers/urlhaus/status`
- `GET http://127.0.0.1:8001/api/llm/status`
- `POST http://127.0.0.1:8001/api/llm/verify`

An absent or failed provider is represented as unavailable/unknown. It is never converted into a clean verdict. URL submissions to VirusTotal require explicit confirmation and are not performed during ordinary scans.

## Implemented analysis

- URL normalization with private, loopback, link-local, reserved, and metadata destination protection.
- Explainable phishing heuristics and rule-based risk scoring.
- Damerau/Levenshtein typosquatting detection, lookalike substitutions, IDN/Punycode indicators, brand subdomains, and TLD variations.
- Safe RDAP discovery with HTTPS-only validated redirects, IANA bootstrap data, timeouts, and structured unavailable states.
- DNS records, TLS certificate checks, redirects, HTTP security headers, cookies, and passive website identity checks.
- Redirect intelligence with validated hop collection, loop/depth/downgrade handling, destination comparison, explainable redirect risk scoring, persistent redirect hops, and a frontend timeline/details panel.
- IPinfo Lite lookup with Bearer authentication and FreeIPAPI fallback. Unsupported plan fields remain unavailable.
- Google Safe Browsing v4 adapter with retries, cache, threat categories, and explicit connection diagnostics. It requires a valid key and enabled Google API.
- VirusTotal API v3 lookup-first adapter with URL identifiers, report parsing, domain/IP lookup helpers, explicit submission, analysis polling, caching, and quota handling.
- AlienVault OTX and OPSWAT MetaDefender domain lookups connected to scan findings and risk scoring.
- URLhaus authenticated lookup connected to scan findings; PhishTank remains a separate optional provider.
- Community reports, persistent provider verdicts, threat indicators, scan history, and report commitments.
- Dataset-backed message classifier and optional Kimi explanation service with rate-limit reporting.
- TLS Phase 1 certificate-chain intelligence: presented-chain collection with pyOpenSSL, AIA issuer discovery, bounded alternative-path construction, cryptographic path validation, trust-anchor checks, and SAN validation.
- TLS Phase 2 revocation intelligence: cryptographic OCSP and CRL checks, conservative conflict aggregation, persistent revocation caching, background refresh jobs, system trust-store checks, and configurable CA distrust/advisory-feed support.
- TLS Phase 3 configuration grading: actual TLS 1.0/1.1/1.2/1.3 probes, negotiated cipher analysis, key-exchange/AEAD/forward-secrecy grading, certificate-algorithm grading, and explicit DNS/IP SAN mismatch reporting.
- TLS Phase 4 Certificate Transparency intelligence: normalized crt.sh history, issuer/SAN/duplicate/wildcard observations, conservative anomaly evidence, persistent CT entries/anomalies, and a CT timeline panel.
- TLS Phase 5 independent certificate risk: configurable evidence weights, deduplicated chain/revocation/TLS/SAN/CT findings, persistent certificate assessments, separate certificate score card, and bounded influence on overall reputation.

## Dataset model

Datasets are stored under `dataset/`. Train the reproducible classifier with:

```powershell
python engines/ml_engine/train.py --dataset dataset\Merged_Dataset.csv --max-rows 100000
```

The model reports precision, recall, F1, accuracy, label distribution, and a confusion matrix. Model output is a risk estimate, not proof of fraud.

## Verification

Run backend tests:

```powershell
$env:PYTHONPATH=(Get-Location).Path
python -m pytest tests -q
```

Build the frontend:

```powershell
cd frontend
npm run build
```

The current verified baseline is recorded in [`progress.md`](progress.md). The latest local verification is `96 passed, 1 skipped` for the backend suite, with frontend typechecking, the component test, and the production build also passing. The Phase 5 live certificate check was verified on scan `106` with certificate risk `25/100`, TLS grade `A`, and a bounded `+6` overall-risk influence.

Redirect endpoints:

- `GET http://127.0.0.1:8001/api/scans/{scan_id}/redirects`
- `GET http://127.0.0.1:8001/api/scans/{scan_id}/redirects/{sequence}`

Redirect scoring is intentionally separate from the overall score. Cross-domain movement alone is a warning signal, not proof of maliciousness; confirmed destination findings, brand impersonation, HTTPS downgrade, and excessive depth contribute explainable points. Unavailable destination intelligence is reported as missing and does not create a clean verdict.

## TLS certificate intelligence

Certificate endpoints include:

- `GET /api/scans/{scan_id}/certificate`
- `GET /api/scans/{scan_id}/certificate/chain`
- `GET /api/scans/{scan_id}/certificate/validation`
- `GET /api/scans/{scan_id}/certificate/revocation`
- `POST /api/scans/{scan_id}/certificate/revocation/refresh`
- `GET /api/certificate/revocation/jobs/{job_id}`
- `GET /api/scans/{scan_id}/certificate/transparency`
- `GET /api/scans/{scan_id}/certificate/risk`

Certificate migrations include `007_certificate_chain.sql`, `008_certificate_revocation.sql`, `009_revocation_cache_ca_feed.sql`, `010_certificate_transparency.sql`, and `011_certificate_risk.sql`.

The dashboard displays chain validation, alternative paths, OCSP/CRL status, CA trust, TLS grades, SAN evidence, CT history/anomalies, and certificate risk. Unknown or unavailable certificate evidence is never rendered as clean.

Relevant configuration:

```env
CERTIFICATE_REVOCATION_TIMEOUT_SECONDS=6
CERTIFICATE_REVOCATION_CACHE_TTL_SECONDS=900
CERTIFICATE_DISTRUST_FINGERPRINTS=
CA_REPUTATION_FEED_URL=
CA_REPUTATION_FEED_TTL_SECONDS=21600
TLS_GRADING_TIMEOUT_SECONDS=5
TLS_MINIMUM_VERSION=TLSv1.2
TLS_MINIMUM_CIPHER_BITS=128
CERTIFICATE_RISK_WEIGHTS_JSON={}
```

## Security and provider limitations

Scanning is passive. Requests have timeouts and response limits, redirects are revalidated, and downloaded scripts are never executed. Public VirusTotal use and Google Safe Browsing use must follow the providers' terms; commercial deployments may require Google Web Risk or a suitable commercial VirusTotal agreement. Historical WHOIS data, ownership, brand truth, and a clean provider result are not fabricated or inferred beyond available evidence.

## Phone and email contact intelligence

Message analysis now enriches extracted phone numbers and email addresses with evidence-backed contact intelligence:

- Phone numbers are parsed with `libphonenumber` and return country, formats, carrier/type metadata and validity separately from abuse reputation.
- Phone abuse reputation is an optional backend-only adapter configured with `PHONE_REPUTATION_API_URL`, `PHONE_REPUTATION_API_KEY`, and related timeout/cache settings. Missing or failed provider lookups remain `UNKNOWN`.
- IPQualityScore Phone Validation is supported as an explicit adapter through `IPQUALITYSCORE_API_KEY` and `IPQUALITYSCORE_BASE_URL`; its fraud score, recent-abuse, VOIP, carrier and line-type fields are preserved only when returned by the provider.
- Email domains are classified from the persisted provider registry. Legitimate free providers are neutral/low-risk, disposable providers are identified as disposable rather than malicious, and elevated risk requires actual threat-intelligence evidence.
- Email indicators receive MX, SPF and DMARC presence checks and are correlated with the configured URL/domain threat providers without sending full message content.
- Contact assessments are persisted in `contact_risk_assessments`; the provider registry is initialized by migration `015_contact_intelligence.sql`.

Configuration:

```env
PHONE_REPUTATION_API_URL=
PHONE_REPUTATION_API_KEY=
PHONE_REPUTATION_AUTH_HEADER=Authorization
PHONE_REPUTATION_TIMEOUT_SECONDS=6
PHONE_REPUTATION_CACHE_TTL_SECONDS=900
DISPOSABLE_EMAIL_DOMAINS=
```

The current test baseline is `125 passed, 1 skipped` for the backend suite. Frontend TypeScript checking and the Vite production build also pass. A live phone-abuse provider result is not claimed until a compatible provider endpoint and credential are configured.

## Production phone, email authentication and infrastructure

The production upgrade adds:

- `POST /api/intelligence/phone/analyze` for normalized phone metadata and configurable provider reputation.
- `POST /api/intelligence/email/authentication` for independent DNS SPF/DMARC analysis and selector-aware DKIM verification. DNS key presence is reported as a warning, never as a DKIM signature pass.
- `GET /api/intelligence/providers/health` for database, Redis, worker and phone-provider configuration status.
- `GET /api/intelligence/tasks/{task_id}` for persisted background-task status.
- Migration `016_production_intelligence.sql` for verification history and background task records.
- Optional Redis cache through `REDIS_URL`; production mode fails closed if Redis is absent instead of silently using local memory.
- Optional Celery worker/beat tasks through `CELERY_BROKER_URL` and `CELERY_RESULT_BACKEND`.
- PostgreSQL SQLAlchemy pooling and pre-ping when `DATABASE_URL` uses a PostgreSQL driver.
- `docker-compose.yml` with API, Vite/Nginx frontend, PostgreSQL, Redis, Celery worker and beat services. PostgreSQL and Redis are internal-only by default.

Production configuration requires a real phone intelligence account and compatible endpoint. SPF/DMARC DNS inspection works without provider credentials. Independent DKIM cryptographic verification additionally requires original RFC 5322 bytes and a valid selector/public key; a selector record alone is not a message verification result.

## Persistent message analysis history

Phase 4 adds migration `017_message_history.sql` and persists text and `.eml` analyses with an owner, input type, sender/subject metadata, risk classification, ML prediction/confidence, LLM status, model version, duplicate linkage and audit events. Original text bytes are retained in the protected `message_contents` table for authorized re-analysis; uploaded email bytes were already retained in `email_raw_messages`.

History API endpoints:

- `GET /api/message-analysis/history` — paginated search/filter history (`page`, `page_size`, `search`, `risk`, `input_type`, `provider`).
- `GET /api/message-analysis/text/{analysis_id}` — ownership-protected text report.
- `POST /api/message-analysis/text/{analysis_id}/reanalyze` — creates a new record and preserves the prior result.
- `DELETE /api/message-analysis/text/{analysis_id}` — ownership/admin-protected deletion with child-record cleanup.
- `GET /api/message-analysis/email/{analysis_id}` and `DELETE /api/message-analysis/email/{analysis_id}` — protected email retrieval/deletion.

Use verified OIDC sessions for production ownership. `X-User-ID` remains only a development compatibility path when authentication is not required; it is ignored when `ENVIRONMENT=production` or `AUTH_REQUIRED=true`.

## OIDC authentication and identity

The Phase 4 ownership limitation is now addressed with an OIDC-compatible JWT/JWKS adapter. Configure `OIDC_ISSUER_URL`, `OIDC_JWKS_URL` (or issuer discovery), and `OIDC_AUDIENCE`; the backend validates signing keys, issuer, audience, expiration and subject claims, synchronizes users into `app_users`, and derives message ownership from the verified subject. In production, `AUTH_REQUIRED=true` or `ENVIRONMENT=production` disables legacy header ownership.

Authentication endpoints:

- `GET /api/auth/config` — non-secret OIDC configuration for the frontend.
- `GET /api/auth/me` — verified session identity.
- `POST /api/auth/session` — validates a bearer token and sets an HttpOnly session cookie.
- `POST /api/auth/logout` — clears the session cookie.
- `POST /api/admin/identity-links` — explicitly links a legacy owner ID to an already-authenticated external subject and records an audit event.

The frontend includes an OIDC sign-in/logout status panel and sends cookies using `credentials: include`. Registration and password handling remain with the configured identity provider; the application never stores provider passwords or refresh tokens. The local environment now contains the supplied Keycloak realm/client configuration; live connectivity remains dependent on Keycloak running at the configured issuer.

## Phase 5 message reports and administrator review

Phase 5 adds persisted human review without overwriting automated analysis:

- Migration `019_message_reviews.sql` adds review cases, audit events and reviewer feedback. New text and `.eml` analyses automatically open as `PENDING_REVIEW`.
- `GET /api/message-analysis/reports/{text|email}/{id}?format=json|csv|pdf` exports the stored analysis result, evidence, model/LLM metadata, timestamps and limitations. Exports do not recalculate risk and never include credentials.
- Administrator endpoints under `/api/admin/message-reviews` support listing, opening, viewing the full report, assignment, status transitions, audit history and feedback. Feedback is stored as `PENDING_VALIDATION` and is not automatically added to training data.
- The Vite dashboard includes an administrator review panel with review status controls and JSON/PDF report links. It remains unavailable to non-administrators.
- The dashboard also includes a user-facing Message Analysis Reports panel that selects persisted history records and offers JSON, CSV and PDF downloads.
- PDF exports use ReportLab (`reportlab==4.2.5`). The existing SQL migration runner applies migration 019 at startup; no existing records are recreated or deleted.

Phase 5 verification: backend suite `130 passed, 1 skipped`; Phase 5 report/review tests `2 passed`; frontend typecheck and production build pass; frontend component suite passes after excluding Playwright files from the Vitest script. Browser E2E remains a separate `npm run test:e2e` command and requires the running app/browser fixture.

## Phase 6 ML model and dataset lifecycle

Phase 6 preserves the existing TF-IDF + Logistic Regression classifier while adding reproducibility and controlled deployment:

- Migration 020_ml_registry.sql adds dataset versions, model versions, training runs and deployment history.
- backend/app/services/ml_registry.py validates dataset labels/content, detects duplicates and inconsistent labels, records class distributions/checksums, and verifies model artifact checksums.
- Training now writes candidate artifacts under models/candidates/ by default and records model version, dataset version, preprocessing version, feature configuration and expanded metrics including macro/weighted F1, ROC-AUC, PR-AUC and Brier score. It never updates the production pointer automatically.
- Admin APIs under /api/ml/ support registry inspection, dataset registration/approval, model registration/approval, controlled deployment and rollback. Only approved artifacts with unchanged checksums may be deployed.
- The active model loader uses a validated models/production_pointer.json when present and otherwise preserves the existing models/phishing_message_model.joblib path. Historical message records retain their model version metadata.
- The dashboard includes an ML Model Management panel showing the active model, dataset versions, metrics, approval status, deployments and rollback controls.
- A separate ML Lifecycle Status panel shows live deployed model/dataset provenance, evaluation metrics, API/database health, cache state and the database-backed retraining runtime.

## Phase 7 automated retraining and final integration

- Retraining is available through admin-only POST /api/ml/retraining and persists MLTrainingRun plus BackgroundTaskRun status.
- Jobs require a VALID and APPROVED dataset, verify its checksum before training, use deterministic stratified train/validation/test splits, and keep the test split untouched.
- Approved human feedback can be explicitly approved through the administrator workflow and is added only to the training partition; pending/unapproved feedback is never used.
- Candidate artifacts are evaluated against the active production artifact on the same test split, including false-positive/false-negative rates, ROC-AUC, PR-AUC and calibration Brier score. Failed thresholds create REJECTED/EVALUATION_FAILED results.
- Candidates are never auto-approved or auto-deployed. Existing model approval, checksum verification, deployment and rollback endpoints remain the only promotion path.
- Optional Celery Beat scheduling is configured with ML_RETRAINING_SCHEDULE and ML_RETRAINING_DATASET_ID. Without a broker, development uses the existing FastAPI background-task path.
- When Celery/Redis is not configured, the API uses a persisted single-process worker fallback that resumes pending/running retraining records on API startup. Redis/Celery remains recommended for multi-worker production capacity.
- The ML management panel shows training runs and permits an administrator to start retraining from approved datasets.
- Verification: controlled retraining and registry tests pass; full backend suite is 133 passed, 1 skipped; frontend typecheck, component tests and production build pass. Browser E2E remains a separate command requiring a running browser fixture.
- Live local verification: cleaned approved dataset merged-managed-dataset-v1 (98,778 records) produced and deployed model retrain-3-20261108070111. The active API reports both model and dataset versions, with health status OK. Browser Chromium E2E passed 1 test.

## Structure

`frontend/` Vite/React dashboard · `backend/` FastAPI API, engines, persistence, and migrations · `engines/` model/detection modules · `dataset/` local training data · `tests/` automated backend tests · `docs/` architecture notes · `infrastructure/` deployment notes.
