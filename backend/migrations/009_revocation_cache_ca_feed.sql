CREATE TABLE IF NOT EXISTS certificate_revocation_cache (id INTEGER PRIMARY KEY, certificate_fingerprint VARCHAR(64) NOT NULL, issuer_fingerprint VARCHAR(64), result_json TEXT NOT NULL, checked_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL, created_at TIMESTAMP);
CREATE UNIQUE INDEX IF NOT EXISTS uq_certificate_revocation_cache_pair ON certificate_revocation_cache(certificate_fingerprint, issuer_fingerprint);
CREATE INDEX IF NOT EXISTS ix_certificate_revocation_cache_fingerprint ON certificate_revocation_cache(certificate_fingerprint);
CREATE TABLE IF NOT EXISTS ca_reputation_records (id INTEGER PRIMARY KEY, certificate_fingerprint VARCHAR(64) NOT NULL, status VARCHAR(40) NOT NULL, source VARCHAR(2048) NOT NULL, effective_date TIMESTAMP, details_json TEXT DEFAULT '{}', checked_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS uq_ca_reputation_source ON ca_reputation_records(certificate_fingerprint, source);
CREATE INDEX IF NOT EXISTS ix_ca_reputation_fingerprint ON ca_reputation_records(certificate_fingerprint);
CREATE TABLE IF NOT EXISTS certificate_revocation_jobs (id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, status VARCHAR(30) NOT NULL, requested_at TIMESTAMP, started_at TIMESTAMP, completed_at TIMESTAMP, error TEXT);
CREATE INDEX IF NOT EXISTS ix_certificate_revocation_jobs_scan_id ON certificate_revocation_jobs(scan_id);
