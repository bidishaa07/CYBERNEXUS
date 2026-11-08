CREATE TABLE IF NOT EXISTS certificate_revocation_results (id INTEGER PRIMARY KEY, scan_id INTEGER, certificate_fingerprint VARCHAR(64) NOT NULL, role VARCHAR(30) NOT NULL, status VARCHAR(30) NOT NULL, ocsp_status VARCHAR(30), crl_status VARCHAR(30), distrust_status VARCHAR(40), ca_reputation VARCHAR(50), evidence_json TEXT DEFAULT '{}', checked_at TIMESTAMP);
CREATE INDEX IF NOT EXISTS ix_certificate_revocation_scan_id ON certificate_revocation_results(scan_id);
CREATE INDEX IF NOT EXISTS ix_certificate_revocation_fingerprint ON certificate_revocation_results(certificate_fingerprint);
