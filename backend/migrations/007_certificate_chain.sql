CREATE TABLE IF NOT EXISTS certificate_records (id INTEGER PRIMARY KEY, scan_id INTEGER, fingerprint_sha256 VARCHAR(64) NOT NULL, role VARCHAR(30) NOT NULL, subject TEXT, issuer TEXT, serial_number VARCHAR(255), not_before TIMESTAMP, not_after TIMESTAMP, der BLOB, parsed_json TEXT DEFAULT '{}', created_at TIMESTAMP);
CREATE INDEX IF NOT EXISTS ix_certificate_records_scan_id ON certificate_records(scan_id);
CREATE INDEX IF NOT EXISTS ix_certificate_records_fingerprint ON certificate_records(fingerprint_sha256);
CREATE TABLE IF NOT EXISTS certificate_chain_links (id INTEGER PRIMARY KEY, scan_id INTEGER, child_fingerprint VARCHAR(64) NOT NULL, issuer_fingerprint VARCHAR(64), relation VARCHAR(40) NOT NULL, position INTEGER, evidence_json TEXT DEFAULT '{}', created_at TIMESTAMP);
CREATE INDEX IF NOT EXISTS ix_certificate_chain_links_scan_id ON certificate_chain_links(scan_id);
CREATE TABLE IF NOT EXISTS certificate_validation_results (id INTEGER PRIMARY KEY, scan_id INTEGER, status VARCHAR(30) NOT NULL, trust_anchor VARCHAR(64), errors_json TEXT DEFAULT '[]', evidence_json TEXT DEFAULT '{}', checked_at TIMESTAMP);
CREATE INDEX IF NOT EXISTS ix_certificate_validation_results_scan_id ON certificate_validation_results(scan_id);
