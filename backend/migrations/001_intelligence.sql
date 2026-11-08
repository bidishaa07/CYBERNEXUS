-- Versioned additive migration. Existing scans and reports are preserved.
CREATE TABLE IF NOT EXISTS threat_indicators (id INTEGER PRIMARY KEY, indicator VARCHAR(2048) NOT NULL, indicator_type VARCHAR(40) NOT NULL, category VARCHAR(80), confidence FLOAT DEFAULT 0, verification_status VARCHAR(30) DEFAULT 'unverified', source VARCHAR(100), source_reference VARCHAR(2048), first_seen TIMESTAMP, last_seen TIMESTAMP, expires_at TIMESTAMP);
CREATE INDEX IF NOT EXISTS ix_threat_indicators_indicator ON threat_indicators(indicator);
CREATE TABLE IF NOT EXISTS provider_verdicts (id INTEGER PRIMARY KEY, scan_id INTEGER, provider VARCHAR(100) NOT NULL, status VARCHAR(30) NOT NULL, verdict VARCHAR(40), evidence_json TEXT DEFAULT '{}', checked_at TIMESTAMP);
CREATE INDEX IF NOT EXISTS ix_provider_verdicts_scan_id ON provider_verdicts(scan_id);
CREATE TABLE IF NOT EXISTS domain_intelligence (id INTEGER PRIMARY KEY, scan_id INTEGER, domain VARCHAR(255), rdap_json TEXT DEFAULT '{}', infrastructure_json TEXT DEFAULT '{}', identity_json TEXT DEFAULT '{}', created_at TIMESTAMP);
CREATE INDEX IF NOT EXISTS ix_domain_intelligence_scan_id ON domain_intelligence(scan_id);
