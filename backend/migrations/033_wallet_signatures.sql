ALTER TABLE threat_report_signatures ADD COLUMN report_id INTEGER;
ALTER TABLE threat_report_signatures ADD COLUMN signature_type VARCHAR(40) DEFAULT 'EIP712';
ALTER TABLE threat_report_signatures ADD COLUMN purpose VARCHAR(80) DEFAULT 'REPORT_REVISION';
ALTER TABLE threat_report_signatures ADD COLUMN chain_id VARCHAR(80);
ALTER TABLE threat_report_signatures ADD COLUMN nonce VARCHAR(160);
ALTER TABLE threat_report_signatures ADD COLUMN expires_at TIMESTAMP;
CREATE INDEX IF NOT EXISTS ix_threat_report_signatures_report_id ON threat_report_signatures(report_id);
CREATE INDEX IF NOT EXISTS ix_threat_report_signatures_nonce ON threat_report_signatures(nonce);
CREATE TABLE IF NOT EXISTS wallet_challenges (
  id INTEGER PRIMARY KEY,
  challenge_id VARCHAR(160) NOT NULL UNIQUE,
  owner_user_id VARCHAR(160) NOT NULL,
  wallet_address VARCHAR(255) NOT NULL,
  domain VARCHAR(255) NOT NULL,
  action VARCHAR(80) NOT NULL,
  chain_id VARCHAR(80) NOT NULL,
  nonce VARCHAR(160) NOT NULL UNIQUE,
  message TEXT NOT NULL,
  typed_data_json TEXT,
  report_id INTEGER,
  revision_id INTEGER,
  report_hash VARCHAR(64),
  expires_at TIMESTAMP NOT NULL,
  consumed_at TIMESTAMP,
  created_at TIMESTAMP,
  FOREIGN KEY(report_id) REFERENCES threat_intelligence_reports(id),
  FOREIGN KEY(revision_id) REFERENCES threat_report_revisions(id)
);
CREATE INDEX IF NOT EXISTS ix_wallet_challenges_owner ON wallet_challenges(owner_user_id);
CREATE INDEX IF NOT EXISTS ix_wallet_challenges_expiry ON wallet_challenges(expires_at);
