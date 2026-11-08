ALTER TABLE threat_append_only_ledger_events ADD COLUMN sequence_number INTEGER;
ALTER TABLE threat_append_only_ledger_events ADD COLUMN hash_algorithm VARCHAR(30) DEFAULT 'SHA-256';
ALTER TABLE threat_append_only_ledger_events ADD COLUMN hash_version VARCHAR(30) DEFAULT 'v1';
ALTER TABLE threat_append_only_ledger_events ADD COLUMN evidence_refs_json TEXT DEFAULT '[]';
ALTER TABLE threat_append_only_ledger_events ADD COLUMN dedupe_key VARCHAR(255);
UPDATE threat_append_only_ledger_events
SET sequence_number = (SELECT COUNT(*) FROM threat_append_only_ledger_events prior WHERE prior.id <= threat_append_only_ledger_events.id)
WHERE sequence_number IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_ledger_sequence ON threat_append_only_ledger_events(sequence_number);
CREATE INDEX IF NOT EXISTS ix_threat_ledger_hash_version ON threat_append_only_ledger_events(hash_version);
CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_ledger_dedupe_key ON threat_append_only_ledger_events(dedupe_key);
