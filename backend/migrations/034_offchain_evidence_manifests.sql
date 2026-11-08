-- Phase 6.5: private off-chain evidence metadata, immutable manifests and provenance links.
ALTER TABLE threat_evidence_objects ADD COLUMN report_id INTEGER;
ALTER TABLE threat_evidence_objects ADD COLUMN revision_id INTEGER;
ALTER TABLE threat_evidence_objects ADD COLUMN access_classification VARCHAR(40) NOT NULL DEFAULT 'PRIVATE';
ALTER TABLE threat_evidence_objects ADD COLUMN encryption_status VARCHAR(40) NOT NULL DEFAULT 'NOT_ENCRYPTED';
ALTER TABLE threat_evidence_objects ADD COLUMN retention_expires_at TIMESTAMP;
ALTER TABLE threat_evidence_objects ADD COLUMN status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE';
ALTER TABLE threat_provenance_events ADD COLUMN source_type VARCHAR(80);
ALTER TABLE threat_provenance_events ADD COLUMN source_id VARCHAR(160);
ALTER TABLE threat_provenance_events ADD COLUMN ledger_event_id INTEGER;
CREATE INDEX IF NOT EXISTS ix_threat_evidence_objects_report ON threat_evidence_objects(report_id);
CREATE INDEX IF NOT EXISTS ix_threat_evidence_objects_revision ON threat_evidence_objects(revision_id);
CREATE INDEX IF NOT EXISTS ix_threat_evidence_objects_status ON threat_evidence_objects(status);
CREATE INDEX IF NOT EXISTS ix_threat_provenance_ledger_event ON threat_provenance_events(ledger_event_id);
CREATE TABLE IF NOT EXISTS threat_evidence_manifests (
  id INTEGER PRIMARY KEY,
  report_id INTEGER NOT NULL,
  revision_id INTEGER NOT NULL,
  version INTEGER NOT NULL,
  canonical_manifest TEXT NOT NULL,
  manifest_hash VARCHAR(64) NOT NULL,
  hash_algorithm VARCHAR(30) NOT NULL DEFAULT 'SHA-256',
  created_by VARCHAR(160) NOT NULL,
  created_at TIMESTAMP,
  FOREIGN KEY(report_id) REFERENCES threat_intelligence_reports(id),
  FOREIGN KEY(revision_id) REFERENCES threat_report_revisions(id),
  UNIQUE(revision_id, version)
);
CREATE INDEX IF NOT EXISTS ix_threat_evidence_manifests_report ON threat_evidence_manifests(report_id);
CREATE INDEX IF NOT EXISTS ix_threat_evidence_manifests_revision ON threat_evidence_manifests(revision_id);
CREATE INDEX IF NOT EXISTS ix_threat_evidence_manifests_hash ON threat_evidence_manifests(manifest_hash);
