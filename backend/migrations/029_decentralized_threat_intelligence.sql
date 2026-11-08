-- Phase 6.1: report revisions, local commitments, provenance and blockchain metadata.
-- This migration stores no private keys and submits no blockchain transactions.
CREATE TABLE IF NOT EXISTS threat_intelligence_reports (
  id INTEGER PRIMARY KEY,
  report_key VARCHAR(160) NOT NULL UNIQUE,
  owner_user_id VARCHAR(160) NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT DEFAULT '',
  status VARCHAR(30) NOT NULL DEFAULT 'DRAFT',
  visibility VARCHAR(20) NOT NULL DEFAULT 'PRIVATE',
  published_revision_id INTEGER,
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_threat_intelligence_reports_owner ON threat_intelligence_reports(owner_user_id);
CREATE INDEX IF NOT EXISTS ix_threat_intelligence_reports_status ON threat_intelligence_reports(status);
CREATE TABLE IF NOT EXISTS threat_report_revisions (
  id INTEGER PRIMARY KEY,
  report_id INTEGER NOT NULL,
  revision_number INTEGER NOT NULL,
  previous_revision_id INTEGER,
  canonical_report_hash VARCHAR(64) NOT NULL,
  hash_algorithm VARCHAR(30) NOT NULL DEFAULT 'SHA-256',
  canonicalization_version VARCHAR(30) NOT NULL DEFAULT 'v1',
  canonical_payload TEXT NOT NULL,
  revision_metadata_json TEXT DEFAULT '{}',
  author_user_id VARCHAR(160) NOT NULL,
  validation_state VARCHAR(30) NOT NULL DEFAULT 'DRAFT',
  created_at TIMESTAMP,
  published_at TIMESTAMP,
  FOREIGN KEY(report_id) REFERENCES threat_intelligence_reports(id),
  FOREIGN KEY(previous_revision_id) REFERENCES threat_report_revisions(id),
  UNIQUE(report_id, revision_number)
);
CREATE INDEX IF NOT EXISTS ix_threat_report_revisions_report ON threat_report_revisions(report_id);
CREATE INDEX IF NOT EXISTS ix_threat_report_revisions_hash ON threat_report_revisions(canonical_report_hash);
CREATE TABLE IF NOT EXISTS threat_report_commitments (
  id INTEGER PRIMARY KEY,
  revision_id INTEGER NOT NULL UNIQUE,
  commitment VARCHAR(64) NOT NULL,
  hash_algorithm VARCHAR(30) NOT NULL DEFAULT 'SHA-256',
  domain_separator VARCHAR(120) NOT NULL,
  commitment_scope VARCHAR(30) NOT NULL DEFAULT 'LOCAL',
  created_at TIMESTAMP,
  FOREIGN KEY(revision_id) REFERENCES threat_report_revisions(id)
);
CREATE INDEX IF NOT EXISTS ix_threat_report_commitments_commitment ON threat_report_commitments(commitment);
CREATE TABLE IF NOT EXISTS blockchain_networks (
  id INTEGER PRIMARY KEY,
  network_key VARCHAR(120) NOT NULL UNIQUE,
  name VARCHAR(120) NOT NULL,
  chain_id VARCHAR(120),
  rpc_url VARCHAR(2048),
  contract_address VARCHAR(255),
  status VARCHAR(30) NOT NULL DEFAULT 'CONFIGURED',
  created_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS blockchain_transactions (
  id INTEGER PRIMARY KEY,
  network_id INTEGER NOT NULL,
  revision_id INTEGER NOT NULL,
  tx_hash VARCHAR(255),
  status VARCHAR(30) NOT NULL DEFAULT 'NOT_SUBMITTED',
  block_number INTEGER,
  confirmations INTEGER DEFAULT 0,
  submitted_at TIMESTAMP,
  verified_at TIMESTAMP,
  error TEXT,
  metadata_json TEXT DEFAULT '{}',
  FOREIGN KEY(network_id) REFERENCES blockchain_networks(id),
  FOREIGN KEY(revision_id) REFERENCES threat_report_revisions(id),
  UNIQUE(network_id, revision_id)
);
CREATE INDEX IF NOT EXISTS ix_blockchain_transactions_revision ON blockchain_transactions(revision_id);
CREATE TABLE IF NOT EXISTS wallet_identities (
  id INTEGER PRIMARY KEY,
  owner_user_id VARCHAR(160) NOT NULL,
  network_id INTEGER NOT NULL,
  address VARCHAR(255) NOT NULL,
  verification_status VARCHAR(30) NOT NULL DEFAULT 'UNVERIFIED',
  first_verified_at TIMESTAMP,
  created_at TIMESTAMP,
  FOREIGN KEY(network_id) REFERENCES blockchain_networks(id),
  UNIQUE(network_id, address)
);
CREATE TABLE IF NOT EXISTS threat_report_signatures (
  id INTEGER PRIMARY KEY,
  revision_id INTEGER NOT NULL,
  wallet_id INTEGER,
  algorithm VARCHAR(60) NOT NULL,
  signature TEXT NOT NULL,
  verification_status VARCHAR(30) NOT NULL DEFAULT 'UNVERIFIED',
  verified_at TIMESTAMP,
  evidence_json TEXT DEFAULT '{}',
  created_at TIMESTAMP,
  FOREIGN KEY(revision_id) REFERENCES threat_report_revisions(id),
  FOREIGN KEY(wallet_id) REFERENCES wallet_identities(id)
);
CREATE TABLE IF NOT EXISTS threat_evidence_objects (
  id INTEGER PRIMARY KEY,
  owner_user_id VARCHAR(160) NOT NULL,
  object_hash VARCHAR(64) NOT NULL,
  hash_algorithm VARCHAR(30) NOT NULL DEFAULT 'SHA-256',
  storage_uri VARCHAR(2048),
  content_type VARCHAR(160),
  size_bytes INTEGER,
  metadata_json TEXT DEFAULT '{}',
  created_at TIMESTAMP,
  UNIQUE(owner_user_id, object_hash)
);
CREATE INDEX IF NOT EXISTS ix_threat_evidence_objects_hash ON threat_evidence_objects(object_hash);
CREATE TABLE IF NOT EXISTS threat_evidence_references (
  id INTEGER PRIMARY KEY,
  revision_id INTEGER NOT NULL,
  evidence_object_id INTEGER NOT NULL,
  reference_type VARCHAR(80) NOT NULL DEFAULT 'SUPPORTING',
  description TEXT DEFAULT '',
  created_at TIMESTAMP,
  FOREIGN KEY(revision_id) REFERENCES threat_report_revisions(id),
  FOREIGN KEY(evidence_object_id) REFERENCES threat_evidence_objects(id),
  UNIQUE(revision_id, evidence_object_id, reference_type)
);
CREATE TABLE IF NOT EXISTS threat_provenance_events (
  id INTEGER PRIMARY KEY,
  report_id INTEGER NOT NULL,
  revision_id INTEGER,
  actor_user_id VARCHAR(160) NOT NULL,
  event_type VARCHAR(80) NOT NULL,
  details_json TEXT DEFAULT '{}',
  created_at TIMESTAMP,
  FOREIGN KEY(report_id) REFERENCES threat_intelligence_reports(id),
  FOREIGN KEY(revision_id) REFERENCES threat_report_revisions(id)
);
CREATE INDEX IF NOT EXISTS ix_threat_provenance_events_report ON threat_provenance_events(report_id);
CREATE TABLE IF NOT EXISTS threat_validation_records (
  id INTEGER PRIMARY KEY,
  report_id INTEGER NOT NULL,
  revision_id INTEGER NOT NULL,
  validator_user_id VARCHAR(160) NOT NULL,
  validation_state VARCHAR(30) NOT NULL,
  notes TEXT DEFAULT '',
  created_at TIMESTAMP,
  FOREIGN KEY(report_id) REFERENCES threat_intelligence_reports(id),
  FOREIGN KEY(revision_id) REFERENCES threat_report_revisions(id)
);
CREATE TABLE IF NOT EXISTS threat_dispute_records (
  id INTEGER PRIMARY KEY,
  report_id INTEGER NOT NULL,
  revision_id INTEGER,
  opened_by VARCHAR(160) NOT NULL,
  status VARCHAR(30) NOT NULL DEFAULT 'OPEN',
  reason TEXT NOT NULL,
  resolution TEXT,
  created_at TIMESTAMP,
  resolved_at TIMESTAMP,
  FOREIGN KEY(report_id) REFERENCES threat_intelligence_reports(id),
  FOREIGN KEY(revision_id) REFERENCES threat_report_revisions(id)
);
CREATE TABLE IF NOT EXISTS threat_append_only_ledger_events (
  id INTEGER PRIMARY KEY,
  event_type VARCHAR(80) NOT NULL,
  report_id INTEGER,
  revision_id INTEGER,
  actor_user_id VARCHAR(160) NOT NULL,
  payload_hash VARCHAR(64) NOT NULL,
  previous_event_hash VARCHAR(64),
  event_hash VARCHAR(64) NOT NULL UNIQUE,
  payload_json TEXT NOT NULL,
  occurred_at TIMESTAMP,
  FOREIGN KEY(report_id) REFERENCES threat_intelligence_reports(id),
  FOREIGN KEY(revision_id) REFERENCES threat_report_revisions(id)
);
CREATE INDEX IF NOT EXISTS ix_threat_ledger_events_report ON threat_append_only_ledger_events(report_id);
CREATE TABLE IF NOT EXISTS threat_integrity_verifications (
  id INTEGER PRIMARY KEY,
  report_id INTEGER NOT NULL,
  revision_id INTEGER NOT NULL,
  commitment VARCHAR(64) NOT NULL,
  verification_source VARCHAR(120) NOT NULL,
  status VARCHAR(30) NOT NULL,
  details_json TEXT DEFAULT '{}',
  verified_at TIMESTAMP,
  FOREIGN KEY(report_id) REFERENCES threat_intelligence_reports(id),
  FOREIGN KEY(revision_id) REFERENCES threat_report_revisions(id)
);
CREATE INDEX IF NOT EXISTS ix_threat_integrity_verifications_revision ON threat_integrity_verifications(revision_id);
