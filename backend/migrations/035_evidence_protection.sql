-- Phase 6.5 protection upgrades: encrypted storage, malware scan and IPFS metadata.
ALTER TABLE threat_evidence_objects ADD COLUMN malware_scan_status VARCHAR(30) NOT NULL DEFAULT 'UNKNOWN';
ALTER TABLE threat_evidence_objects ADD COLUMN malware_scan_provider VARCHAR(120);
ALTER TABLE threat_evidence_objects ADD COLUMN malware_scanned_at TIMESTAMP;
ALTER TABLE threat_evidence_objects ADD COLUMN ipfs_cid VARCHAR(255);
ALTER TABLE threat_evidence_objects ADD COLUMN ipfs_status VARCHAR(30) NOT NULL DEFAULT 'NOT_REQUESTED';
CREATE INDEX IF NOT EXISTS ix_threat_evidence_objects_ipfs_cid ON threat_evidence_objects(ipfs_cid);
