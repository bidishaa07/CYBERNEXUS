-- Phase 5.4: remediation state, verification and audit history.
ALTER TABLE security_remediation_records ADD COLUMN assigned_to VARCHAR(160);
ALTER TABLE security_remediation_records ADD COLUMN proposed_fix TEXT DEFAULT '';
ALTER TABLE security_remediation_records ADD COLUMN applied_fix TEXT DEFAULT '';
ALTER TABLE security_remediation_records ADD COLUMN verification_status VARCHAR(30) NOT NULL DEFAULT 'NOT_REQUESTED';
ALTER TABLE security_remediation_records ADD COLUMN verification_note TEXT DEFAULT '';
ALTER TABLE security_remediation_records ADD COLUMN verified_by VARCHAR(160);
ALTER TABLE security_remediation_records ADD COLUMN verified_at TIMESTAMP;

CREATE TABLE IF NOT EXISTS security_finding_remediation_events (
  id INTEGER PRIMARY KEY,
  finding_id INTEGER NOT NULL,
  actor VARCHAR(160) NOT NULL,
  action VARCHAR(50) NOT NULL,
  previous_status VARCHAR(30),
  new_status VARCHAR(30),
  note TEXT DEFAULT '',
  verification_result VARCHAR(30) DEFAULT 'NOT_REQUESTED',
  details_json TEXT DEFAULT '{}',
  created_at TIMESTAMP,
  FOREIGN KEY(finding_id) REFERENCES security_findings(id)
);
CREATE INDEX IF NOT EXISTS ix_security_finding_remediation_events_finding_id ON security_finding_remediation_events(finding_id);
CREATE INDEX IF NOT EXISTS ix_security_finding_remediation_events_created_at ON security_finding_remediation_events(created_at);
CREATE UNIQUE INDEX IF NOT EXISTS ux_security_remediation_records_finding_id ON security_remediation_records(finding_id);
