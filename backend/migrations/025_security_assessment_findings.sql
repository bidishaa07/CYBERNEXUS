-- Phase 5.1: normalized website security assessment architecture.
CREATE TABLE IF NOT EXISTS security_assessments (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER,
  user_id VARCHAR(160) NOT NULL DEFAULT 'anonymous',
  target_url VARCHAR(2048) NOT NULL,
  hostname VARCHAR(255) NOT NULL,
  status VARCHAR(30) NOT NULL DEFAULT 'COMPLETED',
  finding_count INTEGER NOT NULL DEFAULT 0,
  pass_count INTEGER NOT NULL DEFAULT 0,
  fail_count INTEGER NOT NULL DEFAULT 0,
  warning_count INTEGER NOT NULL DEFAULT 0,
  unknown_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP,
  completed_at TIMESTAMP,
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS ix_security_assessments_user_id ON security_assessments(user_id);
CREATE INDEX IF NOT EXISTS ix_security_assessments_hostname ON security_assessments(hostname);
CREATE INDEX IF NOT EXISTS ix_security_assessments_scan_id ON security_assessments(scan_id);

CREATE TABLE IF NOT EXISTS security_findings (
  id INTEGER PRIMARY KEY,
  assessment_id INTEGER NOT NULL,
  target_url VARCHAR(2048) NOT NULL,
  hostname VARCHAR(255) NOT NULL,
  category VARCHAR(50) NOT NULL,
  check_identifier VARCHAR(120) NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT DEFAULT '',
  severity VARCHAR(20) NOT NULL DEFAULT 'INFO',
  confidence VARCHAR(20) NOT NULL DEFAULT 'UNKNOWN',
  status VARCHAR(30) NOT NULL DEFAULT 'UNKNOWN',
  observed_value TEXT,
  expected_value TEXT,
  security_impact TEXT DEFAULT '',
  remediation TEXT DEFAULT '',
  evidence_json TEXT DEFAULT '{}',
  verification_limitations TEXT DEFAULT '',
  remediation_status VARCHAR(30) NOT NULL DEFAULT 'OPEN',
  first_detected TIMESTAMP,
  last_detected TIMESTAMP,
  created_at TIMESTAMP,
  FOREIGN KEY(assessment_id) REFERENCES security_assessments(id),
  CONSTRAINT uq_security_finding_check UNIQUE(assessment_id, check_identifier)
);
CREATE INDEX IF NOT EXISTS ix_security_findings_assessment_id ON security_findings(assessment_id);
CREATE INDEX IF NOT EXISTS ix_security_findings_category ON security_findings(category);
CREATE INDEX IF NOT EXISTS ix_security_findings_severity ON security_findings(severity);
CREATE INDEX IF NOT EXISTS ix_security_findings_status ON security_findings(status);

CREATE TABLE IF NOT EXISTS security_check_results (
  id INTEGER PRIMARY KEY,
  assessment_id INTEGER NOT NULL,
  category VARCHAR(50) NOT NULL,
  check_identifier VARCHAR(120) NOT NULL,
  status VARCHAR(30) NOT NULL,
  result_json TEXT DEFAULT '{}',
  checked_at TIMESTAMP,
  FOREIGN KEY(assessment_id) REFERENCES security_assessments(id),
  CONSTRAINT uq_security_check_result UNIQUE(assessment_id, check_identifier)
);
CREATE INDEX IF NOT EXISTS ix_security_check_results_assessment_id ON security_check_results(assessment_id);

CREATE TABLE IF NOT EXISTS security_evidence (
  id INTEGER PRIMARY KEY,
  assessment_id INTEGER NOT NULL,
  finding_id INTEGER,
  source VARCHAR(120) NOT NULL,
  evidence_type VARCHAR(80) NOT NULL,
  details_json TEXT DEFAULT '{}',
  observed_at TIMESTAMP,
  FOREIGN KEY(assessment_id) REFERENCES security_assessments(id),
  FOREIGN KEY(finding_id) REFERENCES security_findings(id)
);
CREATE INDEX IF NOT EXISTS ix_security_evidence_assessment_id ON security_evidence(assessment_id);
CREATE INDEX IF NOT EXISTS ix_security_evidence_finding_id ON security_evidence(finding_id);

CREATE TABLE IF NOT EXISTS security_remediation_records (
  id INTEGER PRIMARY KEY,
  finding_id INTEGER NOT NULL,
  status VARCHAR(30) NOT NULL DEFAULT 'OPEN',
  note TEXT DEFAULT '',
  updated_by VARCHAR(160) NOT NULL DEFAULT 'system',
  updated_at TIMESTAMP,
  FOREIGN KEY(finding_id) REFERENCES security_findings(id)
);
CREATE INDEX IF NOT EXISTS ix_security_remediation_records_finding_id ON security_remediation_records(finding_id);

CREATE TABLE IF NOT EXISTS security_assessment_authorizations (
  id INTEGER PRIMARY KEY,
  assessment_id INTEGER NOT NULL,
  user_id VARCHAR(160) NOT NULL,
  access_level VARCHAR(30) NOT NULL DEFAULT 'VIEW',
  created_at TIMESTAMP,
  FOREIGN KEY(assessment_id) REFERENCES security_assessments(id),
  CONSTRAINT uq_security_assessment_authorization UNIQUE(assessment_id, user_id)
);
CREATE INDEX IF NOT EXISTS ix_security_assessment_authorizations_user_id ON security_assessment_authorizations(user_id);

CREATE TABLE IF NOT EXISTS security_assessment_events (
  id INTEGER PRIMARY KEY,
  assessment_id INTEGER NOT NULL,
  actor VARCHAR(160) NOT NULL,
  event_type VARCHAR(60) NOT NULL,
  details_json TEXT DEFAULT '{}',
  created_at TIMESTAMP,
  FOREIGN KEY(assessment_id) REFERENCES security_assessments(id)
);
CREATE INDEX IF NOT EXISTS ix_security_assessment_events_assessment_id ON security_assessment_events(assessment_id);
