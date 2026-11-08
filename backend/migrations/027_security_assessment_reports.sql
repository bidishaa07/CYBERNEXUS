-- Phase 5.5: persisted security-assessment report generation history.
CREATE TABLE IF NOT EXISTS security_assessment_reports (
  id INTEGER PRIMARY KEY,
  assessment_id INTEGER NOT NULL,
  generated_by VARCHAR(160) NOT NULL,
  report_version VARCHAR(30) NOT NULL DEFAULT '1.0',
  format VARCHAR(10) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'COMPLETED',
  finding_count INTEGER NOT NULL DEFAULT 0,
  error TEXT DEFAULT '',
  generated_at TIMESTAMP,
  FOREIGN KEY(assessment_id) REFERENCES security_assessments(id)
);
CREATE INDEX IF NOT EXISTS ix_security_assessment_reports_assessment_id ON security_assessment_reports(assessment_id);
CREATE INDEX IF NOT EXISTS ix_security_assessment_reports_generated_by ON security_assessment_reports(generated_by);
CREATE INDEX IF NOT EXISTS ix_security_assessment_reports_generated_at ON security_assessment_reports(generated_at);
