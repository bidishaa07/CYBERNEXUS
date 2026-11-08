-- Phase 5.6: explicit authorization and active-testing controls.
ALTER TABLE security_assessments ADD COLUMN assessment_mode VARCHAR(20) NOT NULL DEFAULT 'PASSIVE';
ALTER TABLE security_assessments ADD COLUMN authorization_id INTEGER;
ALTER TABLE security_assessments ADD COLUMN stopped_reason VARCHAR(255);

CREATE TABLE IF NOT EXISTS security_authorizations (
  id INTEGER PRIMARY KEY,
  assessment_id INTEGER,
  target_hostname VARCHAR(255) NOT NULL,
  authorized_organization VARCHAR(255) NOT NULL,
  requester_user_id VARCHAR(160) NOT NULL,
  authorization_confirmed INTEGER NOT NULL DEFAULT 0,
  permitted_scope_json TEXT DEFAULT '[]',
  allowed_categories_json TEXT DEFAULT '[]',
  start_time TIMESTAMP NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  approval_status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
  supporting_reference VARCHAR(2048),
  approved_by VARCHAR(160),
  approved_at TIMESTAMP,
  revoked_at TIMESTAMP,
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  FOREIGN KEY(assessment_id) REFERENCES security_assessments(id)
);
CREATE INDEX IF NOT EXISTS ix_security_authorizations_target_hostname ON security_authorizations(target_hostname);
CREATE INDEX IF NOT EXISTS ix_security_authorizations_requester_user_id ON security_authorizations(requester_user_id);
CREATE INDEX IF NOT EXISTS ix_security_authorizations_expires_at ON security_authorizations(expires_at);
CREATE INDEX IF NOT EXISTS ix_security_authorizations_approval_status ON security_authorizations(approval_status);
CREATE TABLE IF NOT EXISTS security_authorization_events (
  id INTEGER PRIMARY KEY,
  authorization_id INTEGER NOT NULL,
  actor VARCHAR(160) NOT NULL,
  action VARCHAR(40) NOT NULL,
  previous_status VARCHAR(20),
  new_status VARCHAR(20),
  note TEXT DEFAULT '',
  created_at TIMESTAMP,
  FOREIGN KEY(authorization_id) REFERENCES security_authorizations(id)
);
CREATE INDEX IF NOT EXISTS ix_security_authorization_events_authorization_id ON security_authorization_events(authorization_id);
CREATE INDEX IF NOT EXISTS ix_security_authorization_events_created_at ON security_authorization_events(created_at);
