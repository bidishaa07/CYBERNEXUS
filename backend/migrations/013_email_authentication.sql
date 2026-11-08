CREATE TABLE IF NOT EXISTS email_raw_messages (
    id INTEGER PRIMARY KEY,
    analysis_id INTEGER NOT NULL UNIQUE,
    raw_bytes BLOB NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    created_at TIMESTAMP,
    FOREIGN KEY(analysis_id) REFERENCES email_analyses(id)
);
CREATE INDEX IF NOT EXISTS ix_email_raw_messages_analysis_id ON email_raw_messages(analysis_id);
CREATE TABLE IF NOT EXISTS email_smtp_contexts (
    id INTEGER PRIMARY KEY,
    analysis_id INTEGER NOT NULL,
    smtp_client_ip VARCHAR(64) NOT NULL,
    envelope_mail_from VARCHAR(512) NOT NULL,
    helo_hostname VARCHAR(255) NOT NULL,
    receiving_server VARCHAR(255) NOT NULL,
    message_id VARCHAR(512) NOT NULL,
    trusted_source VARCHAR(255) NOT NULL,
    received_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP,
    FOREIGN KEY(analysis_id) REFERENCES email_analyses(id)
);
CREATE INDEX IF NOT EXISTS ix_email_smtp_contexts_analysis_id ON email_smtp_contexts(analysis_id);
CREATE TABLE IF NOT EXISTS email_verification_runs (
    id INTEGER PRIMARY KEY,
    analysis_id INTEGER NOT NULL,
    verification_type VARCHAR(30) NOT NULL,
    result_json TEXT NOT NULL,
    source VARCHAR(255) NOT NULL,
    created_at TIMESTAMP,
    FOREIGN KEY(analysis_id) REFERENCES email_analyses(id)
);
CREATE INDEX IF NOT EXISTS ix_email_verification_runs_analysis_id ON email_verification_runs(analysis_id);
