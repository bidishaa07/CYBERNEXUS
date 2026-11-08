CREATE TABLE IF NOT EXISTS email_analyses (
    id INTEGER PRIMARY KEY,
    filename VARCHAR(255),
    content_type VARCHAR(120),
    size_bytes INTEGER NOT NULL,
    message_id VARCHAR(512),
    sender VARCHAR(512),
    subject TEXT,
    analysis_status VARCHAR(30) NOT NULL DEFAULT 'COMPLETED',
    result_json TEXT NOT NULL,
    created_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_email_analyses_created_at ON email_analyses(created_at);
CREATE TABLE IF NOT EXISTS email_headers (
    id INTEGER PRIMARY KEY,
    analysis_id INTEGER NOT NULL,
    header_name VARCHAR(120) NOT NULL,
    header_value TEXT NOT NULL,
    normalized_value TEXT,
    position INTEGER DEFAULT 0,
    FOREIGN KEY(analysis_id) REFERENCES email_analyses(id)
);
CREATE INDEX IF NOT EXISTS ix_email_headers_analysis_id ON email_headers(analysis_id);
CREATE TABLE IF NOT EXISTS email_authentication_results (
    id INTEGER PRIMARY KEY,
    analysis_id INTEGER NOT NULL,
    mechanism VARCHAR(20) NOT NULL,
    status VARCHAR(30) NOT NULL,
    domain VARCHAR(255),
    selector VARCHAR(255),
    source VARCHAR(120),
    evidence_json TEXT DEFAULT '{}',
    checked_at TIMESTAMP,
    FOREIGN KEY(analysis_id) REFERENCES email_analyses(id)
);
CREATE INDEX IF NOT EXISTS ix_email_authentication_results_analysis_id ON email_authentication_results(analysis_id);
CREATE TABLE IF NOT EXISTS email_header_anomalies (
    id INTEGER PRIMARY KEY,
    analysis_id INTEGER NOT NULL,
    anomaly_type VARCHAR(80) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    evidence TEXT NOT NULL,
    created_at TIMESTAMP,
    FOREIGN KEY(analysis_id) REFERENCES email_analyses(id)
);
CREATE INDEX IF NOT EXISTS ix_email_header_anomalies_analysis_id ON email_header_anomalies(analysis_id);
