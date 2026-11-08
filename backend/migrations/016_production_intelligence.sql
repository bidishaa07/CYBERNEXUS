CREATE TABLE IF NOT EXISTS intelligence_verifications (id INTEGER PRIMARY KEY, indicator_type VARCHAR(30) NOT NULL, indicator VARCHAR(2048) NOT NULL, provider VARCHAR(120) NOT NULL, status VARCHAR(30) NOT NULL, result_json TEXT NOT NULL, checked_at TIMESTAMP, created_at TIMESTAMP);
CREATE INDEX IF NOT EXISTS ix_intelligence_verifications_indicator_type ON intelligence_verifications(indicator_type);
CREATE INDEX IF NOT EXISTS ix_intelligence_verifications_indicator ON intelligence_verifications(indicator);
CREATE TABLE IF NOT EXISTS background_task_runs (id INTEGER PRIMARY KEY, task_id VARCHAR(160) NOT NULL UNIQUE, task_name VARCHAR(160) NOT NULL, status VARCHAR(30) NOT NULL, result_json TEXT, error VARCHAR(255), started_at TIMESTAMP, completed_at TIMESTAMP, created_at TIMESTAMP);
CREATE INDEX IF NOT EXISTS ix_background_task_runs_task_id ON background_task_runs(task_id);
