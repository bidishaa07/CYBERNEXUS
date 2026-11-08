CREATE TABLE IF NOT EXISTS app_users (id INTEGER PRIMARY KEY, external_subject VARCHAR(512) NOT NULL UNIQUE, email VARCHAR(512), display_name VARCHAR(255), role VARCHAR(40) NOT NULL DEFAULT 'user', account_status VARCHAR(30) NOT NULL DEFAULT 'active', created_at TIMESTAMP, last_login_at TIMESTAMP);
CREATE INDEX IF NOT EXISTS ix_app_users_external_subject ON app_users(external_subject);
CREATE TABLE IF NOT EXISTS legacy_identity_links (id INTEGER PRIMARY KEY, legacy_user_id VARCHAR(160) NOT NULL UNIQUE, external_subject VARCHAR(512) NOT NULL, linked_by VARCHAR(512) NOT NULL, created_at TIMESTAMP);
CREATE INDEX IF NOT EXISTS ix_legacy_identity_links_external_subject ON legacy_identity_links(external_subject);
