CREATE TABLE IF NOT EXISTS brand_verification_challenges (id INTEGER PRIMARY KEY, brand_id INTEGER, domain VARCHAR(255) NOT NULL, method VARCHAR(30) NOT NULL, token_hash VARCHAR(64) NOT NULL, challenge_path VARCHAR(255), status VARCHAR(30) DEFAULT 'pending', created_at TIMESTAMP, expires_at TIMESTAMP NOT NULL, verified_at TIMESTAMP);
CREATE INDEX IF NOT EXISTS ix_brand_verification_challenges_domain ON brand_verification_challenges(domain);
CREATE TABLE IF NOT EXISTS brand_verification_audit (id INTEGER PRIMARY KEY, brand_id INTEGER, actor VARCHAR(120) NOT NULL, action VARCHAR(80) NOT NULL, details_json TEXT DEFAULT '{}', created_at TIMESTAMP);
CREATE INDEX IF NOT EXISTS ix_brand_verification_audit_brand_id ON brand_verification_audit(brand_id);
CREATE TABLE IF NOT EXISTS brand_logo_assets (id INTEGER PRIMARY KEY, brand_id INTEGER, original_source VARCHAR(2048), content_type VARCHAR(120) NOT NULL, width INTEGER, height INTEGER, phash VARCHAR(128) NOT NULL, image_bytes BLOB NOT NULL, approval_status VARCHAR(30) DEFAULT 'pending', source VARCHAR(255), uploaded_at TIMESTAMP, approved_at TIMESTAMP);
CREATE INDEX IF NOT EXISTS ix_brand_logo_assets_brand_id ON brand_logo_assets(brand_id);
CREATE INDEX IF NOT EXISTS ix_brand_logo_assets_approval_status ON brand_logo_assets(approval_status);
