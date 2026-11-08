CREATE TABLE IF NOT EXISTS website_image_candidates (id INTEGER PRIMARY KEY, scan_id INTEGER, asset_type VARCHAR(20) NOT NULL, source_url VARCHAR(2048) NOT NULL, extraction_method VARCHAR(80), status VARCHAR(30), format VARCHAR(20), width INTEGER, height INTEGER, sha256 VARCHAR(64), phash TEXT, dhash TEXT, checked_at TIMESTAMP);
CREATE INDEX IF NOT EXISTS ix_website_image_candidates_scan_id ON website_image_candidates(scan_id);
CREATE TABLE IF NOT EXISTS image_comparisons (id INTEGER PRIMARY KEY, scan_id INTEGER, candidate_id INTEGER, reference_id INTEGER, brand_id INTEGER, asset_type VARCHAR(20) NOT NULL, similarity FLOAT, exact_match VARCHAR(10), confidence VARCHAR(20), method VARCHAR(255), evidence_json TEXT DEFAULT '{}', checked_at TIMESTAMP);
CREATE INDEX IF NOT EXISTS ix_image_comparisons_scan_id ON image_comparisons(scan_id);
CREATE INDEX IF NOT EXISTS ix_image_comparisons_candidate_id ON image_comparisons(candidate_id);
