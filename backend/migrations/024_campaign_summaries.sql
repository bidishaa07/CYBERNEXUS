-- Phase 4.6: evidence-grounded campaign summary history.
CREATE TABLE IF NOT EXISTS campaign_summaries (id INTEGER PRIMARY KEY, campaign_id INTEGER NOT NULL, campaign_version VARCHAR(80) NOT NULL, summary_text TEXT NOT NULL, evidence_refs_json TEXT DEFAULT '[]', provider VARCHAR(120) NOT NULL, model VARCHAR(160), generation_status VARCHAR(40) NOT NULL, generated_at TIMESTAMP, FOREIGN KEY(campaign_id) REFERENCES threat_campaigns(id));
CREATE INDEX IF NOT EXISTS ix_campaign_summaries_campaign_id ON campaign_summaries(campaign_id);
