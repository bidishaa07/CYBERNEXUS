ALTER TABLE blockchain_transactions ADD COLUMN commitment_id VARCHAR(160);
ALTER TABLE blockchain_transactions ADD COLUMN report_id INTEGER;
ALTER TABLE blockchain_transactions ADD COLUMN block_hash VARCHAR(255);
ALTER TABLE blockchain_transactions ADD COLUMN gas_used INTEGER;
ALTER TABLE blockchain_transactions ADD COLUMN effective_gas_price VARCHAR(80);
ALTER TABLE blockchain_transactions ADD COLUMN confirmation_status VARCHAR(30) DEFAULT 'PENDING';
ALTER TABLE blockchain_transactions ADD COLUMN last_checked_at TIMESTAMP;
CREATE INDEX IF NOT EXISTS ix_blockchain_transactions_commitment_id ON blockchain_transactions(commitment_id);
CREATE INDEX IF NOT EXISTS ix_blockchain_transactions_report_id ON blockchain_transactions(report_id);
