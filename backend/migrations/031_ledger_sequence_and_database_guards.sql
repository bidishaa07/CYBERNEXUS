CREATE TABLE IF NOT EXISTS threat_ledger_sequence_state (
  id INTEGER PRIMARY KEY,
  next_sequence INTEGER NOT NULL DEFAULT 1,
  updated_at TIMESTAMP
);
INSERT INTO threat_ledger_sequence_state (id, next_sequence, updated_at)
SELECT 1, COALESCE(MAX(sequence_number), 0) + 1, CURRENT_TIMESTAMP
FROM threat_append_only_ledger_events
WHERE NOT EXISTS (SELECT 1 FROM threat_ledger_sequence_state WHERE id = 1)
ON CONFLICT(id) DO NOTHING;
CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_ledger_sequence_state_id ON threat_ledger_sequence_state(id);
