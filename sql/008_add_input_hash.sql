-- Add input_hash column for dual-attestation
-- Customers compute SHA-256 of their raw input data (transaction payload)
-- and include it in the decision record. This allows third parties to verify
-- that the decision was based on the claimed input, not fabricated data.
ALTER TABLE ledger_entries ADD COLUMN IF NOT EXISTS input_hash TEXT;

-- Index for lookups by input_hash
CREATE INDEX IF NOT EXISTS idx_ledger_input_hash ON ledger_entries(tenant_id, input_hash) WHERE input_hash IS NOT NULL;
