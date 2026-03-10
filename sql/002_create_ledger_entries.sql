CREATE TABLE IF NOT EXISTS ledger_entries (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL REFERENCES tenants(id),
    sequence_number       BIGINT NOT NULL,
    event_id              TEXT NOT NULL,
    decision              TEXT NOT NULL,
    score                 NUMERIC(6,4),
    reason_codes          JSONB NOT NULL DEFAULT '[]',
    feature_contributions JSONB,
    model_version         TEXT,
    policy_version        TEXT,
    decided_at            TIMESTAMPTZ NOT NULL,
    metadata              JSONB,
    record_hash           TEXT NOT NULL,
    previous_hash         TEXT NOT NULL,
    platform_signature    TEXT NOT NULL,
    ingested_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, event_id),
    UNIQUE(tenant_id, sequence_number)
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_ledger_tenant_decided ON ledger_entries(tenant_id, decided_at DESC);
CREATE INDEX IF NOT EXISTS idx_ledger_tenant_sequence ON ledger_entries(tenant_id, sequence_number DESC);
CREATE INDEX IF NOT EXISTS idx_ledger_tenant_decision ON ledger_entries(tenant_id, decision);
