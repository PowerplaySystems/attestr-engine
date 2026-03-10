-- Merkle batch table: stores completed Merkle trees for groups of ledger entries
CREATE TABLE IF NOT EXISTS merkle_batches (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    batch_number    BIGINT NOT NULL,
    start_sequence  BIGINT NOT NULL,
    end_sequence    BIGINT NOT NULL,
    root_hash       TEXT NOT NULL,
    root_signature  TEXT NOT NULL,
    tree_data       JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, batch_number),
    UNIQUE(tenant_id, start_sequence)
);

CREATE INDEX IF NOT EXISTS idx_merkle_batches_tenant_seq
    ON merkle_batches(tenant_id, start_sequence DESC);
