-- Anomaly alerts: detected anomalies in the decision stream
CREATE TABLE IF NOT EXISTS anomaly_alerts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    type            TEXT NOT NULL,           -- score_drift | block_rate | recording_gap | reason_shift | model_transition | velocity
    severity        TEXT NOT NULL,           -- low | medium | high | critical
    confidence      NUMERIC(4,3) NOT NULL,   -- 0.000 to 1.000
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    details         JSONB NOT NULL DEFAULT '{}',
    affected_from   BIGINT,                  -- sequence range start
    affected_to     BIGINT,                  -- sequence range end
    acknowledged    BOOLEAN NOT NULL DEFAULT false,
    acknowledged_at TIMESTAMPTZ,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_tenant ON anomaly_alerts(tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_type ON anomaly_alerts(tenant_id, type, detected_at DESC);

-- Tenant baselines: rolling statistical baselines per tenant
CREATE TABLE IF NOT EXISTS tenant_baselines (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    window_start    TIMESTAMPTZ NOT NULL,
    window_end      TIMESTAMPTZ NOT NULL,
    total_records   INTEGER NOT NULL DEFAULT 0,
    avg_score       NUMERIC(6,4),
    stddev_score    NUMERIC(6,4),
    block_rate      NUMERIC(6,4),
    allow_rate      NUMERIC(6,4),
    review_rate     NUMERIC(6,4),
    reason_code_freq JSONB NOT NULL DEFAULT '{}',
    model_versions  JSONB NOT NULL DEFAULT '[]',
    avg_velocity    NUMERIC(10,2),
    computed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, window_start)
);
CREATE INDEX IF NOT EXISTS idx_baselines_tenant ON tenant_baselines(tenant_id, window_start DESC);
