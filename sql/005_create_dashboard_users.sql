CREATE TABLE IF NOT EXISTS dashboard_users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    supabase_user_id UUID NOT NULL UNIQUE,
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    email           TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'admin',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dashboard_users_supabase ON dashboard_users(supabase_user_id);
CREATE INDEX IF NOT EXISTS idx_dashboard_users_tenant ON dashboard_users(tenant_id);
