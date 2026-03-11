-- Allow a Supabase user to be linked to multiple tenants (e.g. a regulator auditing 2 clients)
ALTER TABLE dashboard_users DROP CONSTRAINT IF EXISTS dashboard_users_supabase_user_id_key;
DROP INDEX IF EXISTS idx_dashboard_users_supabase;
CREATE UNIQUE INDEX IF NOT EXISTS idx_dashboard_users_tenant_user
    ON dashboard_users(supabase_user_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_dashboard_users_supabase
    ON dashboard_users(supabase_user_id);

-- Invite table for auditor/regulator access
CREATE TABLE IF NOT EXISTS tenant_invites (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id),
    email       TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'auditor',
    token       TEXT NOT NULL UNIQUE,
    invited_by  UUID NOT NULL REFERENCES dashboard_users(id),
    accepted_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenant_invites_token ON tenant_invites(token);
CREATE INDEX IF NOT EXISTS idx_tenant_invites_tenant ON tenant_invites(tenant_id);
