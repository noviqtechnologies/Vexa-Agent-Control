-- Migration: 000011_multi_tenant_v1_tables.up.sql
-- Description: Extend tenants table with organization metadata and add tenant_id to all v1 tables.

BEGIN;

-- 1. Extend tenants table with organization metadata, licensing, secrets, and trial info
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS contact_email TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS license_tier TEXT NOT NULL DEFAULT 'community'
    CHECK (license_tier IN ('community', 'team', 'enterprise'));
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_seats INTEGER NOT NULL DEFAULT 10;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS license_key_jwt TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS is_trial BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS trial_days INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS trial_ends_at TIMESTAMPTZ;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS license_expires_at TIMESTAMPTZ;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS gateway_secret TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS policy_read_secret TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS bootstrap_token_hash TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS bootstrap_token_hint TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS bootstrap_consumed_at TIMESTAMPTZ;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Update default tenant metadata
UPDATE tenants 
SET name = 'Default Organization', 
    contact_email = 'admin@agentwall.local',
    license_tier = 'community',
    max_seats = 10,
    is_trial = false
WHERE id = '00000000-0000-0000-0000-000000000001' AND name = '';

-- 2. Add tenant_id to all 13 V1 tables (instant metadata addition with default)
ALTER TABLE agents ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE identity_credentials ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE auth_providers ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_saas_operator BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE spend_budgets ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE spend_snapshots ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE spend_increase_requests ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE group_policy_versions ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE provider_keys ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;

-- 3. Composite Indexes for fast tenant-scoped queries
CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents(tenant_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_tenant ON telemetry_events(tenant_id, timestamp_ms DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_providers_tenant ON auth_providers(tenant_id, type);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id, email);
CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies(tenant_id, is_active);
CREATE INDEX IF NOT EXISTS idx_mcp_servers_tenant ON mcp_servers(tenant_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_group_policies_tenant ON group_policy_versions(tenant_id, group_id);

-- Rebuild provider_keys unique index to be tenant-scoped
DROP INDEX IF EXISTS idx_provider_keys_provider;
CREATE UNIQUE INDEX idx_provider_keys_provider ON provider_keys(tenant_id, provider);

-- Rebuild auth_providers local unique index to be tenant-scoped
DROP INDEX IF EXISTS idx_auth_providers_local_unique;
CREATE UNIQUE INDEX idx_auth_providers_local_unique ON auth_providers(tenant_id, type) WHERE type = 'local';

COMMIT;
