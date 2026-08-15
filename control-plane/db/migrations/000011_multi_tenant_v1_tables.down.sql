-- Migration: 000011_multi_tenant_v1_tables.down.sql
-- Description: Revert multi-tenant v1 additions (Development use only).

BEGIN;

DROP INDEX IF EXISTS idx_agents_tenant;
DROP INDEX IF EXISTS idx_events_tenant;
DROP INDEX IF EXISTS idx_alerts_tenant;
DROP INDEX IF EXISTS idx_auth_providers_tenant;
DROP INDEX IF EXISTS idx_users_tenant;
DROP INDEX IF EXISTS idx_policies_tenant;
DROP INDEX IF EXISTS idx_mcp_servers_tenant;
DROP INDEX IF EXISTS idx_group_policies_tenant;

ALTER TABLE agents DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE telemetry_events DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE alerts DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE identity_credentials DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE auth_providers DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE users DROP COLUMN IF EXISTS is_saas_operator;
ALTER TABLE users DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE policies DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE mcp_servers DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE spend_budgets DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE spend_snapshots DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE spend_increase_requests DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE group_policy_versions DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE provider_keys DROP COLUMN IF EXISTS tenant_id;

DROP INDEX IF EXISTS idx_provider_keys_provider;
CREATE UNIQUE INDEX idx_provider_keys_provider ON provider_keys(provider);

ALTER TABLE tenants DROP COLUMN IF EXISTS name;
ALTER TABLE tenants DROP COLUMN IF EXISTS contact_email;
ALTER TABLE tenants DROP COLUMN IF EXISTS license_tier;
ALTER TABLE tenants DROP COLUMN IF EXISTS max_seats;
ALTER TABLE tenants DROP COLUMN IF EXISTS license_key_jwt;
ALTER TABLE tenants DROP COLUMN IF EXISTS is_trial;
ALTER TABLE tenants DROP COLUMN IF EXISTS trial_days;
ALTER TABLE tenants DROP COLUMN IF EXISTS trial_ends_at;
ALTER TABLE tenants DROP COLUMN IF EXISTS license_expires_at;
ALTER TABLE tenants DROP COLUMN IF EXISTS gateway_secret;
ALTER TABLE tenants DROP COLUMN IF EXISTS policy_read_secret;
ALTER TABLE tenants DROP COLUMN IF EXISTS bootstrap_token_hash;
ALTER TABLE tenants DROP COLUMN IF EXISTS bootstrap_token_hint;
ALTER TABLE tenants DROP COLUMN IF EXISTS bootstrap_consumed_at;
ALTER TABLE tenants DROP COLUMN IF EXISTS updated_at;

COMMIT;
