-- Migration: 000001_init_schema.down.sql
-- Rolls back the unified single-tenant enterprise database schema in clean reverse dependency order.

BEGIN;

-- 1. Drop Leaf & Audit Tables
DROP TABLE IF EXISTS agents CASCADE;
DROP TABLE IF EXISTS identity_credentials CASCADE;
DROP TABLE IF EXISTS request_attributions CASCADE;
DROP TABLE IF EXISTS assignments CASCADE;
DROP TABLE IF EXISTS idempotency_records CASCADE;
DROP TABLE IF EXISTS mcp_servers CASCADE;
DROP TABLE IF EXISTS audit_checkpoints CASCADE;
DROP TABLE IF EXISTS audit_events CASCADE;
DROP TABLE IF EXISTS alerts CASCADE;
DROP TABLE IF EXISTS telemetry_events CASCADE;

-- 2. Drop Broker & Routing Tables
DROP TABLE IF EXISTS broker_admissions CASCADE;
DROP TABLE IF EXISTS broker_attempts CASCADE;
DROP TABLE IF EXISTS broker_requests CASCADE;
DROP TABLE IF EXISTS route_profile_activations CASCADE;
DROP TABLE IF EXISTS route_profiles CASCADE;

-- 3. Drop FinOps & Spend Tables
DROP TABLE IF EXISTS spend_v2_increase_requests CASCADE;
DROP TABLE IF EXISTS spend_idempotency CASCADE;
DROP TABLE IF EXISTS spend_events CASCADE;
DROP TABLE IF EXISTS spend_reservations CASCADE;
DROP TABLE IF EXISTS budget_windows CASCADE;
DROP TABLE IF EXISTS spend_policy_versions CASCADE;
DROP TABLE IF EXISTS spend_policies CASCADE;
DROP TABLE IF EXISTS price_book_items CASCADE;
DROP TABLE IF EXISTS price_book_versions CASCADE;

-- 4. Drop Policies & Templates
DROP TABLE IF EXISTS policy_templates CASCADE;
DROP TABLE IF EXISTS group_policy_versions CASCADE;
DROP TABLE IF EXISTS policy_versions CASCADE;
DROP TABLE IF EXISTS policies CASCADE;

-- 5. Drop Keys & Hardware Governance
DROP TABLE IF EXISTS provider_keys CASCADE;
DROP TABLE IF EXISTS virtual_keys CASCADE;
DROP TABLE IF EXISTS oauth_refresh_tokens CASCADE;
DROP TABLE IF EXISTS device_tamper_logs CASCADE;
DROP TABLE IF EXISTS device_compliance_reports CASCADE;
DROP TABLE IF EXISTS device_certificates CASCADE;
DROP TABLE IF EXISTS enrollment_challenges CASCADE;
DROP TABLE IF EXISTS enrollment_transactions CASCADE;
DROP TABLE IF EXISTS enrollment_tokens CASCADE;
DROP TABLE IF EXISTS device_keys CASCADE;
DROP TABLE IF EXISTS devices CASCADE;

-- 6. Drop Identity, Users & Core Organizations
DROP TABLE IF EXISTS team_memberships CASCADE;
DROP TABLE IF EXISTS user_identities CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS auth_providers CASCADE;
DROP TABLE IF EXISTS teams CASCADE;
DROP TABLE IF EXISTS organizations CASCADE;

-- 7. Drop Enums
DROP TYPE IF EXISTS token_status CASCADE;
DROP TYPE IF EXISTS credential_status CASCADE;
DROP TYPE IF EXISTS device_state CASCADE;
DROP TYPE IF EXISTS agent_status CASCADE;
DROP TYPE IF EXISTS alert_severity CASCADE;
DROP TYPE IF EXISTS event_decision CASCADE;

COMMIT;
