-- Migration: 000001_initial_schema.down.sql
-- Description: Teardown all AgentControl tables, types, and extensions.

BEGIN;

DROP TABLE IF EXISTS spend_v2_increase_requests CASCADE;
DROP TABLE IF EXISTS spend_idempotency CASCADE;
DROP TABLE IF EXISTS spend_events CASCADE;
DROP TABLE IF EXISTS spend_reservations CASCADE;
DROP TABLE IF EXISTS budget_windows CASCADE;
DROP TABLE IF EXISTS spend_policy_versions CASCADE;
DROP TABLE IF EXISTS spend_policies CASCADE;
DROP TABLE IF EXISTS price_book_items CASCADE;
DROP TABLE IF EXISTS price_books CASCADE;
DROP TABLE IF EXISTS spend_increase_requests CASCADE;
DROP TABLE IF EXISTS spend_snapshots CASCADE;
DROP TABLE IF EXISTS spend_budgets CASCADE;

DROP TABLE IF EXISTS audit_events CASCADE;
DROP TABLE IF EXISTS device_security_events CASCADE;
DROP TABLE IF EXISTS device_heartbeats CASCADE;
DROP TABLE IF EXISTS device_state_history CASCADE;
DROP TABLE IF EXISTS device_provider_capabilities CASCADE;
DROP TABLE IF EXISTS device_policy_assignments CASCADE;
DROP TABLE IF EXISTS policy_versions CASCADE;
DROP TABLE IF EXISTS device_certificates CASCADE;
DROP TABLE IF EXISTS device_enrollment_keys CASCADE;
DROP TABLE IF EXISTS enrollment_tokens CASCADE;
DROP TABLE IF EXISTS device_tamper_logs CASCADE;
DROP TABLE IF EXISTS device_ide_status CASCADE;
DROP TABLE IF EXISTS device_compliance_reports CASCADE;
DROP TABLE IF EXISTS device_enrollments CASCADE;
DROP TABLE IF EXISTS devices CASCADE;

DROP TABLE IF EXISTS provider_keys CASCADE;
DROP TABLE IF EXISTS group_policy_versions CASCADE;
DROP TABLE IF EXISTS policy_templates CASCADE;
DROP TABLE IF EXISTS policies CASCADE;
DROP TABLE IF EXISTS mcp_servers CASCADE;
DROP TABLE IF EXISTS identity_credentials CASCADE;
DROP TABLE IF EXISTS alerts CASCADE;
DROP TABLE IF EXISTS telemetry_events CASCADE;
DROP TABLE IF EXISTS agents CASCADE;

DROP TABLE IF EXISTS tenant_memberships CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS auth_providers CASCADE;
DROP TABLE IF EXISTS tenants CASCADE;

DROP TYPE IF EXISTS increase_request_status;
DROP TYPE IF EXISTS reservation_state;
DROP TYPE IF EXISTS spend_event_type;
DROP TYPE IF EXISTS spend_policy_status;
DROP TYPE IF EXISTS spend_action_type;
DROP TYPE IF EXISTS spend_period_type;
DROP TYPE IF EXISTS spend_scope_type;
DROP TYPE IF EXISTS event_severity;
DROP TYPE IF EXISTS actor_type;
DROP TYPE IF EXISTS token_status;
DROP TYPE IF EXISTS credential_status;
DROP TYPE IF EXISTS device_state;
DROP TYPE IF EXISTS subscription_tier;
DROP TYPE IF EXISTS auth_provider_type;
DROP TYPE IF EXISTS agent_status;
DROP TYPE IF EXISTS alert_severity;
DROP TYPE IF EXISTS event_decision;

COMMIT;
