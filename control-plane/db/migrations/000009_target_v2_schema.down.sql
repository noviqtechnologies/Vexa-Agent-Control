-- Migration: 000008_target_v2_schema.down.sql
-- Purpose: Teardown Vexa AgentWall v4.0 Target Schema

BEGIN;

DROP TABLE IF EXISTS device_recovery_approvals CASCADE;
DROP TABLE IF EXISTS outbox_events CASCADE;
DROP TABLE IF EXISTS idempotency_records CASCADE;
DROP TABLE IF EXISTS audit_events CASCADE;
DROP TABLE IF EXISTS device_security_events CASCADE;
DROP TABLE IF EXISTS device_heartbeats CASCADE;
DROP TABLE IF EXISTS device_state_history CASCADE;
DROP TABLE IF EXISTS device_provider_capabilities CASCADE;
DROP TABLE IF EXISTS device_policy_assignments CASCADE;
DROP TABLE IF EXISTS policy_versions CASCADE;
DROP TABLE IF EXISTS device_certificates CASCADE;
DROP TABLE IF EXISTS device_enrollment_keys CASCADE;
DROP TABLE IF EXISTS devices CASCADE;
DROP TABLE IF EXISTS enrollment_challenges CASCADE;
DROP TABLE IF EXISTS enrollment_transactions CASCADE;
DROP TABLE IF EXISTS enrollment_tokens CASCADE;
DROP TABLE IF EXISTS tenant_members CASCADE;
DROP TABLE IF EXISTS tenants CASCADE;

DROP TYPE IF EXISTS actor_type;
DROP TYPE IF EXISTS token_status;
DROP TYPE IF EXISTS credential_status;
DROP TYPE IF EXISTS device_state;

COMMIT;
