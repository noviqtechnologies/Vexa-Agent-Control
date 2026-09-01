-- Migration: 000003 — Observability Request Logs, Live Telemetry & Deleted Entities Audit
-- Enriches spend_reservations with token provenance, TTFT, virtual key attribution, and session tracking
-- Adds tombstone soft-deletion columns to virtual_keys for compliance auditing

BEGIN;

-- 1. ENRICH SPEND RESERVATIONS / RUNS FOR REQUEST LOGS
ALTER TABLE spend_reservations
    ADD COLUMN IF NOT EXISTS ttft_ms INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS input_tokens BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS output_tokens BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS cached_tokens BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS virtual_key_id UUID,
    ADD COLUMN IF NOT EXISTS virtual_key_hash TEXT,
    ADD COLUMN IF NOT EXISTS virtual_key_prefix TEXT,
    ADD COLUMN IF NOT EXISTS virtual_key_alias TEXT,
    ADD COLUMN IF NOT EXISTS session_id TEXT,
    ADD COLUMN IF NOT EXISTS internal_user_id TEXT,
    ADD COLUMN IF NOT EXISTS end_user_id TEXT,
    ADD COLUMN IF NOT EXISTS tags JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS request_type TEXT NOT NULL DEFAULT 'LLM',
    ADD COLUMN IF NOT EXISTS status_code INT NOT NULL DEFAULT 200;

CREATE INDEX IF NOT EXISTS idx_spend_reservations_session
    ON spend_reservations (organization_id, session_id)
    WHERE session_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_spend_reservations_vk
    ON spend_reservations (organization_id, virtual_key_id)
    WHERE virtual_key_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_spend_reservations_created_desc
    ON spend_reservations (organization_id, created_at DESC);

-- 2. VIRTUAL KEYS TOMBSTONING FOR DELETED KEYS AUDITING
ALTER TABLE virtual_keys
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS deleted_by TEXT,
    ADD COLUMN IF NOT EXISTS deleted_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_virtual_keys_deleted
    ON virtual_keys (tenant_id, deleted_at DESC)
    WHERE deleted_at IS NOT NULL;

-- 3. AUDIT EVENTS QUERY INDEXES
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_time
    ON audit_events (tenant_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_resource
    ON audit_events (tenant_id, resource_type, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_action
    ON audit_events (tenant_id, action, occurred_at DESC);

COMMIT;
