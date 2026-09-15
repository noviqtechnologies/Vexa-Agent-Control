-- Migration: 000009 — Phase 1 & Phase 2 Control Hub Hardening
-- Adds device_keys table for Ed25519 public key lifecycle, multi-state capability vector & freshness to devices,
-- and audit_checkpoints table with sequential hash chaining.

BEGIN;

-- 1. Device Public Keys Table (PRD §FR-10.1, §FR-10.2, Task 2.10)
CREATE TABLE IF NOT EXISTS device_keys (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id        TEXT NOT NULL,
    public_key_bytes TEXT NOT NULL,
    algorithm        VARCHAR(32) NOT NULL DEFAULT 'Ed25519',
    status           VARCHAR(32) NOT NULL DEFAULT 'ACTIVE', -- 'ACTIVE', 'ROTATED', 'REVOKED'
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_device_keys_lookup ON device_keys(device_id, status);
CREATE INDEX IF NOT EXISTS idx_device_keys_org ON device_keys(organization_id, device_id);

-- 2. Multi-State Vector and Freshness Tiers on Devices (PRD §CP-FR-16, Task 2.13)
ALTER TABLE devices ADD COLUMN IF NOT EXISTS capability_vector JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_freshness VARCHAR(32) NOT NULL DEFAULT 'STALE';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS verified_target_states JSONB NOT NULL DEFAULT '{}'::jsonb;

-- 3. Audit Checkpoints and Sequential Cryptographic Hash Chaining (PRD §FR-10.8, §NFR-6, Task 3.10)
CREATE TABLE IF NOT EXISTS audit_checkpoints (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id     TEXT NOT NULL DEFAULT 'default',
    sequence_start   BIGINT NOT NULL,
    sequence_end     BIGINT NOT NULL,
    checkpoint_hash  TEXT NOT NULL,
    signature        TEXT NOT NULL,
    algorithm        VARCHAR(32) NOT NULL DEFAULT 'Ed25519',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_checkpoints_org_seq ON audit_checkpoints(organization_id, sequence_end DESC);

ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS event_hash TEXT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS prev_event_hash TEXT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS sequence_number BIGINT;

ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS event_hash TEXT;
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS prev_event_hash TEXT;
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS sequence_number BIGINT;

COMMIT;
