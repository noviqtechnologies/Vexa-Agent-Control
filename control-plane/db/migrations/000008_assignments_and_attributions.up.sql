-- Migration: 000008 — Desired-State Assignment Model, Identity-Correlated Attributions & Dead Schema Pruning
BEGIN;

-- 1. Dead Schema Pruning: Drop unreferenced legacy price_books table (superseded by price_book_versions & price_book_items)
DROP TABLE IF EXISTS price_books CASCADE;

-- 2. Assignments Table (REQ-DSM-001 / REQ-DSM-002)
CREATE TABLE IF NOT EXISTS assignments (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id             UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_type                 TEXT NOT NULL, -- 'device', 'user', 'group'
    target_id                   TEXT NOT NULL,
    kind                        TEXT NOT NULL, -- 'policy', 'provider_keys', 'cursor_mode', 'llm_profile'
    payload_ref                 TEXT NOT NULL, -- SHA-256 hash or version snapshot
    state                       VARCHAR(32) NOT NULL DEFAULT 'desired',
    rollback_from_assignment_id UUID REFERENCES assignments(id) ON DELETE SET NULL,
    state_history               JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_assignments_org_target_kind UNIQUE (organization_id, target_type, target_id, kind),
    CONSTRAINT chk_assignment_state CHECK (state IN (
        'desired', 'eligible', 'delivered', 'applied', 'verified', 'failed', 'stale', 'revoked', 'rolled_back'
    ))
);

CREATE INDEX IF NOT EXISTS idx_assignments_org_target ON assignments(organization_id, target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_assignments_state ON assignments(state);
CREATE INDEX IF NOT EXISTS idx_assignments_updated ON assignments(updated_at DESC);

-- 3. Request Attributions Table (REQ-VER-001 / REQ-VER-003)
CREATE TABLE IF NOT EXISTS request_attributions (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id        TEXT NOT NULL,
    organization_id   UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id         TEXT NOT NULL,
    user_id           TEXT NOT NULL,
    identity_source   TEXT NOT NULL DEFAULT 'local_os', -- 'local_os' vs 'oidc'
    identity_verified BOOLEAN NOT NULL DEFAULT false,
    assignment_id     UUID REFERENCES assignments(id) ON DELETE SET NULL,
    provider          TEXT NOT NULL,
    model             TEXT NOT NULL,
    status_code       INT NOT NULL DEFAULT 200,
    input_tokens      BIGINT NOT NULL DEFAULT 0,
    output_tokens     BIGINT NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_attributions_org_created ON request_attributions(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_attributions_device ON request_attributions(device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_attributions_user ON request_attributions(organization_id, user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_attributions_assignment ON request_attributions(assignment_id);

-- 4. Devices Table Enhancements for Verified Identity (REQ-VER-002)
ALTER TABLE devices ADD COLUMN IF NOT EXISTS identity_source TEXT NOT NULL DEFAULT 'local_os';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS identity_verified BOOLEAN NOT NULL DEFAULT false;

COMMIT;
