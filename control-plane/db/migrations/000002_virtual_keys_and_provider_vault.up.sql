-- Migration: 000002 — Pillar 1: Scoped Virtual Keys & Provider Key Vault
-- Adds the virtual_keys table (per-tenant governed API keys) and the
-- provider_keys table (encrypted per-tenant LLM provider API key vault).
-- Both tables auto-idempotent via CREATE TABLE IF NOT EXISTS.
--
-- Financial model: all spend values are in integer MICROCENTS.
--   $1.00 = 100,000,000 µ¢  (monthly_budget_microcents, spent_microcents)
-- Envelope encryption: provider key ciphertexts use AES-256-GCM with
-- tenant-bound AAD. The KMS master key is injected via KMS_MASTER_KEY_HEX.

BEGIN;

-- ============================================================================
-- 1. VIRTUAL KEYS  (Pillar 1 — scoped, governed LLM access tokens)
-- ============================================================================

CREATE TABLE IF NOT EXISTS virtual_keys (
    id                        UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                 UUID        NOT NULL,

    -- Primary key credential (SHA-256 hash of plaintext — never stored)
    key_hash                  TEXT        NOT NULL,
    key_prefix                TEXT        NOT NULL,  -- e.g. "vk-abc12" for display

    -- Rotation state machine (grace period lets old key remain valid during cutover)
    previous_key_hash         TEXT,
    previous_key_expires_at   TIMESTAMPTZ,

    -- Metadata
    name                      TEXT        NOT NULL,
    team_id                   TEXT        NOT NULL DEFAULT '',
    created_by                TEXT        NOT NULL DEFAULT '',
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at                TIMESTAMPTZ,

    -- Access controls
    allowed_ips               TEXT[]      NOT NULL DEFAULT '{}',

    -- Rate limits (0 = unlimited)
    max_rpm                   INT         NOT NULL DEFAULT 0,
    max_tpm                   INT         NOT NULL DEFAULT 0,
    max_concurrent_requests   INT         NOT NULL DEFAULT 0,

    -- Spend caps in MICROCENTS ($1 = 100,000,000 µ¢; 0 = unlimited)
    monthly_budget_microcents BIGINT      NOT NULL DEFAULT 0,
    spent_microcents          BIGINT      NOT NULL DEFAULT 0,

    -- Model & route allowlists
    allowed_models            TEXT[]      NOT NULL DEFAULT '{}',
    allowed_routes            TEXT[]      NOT NULL DEFAULT '{}',

    -- Lifecycle state: active | rotating | revoked
    status                    TEXT        NOT NULL DEFAULT 'active',

    -- Free-form operator metadata
    tags                      JSONB       NOT NULL DEFAULT '{}',

    CONSTRAINT virtual_keys_unique_hash_per_tenant
        UNIQUE (tenant_id, key_hash),

    CONSTRAINT virtual_keys_status_check
        CHECK (status IN ('active', 'rotating', 'revoked')),

    CONSTRAINT virtual_keys_spent_non_negative
        CHECK (spent_microcents >= 0),

    CONSTRAINT virtual_keys_budget_non_negative
        CHECK (monthly_budget_microcents >= 0)
);

-- Lookup by tenant (list / audit)
CREATE INDEX IF NOT EXISTS idx_virtual_keys_tenant
    ON virtual_keys (tenant_id);

-- Hot path: resolve by primary key hash
CREATE INDEX IF NOT EXISTS idx_virtual_keys_hash
    ON virtual_keys (key_hash);

-- Hot path: rotation grace-period fallback lookup
CREATE INDEX IF NOT EXISTS idx_virtual_keys_prev_hash
    ON virtual_keys (previous_key_hash)
    WHERE previous_key_hash IS NOT NULL;

-- Partial index: only active / rotating rows (skips revoked in key resolution queries)
CREATE INDEX IF NOT EXISTS idx_virtual_keys_active
    ON virtual_keys (tenant_id, status)
    WHERE status != 'revoked';

-- ============================================================================
-- 2. PROVIDER KEY VAULT  (Pillar 2 — encrypted per-tenant LLM provider keys)
-- ============================================================================

CREATE TABLE IF NOT EXISTS provider_keys (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,

    -- Provider identifier: "openai" | "anthropic" | "google" | "azure_openai" etc.
    provider        TEXT        NOT NULL,

    -- Human-readable alias (e.g. "production", "staging")
    key_alias       TEXT        NOT NULL DEFAULT '',

    -- AES-256-GCM ciphertext (hex-encoded); AAD = "{tenant_id}|{provider}|{key_alias}|{version}"
    key_ciphertext  TEXT        NOT NULL,

    -- Monotonically increasing version for AAD binding; incremented on each update
    version         INT         NOT NULL DEFAULT 1,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One active key per provider per tenant; UPSERT on conflict
    CONSTRAINT provider_keys_unique_per_tenant
        UNIQUE (tenant_id, provider)
);

-- Lookup by tenant (list endpoint)
CREATE INDEX IF NOT EXISTS idx_provider_keys_tenant
    ON provider_keys (tenant_id);

COMMIT;
