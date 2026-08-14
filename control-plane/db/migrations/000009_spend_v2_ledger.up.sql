-- Migration: 000009_spend_v2_ledger.up.sql
-- Purpose: Authoritative Central PostgreSQL Ledger for SMB LLM Spend Management

BEGIN;

-- 1. Spend Policies and Versioning
CREATE TABLE IF NOT EXISTS spend_policies (
    policy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('organization', 'project')),
    scope_id TEXT NOT NULL,
    currency TEXT NOT NULL DEFAULT 'USD' CHECK (currency = 'USD'),
    period_type TEXT NOT NULL CHECK (period_type IN ('daily', 'monthly')),
    limit_microcents BIGINT NOT NULL CHECK (limit_microcents >= 0),
    action TEXT NOT NULL CHECK (action IN ('hard_deny', 'warn', 'notify')),
    effective_from TIMESTAMPTZ NOT NULL DEFAULT now(),
    effective_to TIMESTAMPTZ NULL,
    status TEXT NOT NULL CHECK (status IN ('DRAFT', 'PUBLISHED', 'RETIRED')) DEFAULT 'DRAFT',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_spend_policy_scope UNIQUE (organization_id, scope_type, scope_id, period_type)
);

CREATE TABLE IF NOT EXISTS spend_policy_versions (
    policy_version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES spend_policies(policy_id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    snapshot_json JSONB NOT NULL,
    published_by TEXT NOT NULL,
    published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_spend_policy_version UNIQUE (policy_id, version)
);

-- 2. Budget Windows (Accounting Invariants & Optimistic Locking)
CREATE TABLE IF NOT EXISTS budget_windows (
    window_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    policy_version_id UUID NOT NULL REFERENCES spend_policy_versions(policy_version_id) ON DELETE RESTRICT,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    limit_microcents BIGINT NOT NULL CHECK (limit_microcents >= 0),
    reserved_microcents BIGINT NOT NULL DEFAULT 0 CHECK (reserved_microcents >= 0),
    settled_microcents BIGINT NOT NULL DEFAULT 0 CHECK (settled_microcents >= 0),
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_budget_window UNIQUE (organization_id, policy_version_id, window_start)
);

CREATE INDEX IF NOT EXISTS idx_budget_windows_lookup 
    ON budget_windows (organization_id, scope_type, scope_id, window_start, window_end);

-- 3. Price Book and Versioned Catalog (USD microcents per 1M tokens)
CREATE TABLE IF NOT EXISTS price_book_versions (
    price_book_version_id TEXT PRIMARY KEY,
    organization_id UUID NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_by TEXT NOT NULL,
    hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS price_book_items (
    item_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    price_book_version_id TEXT NOT NULL REFERENCES price_book_versions(price_book_version_id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    model_selector TEXT NOT NULL,
    input_rate_microcents_per_million BIGINT NOT NULL CHECK (input_rate_microcents_per_million >= 0),
    output_rate_microcents_per_million BIGINT NOT NULL CHECK (output_rate_microcents_per_million >= 0),
    cached_input_rate_microcents_per_million BIGINT NOT NULL DEFAULT 0 CHECK (cached_input_rate_microcents_per_million >= 0),
    effective_from TIMESTAMPTZ NOT NULL DEFAULT now(),
    effective_to TIMESTAMPTZ NULL,
    CONSTRAINT uq_price_book_item UNIQUE (price_book_version_id, provider, model_selector)
);

-- 4. Spend Reservations (Preflight Authorize State Machine)
CREATE TABLE IF NOT EXISTS spend_reservations (
    reservation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    request_id UUID NOT NULL,
    gateway_id TEXT NOT NULL,
    project_id TEXT NOT NULL DEFAULT 'default',
    state TEXT NOT NULL CHECK (state IN ('AUTHORIZED', 'ACTIVE', 'SETTLED', 'RELEASED', 'EXPIRED', 'REVERSED')) DEFAULT 'AUTHORIZED',
    reserved_microcents BIGINT NOT NULL CHECK (reserved_microcents >= 0),
    settled_microcents BIGINT NOT NULL DEFAULT 0 CHECK (settled_microcents >= 0),
    currency TEXT NOT NULL DEFAULT 'USD',
    expires_at TIMESTAMPTZ NOT NULL,
    policy_snapshot JSONB NOT NULL,
    price_book_version_id TEXT NOT NULL REFERENCES price_book_versions(price_book_version_id),
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    input_tokens_estimated BIGINT NOT NULL DEFAULT 0,
    max_output_tokens BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    settled_at TIMESTAMPTZ NULL,
    released_at TIMESTAMPTZ NULL,
    release_reason TEXT NULL,
    CONSTRAINT uq_spend_reservation_req UNIQUE (organization_id, request_id)
);

CREATE INDEX IF NOT EXISTS idx_spend_reservations_active 
    ON spend_reservations (organization_id, expires_at) 
    WHERE state IN ('AUTHORIZED', 'ACTIVE');

-- 5. Immutable Append-Only Spend Events Ledger
CREATE TABLE IF NOT EXISTS spend_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    reservation_id UUID NOT NULL REFERENCES spend_reservations(reservation_id) ON DELETE RESTRICT,
    request_id UUID NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('AUTHORIZED', 'SETTLED', 'RELEASED', 'REVERSED')),
    amount_microcents BIGINT NOT NULL,
    currency TEXT NOT NULL DEFAULT 'USD',
    usage_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    provider_request_id TEXT NULL,
    actor TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_spend_events_org_occurred 
    ON spend_events (organization_id, occurred_at DESC);

-- 6. Idempotency Records for Gateway Spend Operations
CREATE TABLE IF NOT EXISTS spend_idempotency (
    organization_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    response_json JSONB NOT NULL,
    response_status SMALLINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, operation, idempotency_key)
);

-- 7. Spend Increase Requests
CREATE TABLE IF NOT EXISTS spend_v2_increase_requests (
    request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    requested_limit_microcents BIGINT NOT NULL CHECK (requested_limit_microcents > 0),
    current_limit_microcents BIGINT NOT NULL CHECK (current_limit_microcents >= 0),
    reason TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')) DEFAULT 'PENDING',
    created_by TEXT NOT NULL,
    decided_by TEXT NULL,
    decision_reason TEXT NULL,
    resulting_policy_version_id UUID NULL REFERENCES spend_policy_versions(policy_version_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at TIMESTAMPTZ NULL
);

-- 8. Seed Default Audited Price Book v1 (USD microcents per 1M tokens)
-- Rates: 1 USD = 100,000,000 microcents
INSERT INTO price_book_versions (price_book_version_id, source, published_by, hash)
VALUES (
    'price-book-v1',
    'OpenAI Official Pricing Standard (August 2026)',
    'system_seed',
    'sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069'
) ON CONFLICT (price_book_version_id) DO NOTHING;

INSERT INTO price_book_items (
    price_book_version_id, provider, model_selector, 
    input_rate_microcents_per_million, output_rate_microcents_per_million, cached_input_rate_microcents_per_million
) VALUES 
('price-book-v1', 'openai', 'gpt-4o', 250000000, 1000000000, 125000000),
('price-book-v1', 'openai', 'gpt-4o-mini', 15000000, 60000000, 7500000),
('price-book-v1', 'openai', 'gpt-3.5-turbo', 50000000, 150000000, 25000000),
('price-book-v1', 'openai', 'gpt-4-turbo', 1000000000, 3000000000, 500000000),
('price-book-v1', 'openai', 'o1', 1500000000, 6000000000, 750000000),
('price-book-v1', 'openai', 'o3-mini', 110000000, 440000000, 55000000)
ON CONFLICT (price_book_version_id, provider, model_selector) DO NOTHING;

COMMIT;
