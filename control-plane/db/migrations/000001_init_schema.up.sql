-- Migration: 000001_init_schema.up.sql
-- Vexa Agent Control — Unified Enterprise Single-Tenant Baseline Schema
-- Fresh dataset baseline with Organization, Team, Workspace, and Zero-Trust Governance.

BEGIN;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- 1. CORE ENUMS
-- ============================================================================
CREATE TYPE event_decision    AS ENUM ('allowed', 'denied', 'warned');
CREATE TYPE alert_severity    AS ENUM ('info', 'warning', 'critical');
CREATE TYPE agent_status      AS ENUM ('active', 'inactive', 'revoked');
CREATE TYPE device_state      AS ENUM ('PENDING', 'COMPLIANT', 'NON_COMPLIANT', 'REVOKED');
CREATE TYPE credential_status AS ENUM ('ACTIVE', 'EXPIRING_SOON', 'EXPIRED', 'REVOKED');
CREATE TYPE token_status      AS ENUM ('ACTIVE', 'CONSUMED', 'REVOKED', 'EXPIRED');

-- ============================================================================
-- 2. ORGANIZATIONS & TEAMS
-- ============================================================================

CREATE TABLE organizations (
    id                   UUID PRIMARY KEY DEFAULT '00000000-0000-0000-0000-000000000001'::uuid,
    name                 TEXT NOT NULL DEFAULT 'Primary Organization',
    slug                 TEXT NOT NULL DEFAULT 'default',
    contact_email        TEXT NOT NULL DEFAULT '',
    license_tier         TEXT NOT NULL DEFAULT 'team',      -- "developer", "team", "enterprise"
    license_key_jwt      TEXT,
    max_devices          INT NOT NULL DEFAULT 50,           -- Enterprise default
    license_expires_at   TIMESTAMPTZ,
    status               TEXT NOT NULL DEFAULT 'active',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE teams (
    id              TEXT PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- 3. AUTHENTICATION & USERS
-- ============================================================================

CREATE TABLE auth_providers (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    type              TEXT NOT NULL, -- 'local', 'oidc', 'saml'
    issuer_url        TEXT,
    client_id         TEXT,
    client_secret     TEXT,
    enabled           BOOLEAN NOT NULL DEFAULT true,
    email_domains     TEXT[] NOT NULL DEFAULT '{}',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_auth_provider_org_type UNIQUE (organization_id, type)
);

CREATE TABLE users (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    auth_provider_id  UUID REFERENCES auth_providers(id) ON DELETE SET NULL,
    email             TEXT NOT NULL,
    password_hash     TEXT,
    is_admin          BOOLEAN NOT NULL DEFAULT false,
    role              TEXT NOT NULL DEFAULT 'ADMIN' CHECK (role IN ('OWNER', 'ADMIN', 'MEMBER', 'VIEWER')),
    provider_subject  TEXT,
    provider_issuer   TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_users_org_email UNIQUE (organization_id, email)
);

CREATE INDEX idx_users_email_lower ON users (LOWER(email));
CREATE UNIQUE INDEX uq_users_org_provider_subject 
    ON users (organization_id, auth_provider_id, provider_subject) 
    WHERE provider_subject IS NOT NULL;

CREATE TABLE user_identities (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id    UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider_id        UUID NOT NULL REFERENCES auth_providers(id) ON DELETE CASCADE,
    identity_issuer    TEXT NOT NULL,
    identity_subject   TEXT NOT NULL,
    identity_email     TEXT,
    email_verified     BOOLEAN NOT NULL DEFAULT false,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_user_identity_org_provider_issuer_subject 
        UNIQUE (organization_id, provider_id, identity_issuer, identity_subject)
);

CREATE INDEX idx_user_identities_lookup 
    ON user_identities(organization_id, provider_id, identity_issuer, identity_subject);
CREATE INDEX idx_user_identities_user 
    ON user_identities(user_id);

CREATE TABLE team_memberships (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id    UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id            TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role               TEXT NOT NULL DEFAULT 'MEMBER',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_team_membership UNIQUE (team_id, user_id)
);

CREATE INDEX idx_team_memberships_user ON team_memberships(user_id);

-- ============================================================================
-- 4. FLEET DEVICES & GOVERNANCE
-- ============================================================================

CREATE TABLE devices (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id                TEXT REFERENCES teams(id) ON DELETE SET NULL,
    user_id                UUID REFERENCES users(id) ON DELETE SET NULL,
    stable_device_id       TEXT NOT NULL UNIQUE,
    display_name           TEXT NOT NULL DEFAULT '',
    owner_subject          TEXT,
    os_family              TEXT NOT NULL DEFAULT 'windows',
    architecture           TEXT NOT NULL DEFAULT 'x86_64',
    os_version_summary     TEXT,
    daemon_version         TEXT DEFAULT '2.1.0',
    public_key             TEXT,
    key_fingerprint        TEXT,
    bound_at               TIMESTAMPTZ,
    identity_source        TEXT NOT NULL DEFAULT 'local_os',
    identity_verified      BOOLEAN NOT NULL DEFAULT false,
    state                  device_state NOT NULL DEFAULT 'PENDING',
    capability_vector      JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_freshness         VARCHAR(32) NOT NULL DEFAULT 'STALE',
    verified_target_states JSONB NOT NULL DEFAULT '{}'::jsonb,
    state_reason_code      TEXT,
    state_changed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_enrolled_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_heartbeat_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at             TIMESTAMPTZ,
    revocation_reason      TEXT,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_devices_org_state ON devices(organization_id, state);
CREATE INDEX idx_devices_org_team ON devices(organization_id, team_id);
CREATE INDEX idx_devices_heartbeat ON devices(last_heartbeat_at DESC);
CREATE INDEX idx_devices_user_id ON devices(user_id);
CREATE UNIQUE INDEX uq_device_active_fingerprint ON devices(key_fingerprint)
    WHERE state != 'REVOKED' AND key_fingerprint IS NOT NULL;

CREATE TABLE device_keys (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id        TEXT NOT NULL,
    public_key_bytes TEXT NOT NULL,
    algorithm        VARCHAR(32) NOT NULL DEFAULT 'Ed25519',
    status           VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at       TIMESTAMPTZ
);

CREATE INDEX idx_device_keys_lookup ON device_keys(device_id, status);
CREATE INDEX idx_device_keys_org ON device_keys(organization_id, device_id);

CREATE TABLE enrollment_tokens (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id               TEXT NOT NULL DEFAULT 'default' REFERENCES teams(id) ON DELETE CASCADE,
    token_hash            BYTEA NOT NULL,
    token_hint            TEXT NOT NULL,
    status                token_status NOT NULL DEFAULT 'ACTIVE',
    max_uses              INT NOT NULL DEFAULT 1,
    current_uses          INT NOT NULL DEFAULT 0,
    expected_device_label TEXT,
    target_owner_subject  TEXT,
    reason                TEXT NOT NULL DEFAULT 'Device enrollment',
    created_by_subject    TEXT NOT NULL DEFAULT 'admin',
    expires_at            TIMESTAMPTZ NOT NULL,
    consumed_at           TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE enrollment_transactions (
    id                            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id               UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    enrollment_token_id           UUID REFERENCES enrollment_tokens(id) ON DELETE SET NULL,
    stable_device_id              TEXT NOT NULL,
    display_name                  TEXT,
    owner_subject                 TEXT,
    enrollment_ed25519_public_key BYTEA,
    enrollment_key_fingerprint    TEXT NOT NULL,
    mtls_csr_sha256               TEXT,
    mtls_csr_pem                  TEXT,
    os_family                     TEXT,
    architecture                  TEXT,
    os_version_summary            TEXT,
    status                        TEXT NOT NULL DEFAULT 'CHALLENGE_ISSUED',
    failure_code                  TEXT,
    expires_at                    TIMESTAMPTZ NOT NULL,
    completed_at                  TIMESTAMPTZ,
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_enrollment_tx UNIQUE (organization_id, stable_device_id, enrollment_key_fingerprint)
);

CREATE TABLE enrollment_challenges (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    transaction_id    UUID NOT NULL REFERENCES enrollment_transactions(id) ON DELETE CASCADE,
    challenge_hash    BYTEA NOT NULL,
    transcript_sha256 TEXT NOT NULL DEFAULT '',
    expires_at        TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE device_certificates (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id              UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    serial_number          TEXT NOT NULL UNIQUE,
    certificate_pem        TEXT NOT NULL,
    status                 credential_status NOT NULL DEFAULT 'ACTIVE',
    ca_resource_name       TEXT,
    certificate_fingerprint TEXT,
    sha256_fingerprint     TEXT,
    csr_sha256             TEXT,
    public_key_fingerprint TEXT,
    renew_after            TIMESTAMPTZ,
    not_before             TIMESTAMPTZ NOT NULL,
    not_after              TIMESTAMPTZ NOT NULL,
    issued_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at             TIMESTAMPTZ,
    revocation_reason      TEXT
);

CREATE INDEX idx_device_certs_device ON device_certificates(device_id);

CREATE TABLE device_compliance_reports (
    report_id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id                 UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE UNIQUE,
    overall_compliance        TEXT NOT NULL DEFAULT 'COMPLIANT',
    tamper_event_count_24h    INT NOT NULL DEFAULT 0,
    mcp_servers_total         INT NOT NULL DEFAULT 0,
    mcp_servers_wrapped       INT NOT NULL DEFAULT 0,
    report_payload            JSONB NOT NULL DEFAULT '[]'::jsonb,
    reported_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_compliance_reports_device ON device_compliance_reports(device_id);

CREATE TABLE device_tamper_logs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id         TEXT NOT NULL,
    target_ide        TEXT NOT NULL,
    detected_diff     TEXT NOT NULL,
    action_taken      TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_device_tamper_time ON device_tamper_logs(created_at DESC);

CREATE TABLE oauth_refresh_tokens (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    family_id          UUID NOT NULL,
    parent_token_id    UUID REFERENCES oauth_refresh_tokens(id),
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id    UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id            TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    device_id          UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    token_hash         TEXT NOT NULL UNIQUE,
    consumed_at        TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ,
    expires_at         TIMESTAMPTZ NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_refresh_tokens_family ON oauth_refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_active_lookup ON oauth_refresh_tokens(token_hash) 
    WHERE revoked_at IS NULL AND consumed_at IS NULL;

-- ============================================================================
-- 5. VIRTUAL KEYS & PROVIDER VAULT
-- ============================================================================

CREATE TABLE virtual_keys (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id                   TEXT NOT NULL DEFAULT 'default' REFERENCES teams(id) ON DELETE CASCADE,
    workspace_id              TEXT NOT NULL DEFAULT 'default',
    key_hash                  TEXT NOT NULL UNIQUE,
    key_prefix                TEXT NOT NULL,
    previous_key_hash         TEXT,
    previous_key_expires_at   TIMESTAMPTZ,
    name                      TEXT NOT NULL,
    created_by                TEXT NOT NULL DEFAULT 'admin',
    allowed_ips               TEXT[] NOT NULL DEFAULT '{}',
    max_rpm                   INT NOT NULL DEFAULT 0,
    max_tpm                   INT NOT NULL DEFAULT 0,
    max_concurrent_requests   INT NOT NULL DEFAULT 0,
    monthly_budget_microcents BIGINT NOT NULL DEFAULT 0 CHECK (monthly_budget_microcents >= 0),
    spent_microcents          BIGINT NOT NULL DEFAULT 0 CHECK (spent_microcents >= 0),
    allowed_models            TEXT[] NOT NULL DEFAULT '{}',
    allowed_routes            TEXT[] NOT NULL DEFAULT '{}',
    status                    TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'rotating', 'revoked')),
    tags                      JSONB NOT NULL DEFAULT '{}',
    owner_type                TEXT NOT NULL DEFAULT 'user',
    budget_period             TEXT NOT NULL DEFAULT 'monthly',
    deleted_at                TIMESTAMPTZ,
    deleted_by                TEXT,
    deleted_reason            TEXT,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at                TIMESTAMPTZ
);

CREATE INDEX idx_virtual_keys_status ON virtual_keys(status) WHERE status != 'revoked';
CREATE INDEX idx_virtual_keys_org_team ON virtual_keys(organization_id, team_id);
CREATE INDEX idx_virtual_keys_org_ws ON virtual_keys(organization_id, workspace_id);

CREATE TABLE provider_keys (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider          TEXT NOT NULL,
    key_alias         TEXT NOT NULL DEFAULT 'default',
    version           INT NOT NULL DEFAULT 1,
    status            TEXT NOT NULL DEFAULT 'ACTIVE',
    api_key_masked    TEXT NOT NULL DEFAULT '',
    api_key_encrypted TEXT NOT NULL DEFAULT '',
    is_default        BOOLEAN NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_provider_alias UNIQUE (organization_id, provider, key_alias)
);

-- ============================================================================
-- 6. POLICIES & TEMPLATES
-- ============================================================================

CREATE TABLE policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id    TEXT NOT NULL DEFAULT 'default',
    version         TEXT NOT NULL,
    content         TEXT NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_policies_org_version UNIQUE (organization_id, version)
);

CREATE UNIQUE INDEX idx_policies_active_unique ON policies (organization_id, is_active) WHERE is_active = true;
CREATE INDEX idx_policies_org_ws ON policies(organization_id, workspace_id);

CREATE TABLE policy_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    version         INT NOT NULL,
    mode            TEXT NOT NULL CHECK (mode IN ('AUDIT_ONLY', 'SAFE_MODE', 'TEAM_ENFORCE', 'LOCKDOWN')),
    policy_content  TEXT NOT NULL,
    sha256_hash     TEXT NOT NULL,
    signature_b64   TEXT NOT NULL,
    signer_key_id   TEXT NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_policy_versions_org_ver UNIQUE (organization_id, version)
);

CREATE TABLE group_policy_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id         TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    version         INT NOT NULL,
    claims          JSONB NOT NULL DEFAULT '[]'::jsonb,
    tools           JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_by      TEXT NOT NULL DEFAULT 'system',
    active          BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_team_policy_version UNIQUE (organization_id, team_id, version)
);

CREATE TABLE policy_templates (
    id              TEXT PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    category        TEXT NOT NULL,
    description     TEXT NOT NULL,
    tags            TEXT[] NOT NULL DEFAULT '{}',
    icon            TEXT NOT NULL DEFAULT 'shield',
    content         TEXT NOT NULL,
    is_custom       BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- 7. AUTHORITATIVE SPEND LEDGER
-- ============================================================================

CREATE TABLE price_book_versions (
    price_book_version_id TEXT PRIMARY KEY,
    source                TEXT NOT NULL DEFAULT 'system',
    published_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_by          TEXT NOT NULL DEFAULT 'system',
    hash                  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE price_book_items (
    item_id                                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    price_book_version_id                    TEXT NOT NULL REFERENCES price_book_versions(price_book_version_id) ON DELETE CASCADE,
    provider                                 TEXT NOT NULL,
    model_selector                           TEXT NOT NULL,
    input_rate_microcents_per_million        BIGINT NOT NULL CHECK (input_rate_microcents_per_million >= 0),
    output_rate_microcents_per_million       BIGINT NOT NULL CHECK (output_rate_microcents_per_million >= 0),
    cached_input_rate_microcents_per_million BIGINT NOT NULL DEFAULT 0 CHECK (cached_input_rate_microcents_per_million >= 0),
    created_at                               TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_price_book_item UNIQUE (price_book_version_id, provider, model_selector)
);

CREATE TABLE spend_policies (
    policy_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id     TEXT NOT NULL DEFAULT 'default',
    scope_type       VARCHAR(32) NOT NULL DEFAULT 'organization',
    scope_id         VARCHAR(128) NOT NULL DEFAULT 'global',
    currency         VARCHAR(8) NOT NULL DEFAULT 'USD',
    period_type      VARCHAR(16) NOT NULL DEFAULT 'monthly',
    limit_microcents BIGINT NOT NULL,
    action           VARCHAR(32) NOT NULL DEFAULT 'hard_deny',
    effective_from   TIMESTAMPTZ NOT NULL DEFAULT now(),
    effective_to     TIMESTAMPTZ,
    status           VARCHAR(16) NOT NULL DEFAULT 'PUBLISHED',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_spend_policy_scope UNIQUE (organization_id, scope_type, scope_id, period_type)
);

CREATE INDEX idx_spend_policies_org_ws ON spend_policies(organization_id, workspace_id);

CREATE TABLE spend_policy_versions (
    policy_version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id         UUID NOT NULL REFERENCES spend_policies(policy_id) ON DELETE CASCADE,
    version           INT NOT NULL,
    snapshot_json     JSONB NOT NULL,
    published_by      VARCHAR(128) NOT NULL DEFAULT 'system',
    published_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_spend_policy_version UNIQUE (policy_id, version)
);

CREATE TABLE budget_windows (
    window_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    policy_version_id   UUID NOT NULL REFERENCES spend_policy_versions(policy_version_id) ON DELETE CASCADE,
    scope_type          VARCHAR(32) NOT NULL,
    scope_id            VARCHAR(128) NOT NULL,
    window_start        TIMESTAMPTZ NOT NULL,
    window_end          TIMESTAMPTZ NOT NULL,
    limit_microcents    BIGINT NOT NULL,
    reserved_microcents BIGINT NOT NULL DEFAULT 0,
    settled_microcents  BIGINT NOT NULL DEFAULT 0,
    version             BIGINT NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_budget_window UNIQUE (organization_id, policy_version_id, window_start),
    CONSTRAINT chk_window_bounds CHECK (window_end > window_start)
);

CREATE TABLE spend_reservations (
    reservation_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    request_id             VARCHAR(128) NOT NULL UNIQUE,
    gateway_id             VARCHAR(128) NOT NULL,
    project_id             VARCHAR(128) NOT NULL DEFAULT 'default',
    team_id                TEXT REFERENCES teams(id) ON DELETE SET NULL,
    virtual_key_id         UUID REFERENCES virtual_keys(id) ON DELETE SET NULL,
    virtual_key_hash       TEXT,
    virtual_key_prefix     TEXT,
    virtual_key_alias      TEXT,
    session_id             TEXT,
    internal_user_id       TEXT,
    end_user_id            TEXT,
    request_type           TEXT NOT NULL DEFAULT 'LLM',
    status_code            INT NOT NULL DEFAULT 200,
    ttft_ms                INT NOT NULL DEFAULT 0,
    input_tokens           BIGINT NOT NULL DEFAULT 0,
    output_tokens          BIGINT NOT NULL DEFAULT 0,
    cached_tokens          BIGINT NOT NULL DEFAULT 0,
    state                  VARCHAR(32) NOT NULL DEFAULT 'AUTHORIZED',
    reserved_microcents    BIGINT NOT NULL,
    settled_microcents     BIGINT NOT NULL DEFAULT 0,
    currency               VARCHAR(8) NOT NULL DEFAULT 'USD',
    expires_at             TIMESTAMPTZ NOT NULL,
    policy_snapshot        JSONB NOT NULL DEFAULT '[]'::jsonb,
    price_book_version_id  VARCHAR(64) NOT NULL,
    provider               VARCHAR(64) NOT NULL,
    model                  VARCHAR(128) NOT NULL,
    input_tokens_estimated BIGINT NOT NULL DEFAULT 0,
    max_output_tokens      BIGINT NOT NULL DEFAULT 0,
    tags                   JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    settled_at             TIMESTAMPTZ,
    released_at            TIMESTAMPTZ,
    release_reason         VARCHAR(64)
);

CREATE INDEX idx_spend_reservations_created ON spend_reservations(organization_id, created_at DESC);
CREATE INDEX idx_spend_reservations_session ON spend_reservations(organization_id, session_id) WHERE session_id IS NOT NULL;
CREATE INDEX idx_spend_reservations_vk ON spend_reservations(organization_id, virtual_key_id) WHERE virtual_key_id IS NOT NULL;

CREATE TABLE spend_events (
    event_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    reservation_id      UUID REFERENCES spend_reservations(reservation_id) ON DELETE SET NULL,
    request_id          VARCHAR(128) NOT NULL,
    event_type          VARCHAR(32) NOT NULL,
    amount_microcents   BIGINT NOT NULL,
    currency            VARCHAR(8) NOT NULL DEFAULT 'USD',
    usage_json          JSONB NOT NULL DEFAULT '{}'::jsonb,
    provider_request_id VARCHAR(128),
    actor               VARCHAR(128) NOT NULL,
    reason_code         VARCHAR(64) NOT NULL,
    occurred_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_spend_events_org_time ON spend_events(organization_id, occurred_at DESC);

CREATE TABLE spend_idempotency (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    operation       VARCHAR(32) NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    payload_hash    VARCHAR(64) NOT NULL,
    response_json   JSONB NOT NULL,
    response_status INT NOT NULL DEFAULT 200,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organization_id, operation, idempotency_key)
);

CREATE TABLE spend_v2_increase_requests (
    request_id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id             UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id                  VARCHAR(128) NOT NULL DEFAULT 'default',
    requested_limit_microcents  BIGINT NOT NULL,
    current_limit_microcents    BIGINT NOT NULL DEFAULT 0,
    reason                      TEXT NOT NULL,
    status                      VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    created_by                  VARCHAR(128) NOT NULL,
    decided_by                  VARCHAR(128),
    decision_reason             TEXT,
    resulting_policy_version_id UUID REFERENCES spend_policy_versions(policy_version_id) ON DELETE SET NULL,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at                  TIMESTAMPTZ
);

-- ============================================================================
-- 8. BROKER & ROUTING ENGINE (P0 CORE)
-- ============================================================================

CREATE TABLE route_profiles (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id          TEXT NOT NULL DEFAULT 'default',
    name                  TEXT NOT NULL,
    version               INT NOT NULL DEFAULT 1,
    content_digest        TEXT NOT NULL,
    api_family            TEXT NOT NULL DEFAULT 'chat_completions',
    match_model           TEXT NOT NULL DEFAULT '*',
    primary_provider      TEXT NOT NULL,
    primary_model         TEXT NOT NULL,
    fallback_provider     TEXT,
    fallback_model        TEXT,
    max_attempts          INT NOT NULL DEFAULT 2 CHECK (max_attempts BETWEEN 1 AND 2),
    deadline_ms           INT NOT NULL DEFAULT 30000,
    retry_classes         TEXT[] NOT NULL DEFAULT ARRAY['502', '503', '504', '429', 'connect_timeout', 'dns_error'],
    allowed_regions       TEXT[] NOT NULL DEFAULT ARRAY['*'],
    is_active             BOOLEAN NOT NULL DEFAULT false,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by            TEXT NOT NULL DEFAULT 'system',
    CONSTRAINT uq_route_profile_org_digest UNIQUE (organization_id, content_digest)
);

CREATE INDEX idx_route_profiles_org_active ON route_profiles(organization_id, is_active);
CREATE INDEX idx_route_profiles_lookup ON route_profiles(organization_id, api_family, match_model);
CREATE INDEX idx_route_profiles_org_ws ON route_profiles(organization_id, workspace_id);

CREATE TABLE route_profile_activations (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id             UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    route_profile_id            UUID NOT NULL REFERENCES route_profiles(id) ON DELETE CASCADE,
    version                     INT NOT NULL,
    content_digest              TEXT NOT NULL,
    activated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_by                TEXT NOT NULL DEFAULT 'system',
    reason                      TEXT NOT NULL DEFAULT 'admin_activation',
    rollback_from_activation_id UUID REFERENCES route_profile_activations(id)
);

CREATE INDEX idx_route_activations_org ON route_profile_activations(organization_id, activated_at DESC);

CREATE TABLE broker_requests (
    request_id                 TEXT PRIMARY KEY,
    organization_id            UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id               TEXT NOT NULL DEFAULT 'default',
    idempotency_key            TEXT,
    trace_id                   TEXT,
    principal_device_id        TEXT,
    principal_user_id          TEXT,
    route_profile_id           UUID REFERENCES route_profiles(id),
    policy_version_id          TEXT,
    requested_provider         TEXT NOT NULL,
    requested_model            TEXT NOT NULL,
    stream                     BOOLEAN NOT NULL DEFAULT false,
    status                     TEXT NOT NULL DEFAULT 'admitted',
    terminal_reason_code       TEXT,
    spend_reservation_id       TEXT,
    settled_microcents         BIGINT NOT NULL DEFAULT 0,
    request_hash               TEXT,
    cached_response            JSONB,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at               TIMESTAMPTZ
);

CREATE INDEX idx_broker_requests_org_created ON broker_requests(organization_id, created_at DESC);
CREATE INDEX idx_broker_requests_idempotency ON broker_requests(organization_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX idx_broker_requests_trace ON broker_requests(trace_id) WHERE trace_id IS NOT NULL;
CREATE INDEX idx_broker_requests_org_ws ON broker_requests(organization_id, workspace_id, created_at DESC);

CREATE TABLE broker_attempts (
    attempt_id                 TEXT PRIMARY KEY,
    request_id                 TEXT NOT NULL REFERENCES broker_requests(request_id) ON DELETE CASCADE,
    attempt_number             INT NOT NULL CHECK (attempt_number BETWEEN 1 AND 2),
    target_type                TEXT NOT NULL CHECK (target_type IN ('primary', 'fallback')),
    provider                   TEXT NOT NULL,
    model                      TEXT NOT NULL,
    started_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at               TIMESTAMPTZ,
    latency_ms                 INT NOT NULL DEFAULT 0,
    http_status                INT NOT NULL DEFAULT 0,
    error_class                TEXT,
    error_message_redacted     TEXT,
    stream_committed           BOOLEAN NOT NULL DEFAULT false,
    input_tokens               BIGINT NOT NULL DEFAULT 0,
    output_tokens              BIGINT NOT NULL DEFAULT 0,
    cached_tokens              BIGINT NOT NULL DEFAULT 0,
    usage_source               TEXT NOT NULL DEFAULT 'provider_reported',
    CONSTRAINT uq_broker_attempt_req_num UNIQUE (request_id, attempt_number)
);

CREATE INDEX idx_broker_attempts_req_num ON broker_attempts(request_id, attempt_number ASC);

CREATE TABLE broker_admissions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id         TEXT NOT NULL UNIQUE,
    organization_id    UUID NOT NULL REFERENCES organizations(id),
    team_id            TEXT NOT NULL,
    user_id            UUID NOT NULL REFERENCES users(id),
    device_id          UUID NOT NULL REFERENCES devices(id),
    credential_id      TEXT NOT NULL,
    policy_version     TEXT NOT NULL,
    provider           TEXT NOT NULL,
    model              TEXT NOT NULL,
    estimated_cost     NUMERIC(12, 6) DEFAULT 0,
    settled_cost       NUMERIC(12, 6) DEFAULT 0,
    status             TEXT NOT NULL,
    admitted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    settled_at         TIMESTAMPTZ
);

CREATE INDEX idx_broker_admissions_user ON broker_admissions(user_id, admitted_at DESC);
CREATE INDEX idx_broker_admissions_team ON broker_admissions(team_id, admitted_at DESC);

-- ============================================================================
-- 9. OBSERVABILITY, AUDIT & ASSIGNMENTS
-- ============================================================================

CREATE TABLE telemetry_events (
    event_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id    UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id       TEXT NOT NULL DEFAULT 'default',
    timestamp_ms       BIGINT NOT NULL,
    session_id         TEXT NOT NULL,
    agent_id           TEXT NOT NULL,
    tool_name          TEXT NOT NULL,
    decision           event_decision NOT NULL,
    dlp_findings       JSONB NOT NULL DEFAULT '[]',
    injection_findings JSONB NOT NULL DEFAULT '[]',
    semantic_findings  JSONB NOT NULL DEFAULT '[]',
    event_hash         TEXT,
    prev_event_hash    TEXT,
    sequence_number    BIGINT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_telemetry_org_time ON telemetry_events(organization_id, timestamp_ms DESC);
CREATE INDEX idx_telemetry_agent ON telemetry_events(agent_id, timestamp_ms DESC);

CREATE TABLE alerts (
    alert_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    severity        alert_severity NOT NULL,
    event_id        UUID NOT NULL REFERENCES telemetry_events(event_id) ON DELETE CASCADE,
    pattern_name    TEXT,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_alerts_org_time ON alerts(organization_id, created_at DESC);

CREATE TABLE audit_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id    TEXT NOT NULL DEFAULT 'default',
    correlation_id  UUID,
    request_id      UUID,
    action          TEXT NOT NULL,
    actor_type      TEXT,
    actor_ref       TEXT,
    actor_subject   TEXT,
    actor_role      TEXT,
    resource_type   TEXT,
    resource_id     TEXT,
    outcome         TEXT,
    reason_code     TEXT,
    target_type     TEXT,
    target_id       TEXT,
    diff_json       JSONB NOT NULL DEFAULT '{}',
    ip_address      TEXT,
    event_hash      TEXT,
    prev_event_hash TEXT,
    sequence_number BIGINT,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_events_org_time ON audit_events(organization_id, occurred_at DESC);
CREATE INDEX idx_audit_events_resource ON audit_events(organization_id, resource_type, occurred_at DESC);
CREATE INDEX idx_audit_events_action ON audit_events(organization_id, action, occurred_at DESC);
CREATE INDEX idx_audit_events_org_ws_time ON audit_events(organization_id, workspace_id, occurred_at DESC);

CREATE TABLE audit_checkpoints (
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

CREATE INDEX idx_audit_checkpoints_org_seq ON audit_checkpoints(organization_id, sequence_end DESC);

CREATE TABLE mcp_servers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id        TEXT NOT NULL,
    ide_target      TEXT NOT NULL DEFAULT 'cursor',
    server_name     TEXT NOT NULL,
    wrapped         BOOLEAN NOT NULL DEFAULT false,
    path_verified   BOOLEAN NOT NULL DEFAULT false,
    command         TEXT,
    tools_count     INT NOT NULL DEFAULT 0,
    tools_list      JSONB NOT NULL DEFAULT '[]',
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_mcp_server UNIQUE (organization_id, agent_id, ide_target, server_name)
);

CREATE TABLE idempotency_records (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    principal_ref         TEXT NOT NULL,
    route                 TEXT NOT NULL,
    idempotency_key       TEXT NOT NULL,
    canonical_body_sha256 TEXT NOT NULL,
    response_status       INT NOT NULL,
    response_reference    TEXT,
    expires_at            TIMESTAMPTZ NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_idempotency_record UNIQUE (organization_id, principal_ref, route, idempotency_key)
);

CREATE TABLE assignments (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id             UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_type                 TEXT NOT NULL, -- 'device', 'user', 'group'
    target_id                   TEXT NOT NULL,
    kind                        TEXT NOT NULL, -- 'policy', 'provider_keys', 'cursor_mode', 'llm_profile'
    payload_ref                 TEXT NOT NULL,
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

CREATE INDEX idx_assignments_org_target ON assignments(organization_id, target_type, target_id);
CREATE INDEX idx_assignments_state ON assignments(state);
CREATE INDEX idx_assignments_updated ON assignments(updated_at DESC);

CREATE TABLE request_attributions (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id        TEXT NOT NULL,
    organization_id   UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id         TEXT NOT NULL,
    user_id           TEXT NOT NULL,
    identity_source   TEXT NOT NULL DEFAULT 'local_os',
    identity_verified BOOLEAN NOT NULL DEFAULT false,
    assignment_id     UUID REFERENCES assignments(id) ON DELETE SET NULL,
    provider          TEXT NOT NULL,
    model             TEXT NOT NULL,
    status_code       INT NOT NULL DEFAULT 200,
    input_tokens      BIGINT NOT NULL DEFAULT 0,
    output_tokens     BIGINT NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_attributions_org_created ON request_attributions(organization_id, created_at DESC);
CREATE INDEX idx_attributions_device ON request_attributions(device_id, created_at DESC);
CREATE INDEX idx_attributions_user ON request_attributions(organization_id, user_id, created_at DESC);
CREATE INDEX idx_attributions_assignment ON request_attributions(assignment_id);

CREATE TABLE identity_credentials (
    credential_id      TEXT PRIMARY KEY,
    organization_id    UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id           TEXT NOT NULL,
    scope              TEXT NOT NULL DEFAULT '',
    ttl_seconds        INT NOT NULL DEFAULT 3600,
    created_at_ms      BIGINT NOT NULL DEFAULT 0,
    expires_at_ms      BIGINT NOT NULL DEFAULT 0,
    last_rotated_at_ms BIGINT NOT NULL DEFAULT 0,
    rotation_history   JSONB NOT NULL DEFAULT '[]',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE agents (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id        TEXT PRIMARY KEY,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- 10. PRISTINE CANONICAL SEED DATA
-- ============================================================================

-- 1. Seed Primary Organization
INSERT INTO organizations (id, name, slug, contact_email, license_tier, max_devices, status)
VALUES ('00000000-0000-0000-0000-000000000001', 'Primary Organization', 'default', '', 'enterprise', 100, 'active')
ON CONFLICT (id) DO NOTHING;

-- 2. Seed Default Team
INSERT INTO teams (id, organization_id, name, description)
VALUES ('default', '00000000-0000-0000-0000-000000000001', 'Default Team', 'Default team for enrolled developer workstations, virtual keys, and routing profiles')
ON CONFLICT (id) DO NOTHING;

-- 3. Seed Local Password Auth Provider
INSERT INTO auth_providers (id, organization_id, name, type, enabled)
VALUES ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001', 'Local Password Authentication', 'local', true)
ON CONFLICT (organization_id, type) DO NOTHING;

-- 4. Seed Default Active Policy (v1.0.0)
INSERT INTO policies (id, organization_id, workspace_id, version, content, is_active)
VALUES (
    '00000000-0000-0000-0000-000000000004',
    '00000000-0000-0000-0000-000000000001',
    'default',
    '1.0.0',
    E'version: "1.0.0"\ndefault_action: deny\nenforce_safe_mode: true\n\nrules:\n  - name: allow_read_ops\n    action: allow\n    tools:\n      - "fs:read_file"\n      - "fs:list_dir"\n  - name: deny_secret_access\n    action: deny\n    tools:\n      - "env:get_var"\n    parameters:\n      name: "*KEY*"\n',
    true
)
ON CONFLICT (organization_id, version) DO NOTHING;

-- 5. Seed Default Active Price Book Version & Items (NO legacy price_books table)
INSERT INTO price_book_versions (price_book_version_id, source, published_by, hash)
VALUES ('pb_default_2026_01', 'system', 'system', 'default_hash')
ON CONFLICT (price_book_version_id) DO NOTHING;

INSERT INTO price_book_items (price_book_version_id, provider, model_selector, input_rate_microcents_per_million, output_rate_microcents_per_million, cached_input_rate_microcents_per_million)
VALUES
    ('pb_default_2026_01', 'openai', 'gpt-4o', 250000000, 1000000000, 125000000),
    ('pb_default_2026_01', 'openai', 'gpt-4o-mini', 15000000, 60000000, 7500000),
    ('pb_default_2026_01', 'openai', '*', 250000000, 1000000000, 125000000),
    ('pb_default_2026_01', 'anthropic', 'claude-3-5-sonnet', 300000000, 1500000000, 150000000),
    ('pb_default_2026_01', 'anthropic', 'claude-3-haiku', 25000000, 125000000, 1250000),
    ('pb_default_2026_01', 'anthropic', '*', 300000000, 1500000000, 150000000),
    ('pb_default_2026_01', 'google', 'gemini-1.5-pro', 350000000, 1050000000, 87500000),
    ('pb_default_2026_01', 'google', 'gemini-1.5-flash', 35000000, 105000000, 8750000),
    ('pb_default_2026_01', 'google', '*', 350000000, 1050000000, 87500000)
ON CONFLICT (price_book_version_id, provider, model_selector) DO NOTHING;

-- 6. Seed Default Spend Policy ($500.00/mo)
INSERT INTO spend_policies (
    policy_id, organization_id, workspace_id, scope_type, scope_id, currency, period_type,
    limit_microcents, action, effective_from, status
) VALUES (
    '00000000-0000-0000-0000-000000000010', '00000000-0000-0000-0000-000000000001',
    'default', 'organization', 'global', 'USD', 'monthly',
    50000000000, 'hard_deny', now(), 'PUBLISHED'
) ON CONFLICT (organization_id, scope_type, scope_id, period_type) DO NOTHING;

INSERT INTO spend_policy_versions (
    policy_version_id, policy_id, version, snapshot_json, published_by, published_at
) VALUES (
    '00000000-0000-0000-0000-000000000020', '00000000-0000-0000-0000-000000000010',
    1, '{"scope_type":"organization","limit_microcents":50000000000,"period_type":"monthly"}'::jsonb,
    'system', now()
) ON CONFLICT (policy_id, version) DO NOTHING;

COMMIT;
