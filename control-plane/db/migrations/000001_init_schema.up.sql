-- Migration: 000001_initial_schema.up.sql
-- Description: Consolidated, clean PostgreSQL multi-tenant schema baseline for AgentControl.

BEGIN;

-- ============================================================================
-- 1. EXTENSIONS & ENUMS
-- ============================================================================
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Core Enums
CREATE TYPE event_decision           AS ENUM ('allowed', 'denied', 'warned');
CREATE TYPE alert_severity           AS ENUM ('info', 'warning', 'critical');
CREATE TYPE agent_status             AS ENUM ('active', 'inactive', 'revoked');
CREATE TYPE auth_provider_type       AS ENUM ('local', 'oidc', 'oauth2');
CREATE TYPE subscription_tier        AS ENUM ('COMMUNITY', 'PRO', 'ENTERPRISE');

-- Device & Compliance Enums
CREATE TYPE device_state             AS ENUM ('PENDING', 'COMPLIANT', 'NON_COMPLIANT', 'REVOKED');
CREATE TYPE credential_status        AS ENUM ('ACTIVE', 'EXPIRING_SOON', 'EXPIRED', 'REVOKED');
CREATE TYPE token_status             AS ENUM ('ACTIVE', 'CONSUMED', 'REVOKED', 'EXPIRED');
CREATE TYPE actor_type               AS ENUM ('USER', 'DEVICE', 'SYSTEM', 'SAAS_OPERATOR');
CREATE TYPE event_severity           AS ENUM ('DEBUG', 'INFO', 'WARN', 'CRITICAL');

-- Spend Ledger Enums
CREATE TYPE spend_scope_type         AS ENUM ('organization', 'project', 'agent');
CREATE TYPE spend_period_type        AS ENUM ('daily', 'monthly', 'quarterly');
CREATE TYPE spend_action_type        AS ENUM ('soft_warn', 'require_approval', 'hard_deny');
CREATE TYPE spend_policy_status      AS ENUM ('DRAFT', 'PUBLISHED', 'ARCHIVED');
CREATE TYPE spend_event_type         AS ENUM ('RESERVED', 'SETTLED', 'RELEASED', 'EXPIRED');
CREATE TYPE reservation_state        AS ENUM ('AUTHORIZED', 'ACTIVE', 'SETTLED', 'RELEASED', 'EXPIRED');
CREATE TYPE increase_request_status  AS ENUM ('PENDING', 'APPROVED', 'REJECTED');

-- ============================================================================
-- 2. CORE MULTI-TENANCY & IDENTITY TABLES
-- ============================================================================

-- Tenants / Organizations
CREATE TABLE IF NOT EXISTS tenants (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name              TEXT NOT NULL,
    slug              TEXT NOT NULL UNIQUE,
    tier              subscription_tier NOT NULL DEFAULT 'COMMUNITY',
    max_devices       INT NOT NULL DEFAULT 25,
    max_agents        INT NOT NULL DEFAULT 10,
    license_key       TEXT,
    license_valid_until TIMESTAMPTZ,
    status            TEXT NOT NULL DEFAULT 'active',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status);

-- Auth Providers
CREATE TABLE IF NOT EXISTS auth_providers (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    type              auth_provider_type NOT NULL,
    issuer_url        TEXT,
    client_id         TEXT,
    client_secret_enc TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_providers_local_unique ON auth_providers (tenant_id, type) WHERE type = 'local';
CREATE INDEX IF NOT EXISTS idx_auth_providers_tenant ON auth_providers(tenant_id, type);

-- Users
CREATE TABLE IF NOT EXISTS users (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    auth_provider_id  UUID REFERENCES auth_providers(id) ON DELETE SET NULL,
    email             TEXT NOT NULL,
    password_hash     TEXT,
    is_admin          BOOLEAN NOT NULL DEFAULT false,
    is_saas_operator  BOOLEAN NOT NULL DEFAULT false,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_email_unique ON users(tenant_id, LOWER(email));
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id, email);

-- Tenant Memberships
CREATE TABLE IF NOT EXISTS tenant_memberships (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_subject      TEXT NOT NULL,
    role              TEXT NOT NULL CHECK (role IN ('OWNER', 'ADMIN', 'MEMBER', 'VIEWER')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_subject)
);

CREATE INDEX IF NOT EXISTS idx_memberships_tenant ON tenant_memberships(tenant_id);

-- ============================================================================
-- 3. FLEET AGENTS, TELEMETRY & SECURITY ALERTS
-- ============================================================================

CREATE TABLE IF NOT EXISTS agents (
    agent_id          TEXT PRIMARY KEY,
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    display_name      TEXT,
    status            agent_status NOT NULL DEFAULT 'active',
    policy_version    TEXT,
    first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents (tenant_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents (status);

CREATE TABLE IF NOT EXISTS telemetry_events (
    event_id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    timestamp_ms        BIGINT NOT NULL,
    session_id          TEXT NOT NULL,
    agent_id            TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    tool_name           TEXT NOT NULL,
    decision            event_decision NOT NULL,
    dlp_findings        JSONB NOT NULL DEFAULT '[]',
    injection_findings  JSONB NOT NULL DEFAULT '[]',
    semantic_findings   JSONB NOT NULL DEFAULT '[]',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_events_tenant ON telemetry_events (tenant_id, timestamp_ms DESC);
CREATE INDEX IF NOT EXISTS idx_events_agent_time ON telemetry_events (agent_id, timestamp_ms DESC);
CREATE INDEX IF NOT EXISTS idx_events_decision ON telemetry_events (decision);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    severity          alert_severity NOT NULL,
    event_id          UUID NOT NULL REFERENCES telemetry_events(event_id) ON DELETE CASCADE,
    pattern_name      TEXT NOT NULL,
    description       TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);

CREATE TABLE IF NOT EXISTS identity_credentials (
    credential_id     UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id          TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    provider          TEXT NOT NULL,
    key_id_preview    TEXT NOT NULL,
    last_validated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (agent_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_credentials_tenant ON identity_credentials (tenant_id, agent_id);

CREATE TABLE IF NOT EXISTS mcp_servers (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id          TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    server_name       TEXT NOT NULL,
    command           TEXT,
    tools_count       INT NOT NULL DEFAULT 0,
    tools_list        JSONB NOT NULL DEFAULT '[]',
    last_synced_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (agent_id, server_name)
);

CREATE INDEX IF NOT EXISTS idx_mcp_servers_tenant ON mcp_servers (tenant_id, agent_id);

-- ============================================================================
-- 4. POLICIES, TEMPLATES & PROVIDER SECRETS
-- ============================================================================

CREATE TABLE IF NOT EXISTS policies (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    version           TEXT NOT NULL,
    content           TEXT NOT NULL,
    is_active         BOOLEAN NOT NULL DEFAULT false,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_tenant_version ON policies (tenant_id, version);
CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_tenant_active_unique ON policies (tenant_id, is_active) WHERE is_active = true;

CREATE TABLE IF NOT EXISTS policy_templates (
    id                TEXT PRIMARY KEY,
    tenant_id         UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    category          TEXT NOT NULL,
    description       TEXT NOT NULL,
    tags              TEXT[] NOT NULL DEFAULT '{}',
    icon              TEXT NOT NULL DEFAULT 'shield',
    content           TEXT NOT NULL,
    is_custom         BOOLEAN NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_policy_templates_tenant ON policy_templates(tenant_id);

CREATE TABLE IF NOT EXISTS group_policy_versions (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    group_id          TEXT NOT NULL,
    version           INT NOT NULL,
    claims            JSONB NOT NULL,
    tools             JSONB NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_group_policies_tenant_group_version ON group_policy_versions (tenant_id, group_id, version);
CREATE INDEX IF NOT EXISTS idx_group_policies_tenant ON group_policy_versions(tenant_id, group_id);

CREATE TABLE IF NOT EXISTS provider_keys (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider          TEXT NOT NULL,
    key_preview       TEXT NOT NULL,
    encrypted_key     TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_provider_keys_provider ON provider_keys(tenant_id, provider);

-- ============================================================================
-- 5. DEVICE GOVERNANCE, SENTINEL & mTLS CERTIFICATES
-- ============================================================================

CREATE TABLE IF NOT EXISTS devices (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    stable_device_id  TEXT NOT NULL,
    display_name      TEXT NOT NULL,
    os_family         TEXT NOT NULL,
    architecture      TEXT NOT NULL,
    os_version_summary TEXT,
    daemon_version     TEXT DEFAULT '2.1.0',
    public_key         TEXT,
    state             device_state NOT NULL DEFAULT 'PENDING',
    state_changed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    owner_subject     TEXT,
    first_enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at        TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, stable_device_id)
);

CREATE INDEX IF NOT EXISTS idx_devices_tenant_state ON devices(tenant_id, state);
CREATE INDEX IF NOT EXISTS idx_devices_tenant_heartbeat ON devices(tenant_id, last_heartbeat_at DESC);
CREATE INDEX IF NOT EXISTS idx_devices_stable_id ON devices(stable_device_id);

-- Backward compatibility view for legacy tooling
CREATE OR REPLACE VIEW device_enrollments AS
    SELECT 
        id AS device_id,
        tenant_id AS organization_id,
        COALESCE(stable_device_id, display_name) AS hostname,
        COALESCE(owner_subject, display_name, 'Developer Workstation') AS user_identifier,
        os_family AS os,
        COALESCE(os_version_summary, architecture, 'v1.0') AS os_version,
        COALESCE(public_key, '') AS public_key,
        COALESCE(daemon_version, '2.1.0') AS daemon_version,
        CASE WHEN state = 'REVOKED' THEN 'REVOKED' ELSE 'ACTIVE' END AS enrollment_status,
        first_enrolled_at,
        last_heartbeat_at,
        created_at,
        updated_at
    FROM devices;

CREATE TABLE IF NOT EXISTS device_compliance_reports (
    report_id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id                 UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    overall_compliance        TEXT NOT NULL,
    tamper_event_count_24h    INT NOT NULL DEFAULT 0,
    mcp_servers_total         INT NOT NULL DEFAULT 0,
    mcp_servers_wrapped       INT NOT NULL DEFAULT 0,
    report_payload            JSONB,
    reported_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_device_compliance UNIQUE (device_id)
);

CREATE INDEX IF NOT EXISTS idx_compliance_org_dev ON device_compliance_reports(organization_id, device_id);

CREATE TABLE IF NOT EXISTS device_ide_status (
    status_id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id           UUID REFERENCES tenants(id) ON DELETE CASCADE,
    device_id                 UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ide_name                  TEXT NOT NULL,
    is_installed              BOOLEAN NOT NULL DEFAULT false,
    config_path               TEXT NOT NULL DEFAULT '',
    proxy_configured          BOOLEAN NOT NULL DEFAULT false,
    configured_base_url       TEXT DEFAULT '',
    mcp_wrapped               BOOLEAN NOT NULL DEFAULT false,
    compliance_state          TEXT NOT NULL DEFAULT 'COMPLIANT',
    last_healed_at            TIMESTAMPTZ,
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_device_ide UNIQUE (device_id, ide_name)
);

CREATE INDEX IF NOT EXISTS idx_device_ide_status_dev ON device_ide_status(device_id, ide_name);

CREATE TABLE IF NOT EXISTS device_tamper_events (
    event_id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id                 UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    organization_id           UUID REFERENCES tenants(id) ON DELETE CASCADE,
    ide_name                  VARCHAR(64) NOT NULL,
    event_type                VARCHAR(64) NOT NULL,
    tamper_details            TEXT NOT NULL,
    healed_successfully       BOOLEAN NOT NULL DEFAULT true,
    occurred_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_device_tamper_events_dev ON device_tamper_events(device_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS device_tamper_logs (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id         TEXT NOT NULL,
    target_ide        TEXT NOT NULL,
    detected_diff     TEXT NOT NULL,
    action_taken      TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_device_tamper_tenant ON device_tamper_logs(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_id          TEXT,
    token_hash        BYTEA NOT NULL,
    token_hint        TEXT NOT NULL,
    status            token_status NOT NULL DEFAULT 'ACTIVE',
    max_uses          INT NOT NULL DEFAULT 1,
    current_uses      INT NOT NULL DEFAULT 0,
    reason            TEXT NOT NULL,
    created_by        TEXT,
    created_by_subject TEXT NOT NULL DEFAULT 'admin',
    expires_at        TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_tokens_tenant_status ON enrollment_tokens(tenant_id, status);

CREATE TABLE IF NOT EXISTS device_enrollment_keys (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id         UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    public_key_pem    TEXT NOT NULL,
    fingerprint       TEXT NOT NULL,
    algorithm         TEXT NOT NULL DEFAULT 'ED25519',
    status            TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS device_certificates (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id         UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    serial_number     TEXT NOT NULL,
    sha256_fingerprint TEXT NOT NULL,
    certificate_pem   TEXT NOT NULL,
    status            credential_status NOT NULL DEFAULT 'ACTIVE',
    not_before        TIMESTAMPTZ NOT NULL,
    not_after         TIMESTAMPTZ NOT NULL,
    issued_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at        TIMESTAMPTZ,
    UNIQUE (serial_number),
    UNIQUE (tenant_id, sha256_fingerprint)
);

CREATE TABLE IF NOT EXISTS policy_versions (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    version           INT NOT NULL,
    mode              TEXT NOT NULL CHECK (mode IN ('AUDIT_ONLY', 'SAFE_MODE', 'TEAM_ENFORCE', 'LOCKDOWN')),
    policy_content    TEXT NOT NULL,
    sha256_hash       TEXT NOT NULL,
    signature_b64     TEXT NOT NULL,
    signer_key_id     TEXT NOT NULL,
    is_active         BOOLEAN NOT NULL DEFAULT false,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, version)
);

CREATE TABLE IF NOT EXISTS device_policy_assignments (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id         UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    policy_version_id UUID NOT NULL REFERENCES policy_versions(id) ON DELETE CASCADE,
    assigned_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_at        TIMESTAMPTZ,
    UNIQUE (tenant_id, device_id)
);

CREATE TABLE IF NOT EXISTS device_provider_capabilities (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id         UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    provider          TEXT NOT NULL,
    enabled           BOOLEAN NOT NULL DEFAULT true,
    rate_limit_rpm    INT NOT NULL DEFAULT 60,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, device_id, provider)
);

CREATE TABLE IF NOT EXISTS device_state_history (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id         UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    from_state        device_state,
    to_state          device_state NOT NULL,
    reason_code       TEXT NOT NULL,
    actor_type        actor_type NOT NULL,
    actor_subject     TEXT NOT NULL,
    request_id        TEXT,
    transitioned_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS device_heartbeats (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id         UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ip_address        TEXT NOT NULL,
    agent_version     TEXT NOT NULL,
    supported_targets INT NOT NULL DEFAULT 0,
    wrapped_targets   INT NOT NULL DEFAULT 0,
    unsupported_targets INT NOT NULL DEFAULT 0,
    payload_json      JSONB NOT NULL DEFAULT '{}',
    recorded_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS device_security_events (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id         UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    event_type        TEXT NOT NULL,
    severity          event_severity NOT NULL,
    details           JSONB NOT NULL DEFAULT '{}',
    recorded_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    action            TEXT NOT NULL,
    actor_subject     TEXT NOT NULL,
    actor_role        TEXT NOT NULL,
    target_type       TEXT NOT NULL,
    target_id         TEXT NOT NULL,
    diff_json         JSONB NOT NULL DEFAULT '{}',
    ip_address        TEXT,
    occurred_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- 6. AUTHORITATIVE SPEND LEDGER & BUDGET CONTROLS
-- ============================================================================

-- Legacy V1 spend tables
CREATE TABLE IF NOT EXISTS spend_budgets (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id        TEXT NOT NULL,
    monthly_limit_usd NUMERIC(10, 2) NOT NULL DEFAULT 100.00,
    current_spend_usd NUMERIC(10, 2) NOT NULL DEFAULT 0.00,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, project_id)
);

CREATE TABLE IF NOT EXISTS spend_snapshots (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id        TEXT NOT NULL,
    agent_id          TEXT NOT NULL,
    amount_usd        NUMERIC(10, 4) NOT NULL,
    recorded_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS spend_increase_requests (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id        TEXT NOT NULL,
    requested_by      TEXT NOT NULL,
    requested_amount  NUMERIC(10, 2) NOT NULL,
    reason            TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'PENDING',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Target V2 Spend Ledger
CREATE TABLE IF NOT EXISTS price_books (
    price_book_id     UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    version           TEXT NOT NULL UNIQUE,
    is_active         BOOLEAN NOT NULL DEFAULT false,
    effective_from    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS price_book_items (
    item_id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    price_book_version_id TEXT NOT NULL,
    provider          TEXT NOT NULL,
    model_selector    TEXT NOT NULL,
    input_rate_microcents_per_million  BIGINT NOT NULL,
    output_rate_microcents_per_million BIGINT NOT NULL,
    cached_input_rate_microcents_per_million BIGINT NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (price_book_version_id, provider, model_selector)
);

CREATE TABLE IF NOT EXISTS spend_policies (
    policy_id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scope_type        spend_scope_type NOT NULL,
    scope_id          TEXT NOT NULL,
    currency          TEXT NOT NULL DEFAULT 'USD',
    period_type       spend_period_type NOT NULL,
    limit_microcents  BIGINT NOT NULL,
    action            spend_action_type NOT NULL DEFAULT 'hard_deny',
    effective_from    TIMESTAMPTZ NOT NULL DEFAULT now(),
    effective_to      TIMESTAMPTZ,
    status            spend_policy_status NOT NULL DEFAULT 'DRAFT',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, scope_type, scope_id, period_type)
);

CREATE TABLE IF NOT EXISTS spend_policy_versions (
    policy_version_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id         UUID NOT NULL REFERENCES spend_policies(policy_id) ON DELETE CASCADE,
    version           INT NOT NULL,
    snapshot_json     JSONB NOT NULL,
    published_by      TEXT NOT NULL,
    published_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (policy_id, version)
);

CREATE TABLE IF NOT EXISTS budget_windows (
    window_id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    policy_version_id   UUID NOT NULL REFERENCES spend_policy_versions(policy_version_id) ON DELETE CASCADE,
    scope_type          spend_scope_type NOT NULL,
    scope_id            TEXT NOT NULL,
    window_start        TIMESTAMPTZ NOT NULL,
    window_end          TIMESTAMPTZ NOT NULL,
    limit_microcents    BIGINT NOT NULL,
    reserved_microcents BIGINT NOT NULL DEFAULT 0,
    settled_microcents  BIGINT NOT NULL DEFAULT 0,
    version             BIGINT NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, policy_version_id, window_start)
);

CREATE TABLE IF NOT EXISTS spend_reservations (
    reservation_id      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id          TEXT NOT NULL,
    agent_id            TEXT NOT NULL,
    gateway_id          TEXT NOT NULL,
    request_id          TEXT NOT NULL,
    provider            TEXT NOT NULL,
    model               TEXT NOT NULL,
    reserved_microcents BIGINT NOT NULL,
    settled_microcents  BIGINT NOT NULL DEFAULT 0,
    state               reservation_state NOT NULL DEFAULT 'AUTHORIZED',
    policy_version_snapshot JSONB NOT NULL DEFAULT '[]',
    price_book_version_id TEXT NOT NULL,
    idempotency_key     TEXT NOT NULL,
    request_hash        TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    settled_at          TIMESTAMPTZ,
    released_at         TIMESTAMPTZ,
    release_reason      TEXT,
    UNIQUE (organization_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS spend_events (
    event_id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    reservation_id      UUID REFERENCES spend_reservations(reservation_id) ON DELETE SET NULL,
    request_id          TEXT NOT NULL,
    event_type          spend_event_type NOT NULL,
    amount_microcents   BIGINT NOT NULL,
    currency            TEXT NOT NULL DEFAULT 'USD',
    usage_json          JSONB NOT NULL DEFAULT '{}',
    provider_request_id TEXT,
    actor               TEXT NOT NULL,
    reason_code         TEXT,
    occurred_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_spend_events_org_time ON spend_events(organization_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS spend_idempotency (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    operation           TEXT NOT NULL,
    idempotency_key     TEXT NOT NULL,
    payload_hash        TEXT NOT NULL,
    response_json       JSONB NOT NULL,
    response_status     INT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    UNIQUE (organization_id, operation, idempotency_key)
);

CREATE TABLE IF NOT EXISTS spend_v2_increase_requests (
    request_id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id             UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id                  TEXT NOT NULL,
    requested_limit_microcents  BIGINT NOT NULL,
    current_limit_microcents    BIGINT NOT NULL,
    reason                      TEXT NOT NULL,
    status                      increase_request_status NOT NULL DEFAULT 'PENDING',
    created_by                  TEXT NOT NULL,
    decided_by                  TEXT,
    decision_reason             TEXT,
    resulting_policy_version_id UUID REFERENCES spend_policy_versions(policy_version_id),
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at                  TIMESTAMPTZ
);

-- ============================================================================
-- 7. ROW LEVEL SECURITY (RLS)
-- ============================================================================

DO $$
DECLARE
    t text;
    tenant_tables text[] := ARRAY[
        'agents', 'telemetry_events', 'alerts', 'identity_credentials', 'auth_providers',
        'users', 'policies', 'mcp_servers', 'spend_budgets', 'spend_snapshots',
        'spend_increase_requests', 'group_policy_versions', 'provider_keys',
        'devices', 'device_enrollments', 'device_compliance_reports', 'device_ide_status',
        'device_tamper_logs', 'spend_policies', 'budget_windows', 'spend_reservations',
        'spend_events', 'spend_idempotency', 'spend_v2_increase_requests'
    ];
BEGIN
    FOREACH t IN ARRAY tenant_tables LOOP
        IF EXISTS (SELECT FROM information_schema.tables WHERE table_name = t) THEN
            EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY;', t);
        END IF;
    END LOOP;
END $$;

-- ============================================================================
-- 8. INITIAL SEED DATA
-- ============================================================================

-- Seed Default Tenant
INSERT INTO tenants (id, name, slug, tier, max_devices, max_agents, status, created_at, updated_at)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default Organization', 'default', 'ENTERPRISE', 100, 50, 'active', now(), now())
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, status = EXCLUDED.status, updated_at = now();

-- Seed Local Auth Provider
INSERT INTO auth_providers (id, tenant_id, name, type, created_at, updated_at)
VALUES ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001', 'Local Password Authentication', 'local', now(), now())
ON CONFLICT (tenant_id, type) WHERE type = 'local' DO NOTHING;

-- Seed Default Admin User (Password: admin123! using bcrypt cost 12)
INSERT INTO users (id, tenant_id, auth_provider_id, email, password_hash, is_admin, is_saas_operator, created_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000003',
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000002',
    'admin@agentcontrol.local',
    '$2a$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
    true,
    true,
    now(),
    now()
)
ON CONFLICT (tenant_id, LOWER(email)) DO UPDATE SET
    is_admin = true,
    is_saas_operator = true,
    updated_at = now();

-- Seed Default Active Policy (v1.0.0)
INSERT INTO policies (id, tenant_id, version, content, is_active, created_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000004',
    '00000000-0000-0000-0000-000000000001',
    '1.0.0',
    E'version: "1.0.0"\ndefault_action: deny\nenforce_safe_mode: true\n\nrules:\n  - name: allow_read_ops\n    action: allow\n    tools:\n      - "fs:read_file"\n      - "fs:list_dir"\n  - name: deny_secret_access\n    action: deny\n    tools:\n      - "env:get_var"\n    parameters:\n      name: "*KEY*"\n',
    true,
    now(),
    now()
)
ON CONFLICT (tenant_id, version) DO UPDATE SET is_active = true, updated_at = now();

-- Seed Default Active Price Book
INSERT INTO price_books (price_book_id, version, is_active, effective_from)
VALUES ('00000000-0000-0000-0000-000000000005', 'pb_default_2026_01', true, now())
ON CONFLICT (version) DO NOTHING;

INSERT INTO price_book_items (price_book_version_id, provider, model_selector, input_rate_microcents_per_million, output_rate_microcents_per_million, cached_input_rate_microcents_per_million)
VALUES
    ('pb_default_2026_01', 'openai', 'gpt-4o', 250000000, 1000000000, 125000000),
    ('pb_default_2026_01', 'openai', 'gpt-4o-mini', 15000000, 60000000, 7500000),
    ('pb_default_2026_01', 'anthropic', 'claude-3-5-sonnet', 300000000, 1500000000, 150000000),
    ('pb_default_2026_01', 'anthropic', 'claude-3-haiku', 25000000, 125000000, 12500000),
    ('pb_default_2026_01', 'google', 'gemini-1.5-pro', 350000000, 1050000000, 87500000),
    ('pb_default_2026_01', 'google', 'gemini-1.5-flash', 35000000, 105000000, 8750000)
ON CONFLICT (price_book_version_id, provider, model_selector) DO NOTHING;

COMMIT;
