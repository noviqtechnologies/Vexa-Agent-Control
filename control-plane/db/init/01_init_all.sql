
-- ==================== 000001_init_schema.up.sql ====================
-- FR-23 Phase 1 schema: Fleet Overview + Identity Governance (read-only).
-- All data originates from the gateway via dashboard-api ingest endpoints.
-- AC-23.10: no column in this schema accepts raw secret material, tool-call
-- parameters, response bodies, or DLP match content.

BEGIN;

-- Enum types matching dashboard-proto wire format (snake_case).
CREATE TYPE event_decision AS ENUM ('allowed', 'denied', 'warned');
CREATE TYPE alert_severity AS ENUM ('info', 'warning', 'critical');
CREATE TYPE agent_status   AS ENUM ('active', 'inactive', 'revoked');

-- ─── agents ────────────────────────────────────────────────────────────────────
-- Auto-registered on first event ingest. The gateway is the source of truth
-- for which agents exist; the dashboard never creates agents independently.
CREATE TABLE agents (
    agent_id       TEXT          PRIMARY KEY,  -- OIDC sub claim
    display_name   TEXT,
    status         agent_status  NOT NULL DEFAULT 'active',
    policy_version TEXT,
    first_seen_at  TIMESTAMPTZ   NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ   NOT NULL DEFAULT now(),
    created_at     TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE INDEX idx_agents_status      ON agents (status);
CREATE INDEX idx_agents_last_seen   ON agents (last_seen_at DESC);

-- ─── telemetry_events ──────────────────────────────────────────────────────────
-- Redacted events from the gateway. dlp/injection/semantic findings are stored
-- as JSONB arrays of typed objects (category + pattern_name + count), never
-- raw match content.
CREATE TABLE telemetry_events (
    event_id            UUID          PRIMARY KEY,
    timestamp_ms        BIGINT        NOT NULL,
    session_id          TEXT          NOT NULL,
    agent_id            TEXT          NOT NULL REFERENCES agents(agent_id),
    tool_name           TEXT          NOT NULL,
    decision            event_decision NOT NULL,
    dlp_findings        JSONB         NOT NULL DEFAULT '[]',
    injection_findings  JSONB         NOT NULL DEFAULT '[]',
    semantic_findings   JSONB         NOT NULL DEFAULT '[]',
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE INDEX idx_events_agent_time  ON telemetry_events (agent_id, timestamp_ms DESC);
CREATE INDEX idx_events_decision    ON telemetry_events (decision);
CREATE INDEX idx_events_timestamp   ON telemetry_events (timestamp_ms DESC);
CREATE INDEX idx_events_session     ON telemetry_events (session_id);

-- ─── alerts ────────────────────────────────────────────────────────────────────
-- Real-time alerts derived from events. One event can produce multiple alerts
-- (e.g. DLP finding + injection finding in the same tool call).
CREATE TABLE alerts (
    alert_id    UUID            PRIMARY KEY,
    severity    alert_severity  NOT NULL,
    event_id    UUID            NOT NULL REFERENCES telemetry_events(event_id),
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT now()
);

CREATE INDEX idx_alerts_severity_time ON alerts (severity, created_at DESC);
CREATE INDEX idx_alerts_event         ON alerts (event_id);

-- ─── identity_credentials ──────────────────────────────────────────────────────
-- Credential metadata only. The credential value itself is never stored here
-- (AC-23.10). rotation_history is a JSONB array of {rotated_at_ms, reason}.
CREATE TABLE identity_credentials (
    credential_id      TEXT      PRIMARY KEY,
    agent_id           TEXT      NOT NULL REFERENCES agents(agent_id),
    scope              TEXT[]    NOT NULL DEFAULT '{}',
    ttl_seconds        BIGINT   NOT NULL,
    created_at_ms      BIGINT   NOT NULL,
    expires_at_ms      BIGINT   NOT NULL,
    last_rotated_at_ms BIGINT,
    rotation_history   JSONB    NOT NULL DEFAULT '[]',
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_credentials_agent   ON identity_credentials (agent_id);
CREATE INDEX idx_credentials_expiry  ON identity_credentials (expires_at_ms);

COMMIT;


-- ==================== 000002_auth_and_policy.up.sql ====================
BEGIN;

-- ─── auth_providers ────────────────────────────────────────────────────────────
CREATE TYPE auth_provider_type AS ENUM ('local', 'github', 'google');

CREATE TABLE auth_providers (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type          auth_provider_type NOT NULL,
    name          TEXT NOT NULL,
    client_id     TEXT,
    client_secret TEXT,
    issuer_url    TEXT,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    email_domains TEXT[] NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Ensure only one local provider can exist
CREATE UNIQUE INDEX idx_auth_providers_local_unique ON auth_providers (type) WHERE type = 'local';

-- ─── users ──────────────────────────────────────────────────────────────────────
CREATE TABLE users (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_provider_id UUID NOT NULL REFERENCES auth_providers(id) ON DELETE CASCADE,
    email            TEXT NOT NULL,
    password_hash    TEXT, -- only for local users
    is_admin         BOOLEAN NOT NULL DEFAULT false,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(auth_provider_id, email)
);

-- ─── policies ───────────────────────────────────────────────────────────────────
-- AgentWall uses policy YAML. We will store it in DB to allow dynamic updates via UI.
CREATE TABLE policies (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version    TEXT NOT NULL UNIQUE,
    content    TEXT NOT NULL, -- The YAML content
    is_active  BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Ensure only one active policy
CREATE UNIQUE INDEX idx_policies_active_unique ON policies (is_active) WHERE is_active = true;

COMMIT;


-- ==================== 000003_mcp_server_inventory.up.sql ====================
CREATE TABLE mcp_servers (
    agent_id      TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    ide_target    TEXT NOT NULL,
    server_name   TEXT NOT NULL,
    wrapped       BOOLEAN NOT NULL,
    path_verified BOOLEAN NOT NULL,
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, ide_target, server_name)
);


-- ==================== 000004_seed_default_policy.up.sql ====================
-- Migration: 000003_seed_default_policy
-- Seeds a default AgentWall policy into the policies table IF none exists.
-- This ensures the system works out of the box on first boot without requiring
-- an admin to manually create a policy before agents can connect.
--
-- The default policy:
--   - version: "2" (Schema v2, required by the gateway v6.1+)
--   - default_action: deny (secure by default — unknown tools are blocked)
--   - Allows the most common safe MCP tools with no parameter restrictions
--   - Enables the agent firewall for cycle/loop detection
--   - Rate-limited to 10 calls/second per session
--
-- Admins can refine this policy at any time via the Policy Editor page in the
-- dashboard. Every save creates a new version in this table and the gateway
-- hot-swaps it within POLICY_POLL_INTERVAL_SECS seconds (default: 30).

BEGIN;

INSERT INTO policies (version, content, is_active, created_at, updated_at)
SELECT
    'v1.0.0',
    $POLICY$version: "2"
default_action: deny

# Rate limiting: maximum tool calls per agent session per second
session:
  max_calls_per_second: 10

# LLM Governance & Prompt DLP
llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o", "gpt-3.5-turbo"]
      dlp_tier: "strict"
  dlp:
    actions:
      - entity: "CREDIT_CARD"
        action: "deny"

# Tool allowlist — add or restrict tools as needed.
# All unlisted tools are blocked by default_action: deny.
tools:
  # File system — read access only (write_file is intentionally omitted)
  - name: "read_file"
    action: allow
    parameters:
      - name: "path"
        type: string
        required: true

  - name: "list_directory"
    action: allow
    parameters:
      - name: "directory"
        type: string
        required: true

  # MCP introspection — always safe
  - name: "tools/list"
    action: allow

  - name: "get_schema"
    action: allow

  - name: "ping"
    action: allow

  # Shell execution — allowed but review carefully before enabling in production.
  # Consider adding a pattern constraint (e.g. pattern: "^(ls|pwd|echo .*)$").
  - name: "exec_shell"
    action: allow
    parameters:
      - name: "command"
        type: string
        required: true

  # File write — disabled by default. Remove the comment below to enable.
  # - name: "write_file"
  #   action: allow
  #   parameters:
  #     - name: "path"
  #       type: string
  #       required: true
  #     - name: "content"
  #       type: string
  #       required: true

# Agent firewall: detects and breaks tool-call loops / cycles
firewall:
  enabled: true
  cycle_detection:
    max_attempts: 3
    action: pivot_error  # Options: pivot_error, block, pause_interactive
$POLICY$,
    true,
    now(),
    now()
WHERE NOT EXISTS (
    SELECT 1 FROM policies WHERE is_active = true
);

COMMIT;


-- ==================== 000005_spend_caps.up.sql ====================
BEGIN;

CREATE TABLE spend_budgets (
    scope_type TEXT NOT NULL,
    scope_key  TEXT NOT NULL DEFAULT '',
    cap_cents  BIGINT NOT NULL,
    period     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_type, scope_key)
);

CREATE TABLE spend_snapshots (
    agent_id     TEXT NOT NULL REFERENCES agents(agent_id),
    period_start TIMESTAMPTZ NOT NULL,
    spent_cents  BIGINT NOT NULL,
    cap_cents    BIGINT,
    is_estimated BOOLEAN NOT NULL DEFAULT true,
    pricing_table_version TEXT,
    synced_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, period_start)
);

CREATE TABLE spend_increase_requests (
    request_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id     TEXT NOT NULL REFERENCES agents(agent_id),
    current_cap  BIGINT NOT NULL,
    reason       TEXT,
    status       TEXT NOT NULL DEFAULT 'pending',
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at  TIMESTAMPTZ,
    resolved_by  TEXT,
    new_cap      BIGINT
);

COMMIT;


-- ==================== 000006_group_policy_versions.up.sql ====================
CREATE TABLE IF NOT EXISTS group_policy_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    claims JSONB NOT NULL, -- The group claims to match
    tools JSONB NOT NULL, -- Array of tool rules
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT NOT NULL,
    active BOOLEAN DEFAULT false,
    UNIQUE(group_id, version)
);

CREATE INDEX idx_group_policy_versions_group_id ON group_policy_versions(group_id);
CREATE INDEX idx_group_policy_versions_active ON group_policy_versions(group_id) WHERE active = true;


-- ==================== 000007_provider_keys.up.sql ====================
CREATE TABLE IF NOT EXISTS provider_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider VARCHAR(255) NOT NULL,
    api_key_encrypted TEXT NOT NULL,
    api_key_masked VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Note: We only allow one active key per provider for simplicity right now.
CREATE UNIQUE INDEX idx_provider_keys_provider ON provider_keys(provider);


-- ==================== 000008_devices_and_enrollment.up.sql ====================
CREATE TABLE IF NOT EXISTS devices (
    device_id           VARCHAR(255) PRIMARY KEY,
    hostname            VARCHAR(255) NOT NULL,
    os_arch             VARCHAR(255) NOT NULL,
    os_family           VARCHAR(255) NOT NULL,
    public_key          TEXT NOT NULL,
    agentwall_version   VARCHAR(255) NOT NULL,
    compliance_status   VARCHAR(255) NOT NULL DEFAULT 'COMPLIANT',
    mcp_servers_total   INT NOT NULL DEFAULT 0,
    mcp_servers_wrapped INT NOT NULL DEFAULT 0,
    ide_checksums       JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_enrolled_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_heartbeat_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    is_revoked          BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at          TIMESTAMP WITH TIME ZONE,
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_devices_compliance ON devices(compliance_status);
CREATE INDEX IF NOT EXISTS idx_devices_os_family ON devices(os_family);
CREATE INDEX IF NOT EXISTS idx_devices_heartbeat ON devices(last_heartbeat_at);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_id            VARCHAR(255) PRIMARY KEY,
    token_hash          TEXT NOT NULL,
    created_by          VARCHAR(255) NOT NULL,
    max_uses            INT NOT NULL DEFAULT 1,
    current_uses        INT NOT NULL DEFAULT 0,
    expires_at          TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS device_tamper_logs (
    log_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id           VARCHAR(255) NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    target_ide          VARCHAR(255) NOT NULL,
    detected_diff       TEXT NOT NULL,
    action_taken        VARCHAR(255) NOT NULL,
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);


-- ==================== 000009_target_v2_schema.up.sql ====================
-- Migration: 000008_target_v2_schema.up.sql
-- Purpose: Implement Vexa AgentWall v4.0 Target Contract Relational Schema on PostgreSQL

BEGIN;

-- 1. Custom Types / ENUMs
DO $$ BEGIN
    CREATE TYPE device_state AS ENUM (
        'PENDING', 'COMPLIANT', 'NON_COMPLIANT', 'UNREACHABLE', 'REVOKED', 'LEGACY_AUTH'
    );
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE credential_status AS ENUM (
        'ACTIVE', 'SUPERSEDED', 'REVOKED', 'EXPIRED'
    );
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE token_status AS ENUM (
        'ACTIVE', 'CONSUMED', 'EXPIRED', 'REVOKED'
    );
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE actor_type AS ENUM (
        'OPERATOR', 'DEVICE', 'SYSTEM'
    );
EXCEPTION WHEN duplicate_object THEN null; END $$;

-- Drop legacy v1 unpartitioned/unkeyed tables for clean upgrade to v4.0 target contract
DROP TABLE IF EXISTS device_tamper_logs CASCADE;
DROP TABLE IF EXISTS enrollment_tokens CASCADE;
DROP TABLE IF EXISTS devices CASCADE;

-- 2. Tenants and Members
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED','CLOSED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tenant_members (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    oidc_subject TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner_admin','operator','device_user')),
    assigned_device_id UUID NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, oidc_subject)
);

-- 3. One-Time Enrollment Tokens (OTET)
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    token_hint TEXT NOT NULL,
    hash_algorithm TEXT NOT NULL DEFAULT 'sha256',
    status token_status NOT NULL DEFAULT 'ACTIVE',
    max_uses SMALLINT NOT NULL DEFAULT 1 CHECK (max_uses = 1),
    current_uses SMALLINT NOT NULL DEFAULT 0 CHECK (current_uses IN (0,1)),
    expected_device_label TEXT NULL,
    target_owner_subject TEXT NULL,
    reason TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    consumed_device_id UUID NULL,
    revoked_at TIMESTAMPTZ NULL,
    revoked_by_subject TEXT NULL,
    created_by_subject TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS enrollment_tokens_hash_uq ON enrollment_tokens (token_hash);
CREATE INDEX IF NOT EXISTS enrollment_tokens_active_idx ON enrollment_tokens (tenant_id, expires_at) WHERE status = 'ACTIVE';

-- 4. Enrollment Transactions and Challenges
CREATE TABLE IF NOT EXISTS enrollment_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    enrollment_token_id UUID NOT NULL REFERENCES enrollment_tokens(id) ON DELETE RESTRICT,
    stable_device_id TEXT NOT NULL,
    display_name TEXT NULL,
    owner_subject TEXT NULL,
    enrollment_ed25519_public_key BYTEA NOT NULL,
    enrollment_key_fingerprint TEXT NOT NULL,
    mtls_csr_sha256 TEXT NOT NULL,
    mtls_csr_pem TEXT NOT NULL,
    os_family TEXT NOT NULL CHECK (os_family IN ('windows','macos','linux')),
    os_version_summary TEXT NULL,
    architecture TEXT NOT NULL,
    release_manifest_id UUID NULL,
    status TEXT NOT NULL CHECK (status IN ('CHALLENGE_ISSUED','COMPLETED','FAILED','EXPIRED','CANCELLED')),
    failure_code TEXT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_enrollment_tx UNIQUE (tenant_id, stable_device_id, enrollment_key_fingerprint)
);

CREATE TABLE IF NOT EXISTS enrollment_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    transaction_id UUID NOT NULL UNIQUE REFERENCES enrollment_transactions(id) ON DELETE CASCADE,
    challenge_hash BYTEA NOT NULL,
    transcript_sha256 TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 5. Devices, Keys, and Certificates
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    stable_device_id TEXT NOT NULL,
    display_name TEXT NULL,
    owner_subject TEXT NULL,
    os_family TEXT NOT NULL CHECK (os_family IN ('windows','macos','linux')),
    os_version_summary TEXT NULL,
    architecture TEXT NOT NULL,
    state device_state NOT NULL DEFAULT 'PENDING',
    state_reason_code TEXT NULL,
    state_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    release_manifest_id UUID NULL,
    first_enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_authenticated_at TIMESTAMPTZ NULL,
    last_heartbeat_at TIMESTAMPTZ NULL,
    revoked_at TIMESTAMPTZ NULL,
    revoked_by_subject TEXT NULL,
    revocation_reason TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_device_tenant UNIQUE (tenant_id, stable_device_id)
);

CREATE TABLE IF NOT EXISTS device_enrollment_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    algorithm TEXT NOT NULL CHECK (algorithm = 'Ed25519'),
    public_key BYTEA NOT NULL,
    fingerprint TEXT NOT NULL,
    status credential_status NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at TIMESTAMPTZ NULL,
    CONSTRAINT uq_device_enrollment_keys UNIQUE (tenant_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS device_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    ca_resource_name TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    certificate_fingerprint TEXT NOT NULL,
    csr_sha256 TEXT NOT NULL,
    public_key_fingerprint TEXT NOT NULL,
    status credential_status NOT NULL DEFAULT 'ACTIVE',
    issued_at TIMESTAMPTZ NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    renew_after TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    revocation_reason TEXT NULL,
    superseded_by UUID NULL,
    CONSTRAINT uq_dev_cert_serial UNIQUE (tenant_id, serial_number),
    CONSTRAINT uq_dev_cert_fp UNIQUE (tenant_id, certificate_fingerprint)
);

CREATE INDEX IF NOT EXISTS device_certificates_active_idx 
    ON device_certificates (tenant_id, device_id, not_after) 
    WHERE status = 'ACTIVE';

-- 6. Policy Versions and Assignments
CREATE TABLE IF NOT EXISTS policy_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    policy_name TEXT NOT NULL,
    version INTEGER NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('TEAM_ENFORCE','SHADOW','DEVELOPER')),
    content TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    signer_key_id TEXT NOT NULL,
    signature BYTEA NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    published_by_subject TEXT NOT NULL,
    publish_reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_policy_version UNIQUE (tenant_id, policy_name, version),
    CONSTRAINT uq_policy_hash UNIQUE (tenant_id, content_sha256)
);

CREATE TABLE IF NOT EXISTS device_policy_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    policy_version_id UUID NOT NULL REFERENCES policy_versions(id) ON DELETE RESTRICT,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('DEVICE','PROJECT','REMEDIATION')),
    scope_ref TEXT NULL,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE','SUPERSEDED','REVOKED')),
    assigned_by_subject TEXT NOT NULL,
    expires_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 7. Provider Capabilities
CREATE TABLE IF NOT EXISTS device_provider_capabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    project_ref TEXT NOT NULL,
    model_family TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('INVOKE')),
    status TEXT NOT NULL CHECK (status IN ('ACTIVE','REVOKED','EXPIRED')),
    issued_by_subject TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    reason TEXT NOT NULL
);

-- 8. Heartbeats and Security Evidence
CREATE TABLE IF NOT EXISTS device_state_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    prior_state device_state NULL,
    new_state device_state NOT NULL,
    reason_code TEXT NOT NULL,
    actor_type actor_type NOT NULL,
    actor_subject TEXT NULL,
    correlation_id UUID NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS device_heartbeats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    certificate_id UUID NOT NULL REFERENCES device_certificates(id) ON DELETE RESTRICT,
    sequence BIGINT NOT NULL,
    idempotency_key UUID NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    service_version TEXT NOT NULL,
    policy_version_id UUID NULL,
    policy_state TEXT NOT NULL,
    listener_scope TEXT NOT NULL,
    watcher_state TEXT NULL,
    wrapped_target_count INTEGER NULL,
    supported_target_count INTEGER NULL,
    unverified_target_count INTEGER NULL,
    source_type TEXT NOT NULL DEFAULT 'SENTRY_SELF_REPORT',
    verification_level TEXT NOT NULL DEFAULT 'SELF_REPORTED',
    CONSTRAINT uq_heartbeat_seq UNIQUE (tenant_id, device_id, sequence),
    CONSTRAINT uq_heartbeat_idemp UNIQUE (tenant_id, device_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS device_security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    event_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
    occurred_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    policy_version_id UUID NULL,
    certificate_id UUID NULL,
    reason_code TEXT NOT NULL,
    redacted_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    source_type TEXT NOT NULL DEFAULT 'SENTRY_SELF_REPORT',
    CONSTRAINT uq_dev_sec_event UNIQUE (tenant_id, device_id, event_id)
);

-- 9. Audit, Idempotency, Outbox, and Recovery
CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    correlation_id UUID NOT NULL,
    request_id UUID NOT NULL,
    actor_type actor_type NOT NULL,
    actor_ref TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('ALLOW','DENY','SUCCESS','FAILURE')),
    reason_code TEXT NULL,
    before_metadata JSONB NULL,
    after_metadata JSONB NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS idempotency_records (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    principal_ref TEXT NOT NULL,
    route TEXT NOT NULL,
    idempotency_key UUID NOT NULL,
    canonical_body_sha256 TEXT NOT NULL,
    response_status SMALLINT NOT NULL,
    response_reference TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, principal_ref, route, idempotency_key)
);

CREATE TABLE IF NOT EXISTS outbox_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_version TEXT NOT NULL,
    redacted_payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error_code TEXT NULL
);

CREATE TABLE IF NOT EXISTS device_recovery_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    recovery_token_id UUID NOT NULL REFERENCES enrollment_tokens(id) ON DELETE RESTRICT,
    owner_verification_reference TEXT NOT NULL,
    reason TEXT NOT NULL,
    approved_by_subject TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed default development/SMB tenant
INSERT INTO tenants (id, slug, status)
VALUES ('00000000-0000-0000-0000-000000000001', 'default-smb-tenant', 'ACTIVE')
ON CONFLICT (id) DO NOTHING;

COMMIT;


-- ==================== 000010_spend_v2_ledger.up.sql ====================
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


-- ==================== 000011_device_governance.up.sql ====================
-- Migration: 000010_device_governance.up.sql
-- Description: Device enrollment, IDE compliance tracking, and immutable tamper audit trail.

BEGIN;

-- 1. Device Enrollment Registry
CREATE TABLE IF NOT EXISTS device_enrollments (
    device_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hostname VARCHAR(255) NOT NULL,
    user_identifier VARCHAR(255) NOT NULL,
    os VARCHAR(32) NOT NULL,              -- 'windows', 'macos', 'linux'
    os_version VARCHAR(255) NOT NULL,
    public_key TEXT NOT NULL,             -- Ed25519 public key (hex / base64)
    daemon_version VARCHAR(32) NOT NULL,
    enrollment_status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE', -- 'ACTIVE', 'REVOKED', 'SUSPENDED'
    last_heartbeat_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_device_org_host UNIQUE (organization_id, hostname, user_identifier)
);

CREATE INDEX IF NOT EXISTS idx_device_enrollments_org 
    ON device_enrollments (organization_id, enrollment_status);

-- 2. Device Compliance Reports (Latest Snapshot)
CREATE TABLE IF NOT EXISTS device_compliance_reports (
    report_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES device_enrollments(device_id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    overall_compliance VARCHAR(32) NOT NULL, -- 'COMPLIANT', 'NON_COMPLIANT', 'OFFLINE'
    tamper_event_count_24h INT NOT NULL DEFAULT 0,
    report_payload JSONB NOT NULL,          -- Full telemetry payload
    reported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_device_compliance UNIQUE (device_id)
);

CREATE INDEX IF NOT EXISTS idx_device_compliance_status 
    ON device_compliance_reports (organization_id, overall_compliance);

-- 3. Per-IDE Configuration Status
CREATE TABLE IF NOT EXISTS device_ide_status (
    status_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES device_enrollments(device_id) ON DELETE CASCADE,
    ide_name VARCHAR(64) NOT NULL,         -- 'cursor', 'vscode', 'claude_desktop', 'jetbrains', 'zed', 'windsurf'
    is_installed BOOLEAN NOT NULL DEFAULT false,
    config_path TEXT NOT NULL,
    proxy_configured BOOLEAN NOT NULL DEFAULT false,
    configured_base_url TEXT,
    mcp_wrapped BOOLEAN NOT NULL DEFAULT false,
    compliance_state VARCHAR(32) NOT NULL, -- 'COMPLIANT', 'BYPASSED', 'NOT_INSTALLED', 'UNSUPPORTED'
    last_healed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_device_ide UNIQUE (device_id, ide_name)
);

CREATE INDEX IF NOT EXISTS idx_device_ide_status_lookup 
    ON device_ide_status (device_id, ide_name);

-- 4. Immutable Device Tamper & Drift Audit Events
CREATE TABLE IF NOT EXISTS device_tamper_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES device_enrollments(device_id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ide_name VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,       -- 'CONFIG_TAMPERED', 'AUTO_HEALED', 'DAEMON_DISABLED', 'PROXY_BYPASSED'
    tamper_details TEXT NOT NULL,
    healed_successfully BOOLEAN NOT NULL DEFAULT true,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_device_tamper_events_lookup 
    ON device_tamper_events (organization_id, device_id, occurred_at DESC);

COMMIT;


-- ==================== 000012_multi_tenant_v1_tables.up.sql ====================
-- Migration: 000011_multi_tenant_v1_tables.up.sql
-- Description: Extend tenants table with organization metadata and add tenant_id to all v1 tables.

BEGIN;

-- 1. Extend tenants table with organization metadata, licensing, secrets, and trial info
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS contact_email TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS license_tier TEXT NOT NULL DEFAULT 'community'
    CHECK (license_tier IN ('community', 'team', 'enterprise'));
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_seats INTEGER NOT NULL DEFAULT 10;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS license_key_jwt TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS is_trial BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS trial_days INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS trial_ends_at TIMESTAMPTZ;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS license_expires_at TIMESTAMPTZ;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS gateway_secret TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS policy_read_secret TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS bootstrap_token_hash TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS bootstrap_token_hint TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS bootstrap_consumed_at TIMESTAMPTZ;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Update default tenant metadata
UPDATE tenants 
SET name = 'Default Organization', 
    contact_email = 'admin@agentwall.local',
    license_tier = 'community',
    max_seats = 10,
    is_trial = false
WHERE id = '00000000-0000-0000-0000-000000000001' AND name = '';

-- 2. Add tenant_id to all 13 V1 tables (instant metadata addition with default)
ALTER TABLE agents ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE identity_credentials ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE auth_providers ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_saas_operator BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE spend_budgets ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE spend_snapshots ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE spend_increase_requests ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE group_policy_versions ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE provider_keys ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;

-- 3. Composite Indexes for fast tenant-scoped queries
CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents(tenant_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_tenant ON telemetry_events(tenant_id, timestamp_ms DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_providers_tenant ON auth_providers(tenant_id, type);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id, email);
CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies(tenant_id, is_active);
CREATE INDEX IF NOT EXISTS idx_mcp_servers_tenant ON mcp_servers(tenant_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_group_policies_tenant ON group_policy_versions(tenant_id, group_id);

-- Rebuild provider_keys unique index to be tenant-scoped
DROP INDEX IF EXISTS idx_provider_keys_provider;
CREATE UNIQUE INDEX idx_provider_keys_provider ON provider_keys(tenant_id, provider);

-- Rebuild auth_providers local unique index to be tenant-scoped
DROP INDEX IF EXISTS idx_auth_providers_local_unique;
CREATE UNIQUE INDEX idx_auth_providers_local_unique ON auth_providers(tenant_id, type) WHERE type = 'local';

COMMIT;


-- ==================== 000013_user_auth_and_passwords.up.sql ====================
-- Migration: 000012_user_auth_and_passwords.up.sql
-- Description: Allow users without external auth_provider_id and add tenant-scoped email uniqueness

BEGIN;

-- 1. Make auth_provider_id nullable so local tenant users and bootstrap users can exist without OAuth provider
ALTER TABLE users ALTER COLUMN auth_provider_id DROP NOT NULL;

-- 2. Add composite index / unique constraint on (tenant_id, LOWER(email))
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_email_unique ON users(tenant_id, LOWER(email));

COMMIT;


-- ==================== 000014_migrate_agentwall_to_agentcontrol.up.sql ====================
-- Migration: 000014_migrate_agentwall_to_agentcontrol.up.sql
-- Purpose: Formalize transition from AgentWall to Vexa Agent Control in PostgreSQL database.

BEGIN;

-- 1. Update any policy contents containing legacy agentwall references
UPDATE policies
SET content = REPLACE(content, 'agentwall', 'agentcontrol')
WHERE content LIKE '%agentwall%';

UPDATE policies
SET content = REPLACE(content, 'AgentWall', 'AgentControl')
WHERE content LIKE '%AgentWall%';

COMMIT;

