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
