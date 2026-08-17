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
