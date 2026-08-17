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
