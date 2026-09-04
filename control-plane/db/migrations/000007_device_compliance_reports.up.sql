-- Migration: 000007 — Add device_compliance_reports table for coverage and health monitoring
BEGIN;

CREATE TABLE IF NOT EXISTS device_compliance_reports (
    report_id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id                 UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE UNIQUE,
    overall_compliance        TEXT NOT NULL DEFAULT 'COMPLIANT',
    tamper_event_count_24h    INT NOT NULL DEFAULT 0,
    mcp_servers_total         INT NOT NULL DEFAULT 0,
    mcp_servers_wrapped       INT NOT NULL DEFAULT 0,
    report_payload            JSONB NOT NULL DEFAULT '[]'::jsonb,
    generated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_compliance_reports_device ON device_compliance_reports(device_id);

COMMIT;
