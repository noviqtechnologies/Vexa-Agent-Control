-- Migration: 000005 — Add missing columns for Enrollment v2 and Device Certificates
-- Fixes: ERROR: column "expected_device_label" does not exist (SQLSTATE 42703) on POST /api/v2/admin/enrollment-tokens

BEGIN;

ALTER TABLE enrollment_tokens
    ADD COLUMN IF NOT EXISTS expected_device_label TEXT,
    ADD COLUMN IF NOT EXISTS target_owner_subject TEXT;

ALTER TABLE enrollment_transactions
    ADD COLUMN IF NOT EXISTS os_version_summary TEXT,
    ADD COLUMN IF NOT EXISTS display_name TEXT,
    ADD COLUMN IF NOT EXISTS owner_subject TEXT,
    ADD COLUMN IF NOT EXISTS enrollment_ed25519_public_key BYTEA,
    ADD COLUMN IF NOT EXISTS mtls_csr_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS mtls_csr_pem TEXT,
    ADD COLUMN IF NOT EXISTS os_family TEXT,
    ADD COLUMN IF NOT EXISTS architecture TEXT,
    ADD COLUMN IF NOT EXISTS failure_code TEXT;

CREATE TABLE IF NOT EXISTS enrollment_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    transaction_id UUID NOT NULL REFERENCES enrollment_transactions(id) ON DELETE CASCADE,
    challenge_hash BYTEA NOT NULL,
    transcript_sha256 TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE device_certificates
    ADD COLUMN IF NOT EXISTS ca_resource_name TEXT,
    ADD COLUMN IF NOT EXISTS certificate_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS sha256_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS csr_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS public_key_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS renew_after TIMESTAMPTZ;

COMMIT;
