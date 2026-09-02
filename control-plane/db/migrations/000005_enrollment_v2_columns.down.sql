-- Migration Down: 000005 — Revert missing columns for Enrollment v2

BEGIN;

ALTER TABLE device_certificates
    DROP COLUMN IF EXISTS ca_resource_name,
    DROP COLUMN IF EXISTS certificate_fingerprint,
    DROP COLUMN IF EXISTS sha256_fingerprint,
    DROP COLUMN IF EXISTS csr_sha256,
    DROP COLUMN IF EXISTS public_key_fingerprint,
    DROP COLUMN IF EXISTS renew_after;

DROP TABLE IF EXISTS enrollment_challenges CASCADE;

ALTER TABLE enrollment_transactions
    DROP COLUMN IF EXISTS os_version_summary,
    DROP COLUMN IF EXISTS display_name,
    DROP COLUMN IF EXISTS owner_subject,
    DROP COLUMN IF EXISTS enrollment_ed25519_public_key,
    DROP COLUMN IF EXISTS mtls_csr_sha256,
    DROP COLUMN IF EXISTS mtls_csr_pem,
    DROP COLUMN IF EXISTS os_family,
    DROP COLUMN IF EXISTS architecture,
    DROP COLUMN IF EXISTS failure_code;

ALTER TABLE enrollment_tokens
    DROP COLUMN IF EXISTS expected_device_label,
    DROP COLUMN IF EXISTS target_owner_subject;

COMMIT;
