BEGIN;

DROP TABLE IF EXISTS broker_admissions CASCADE;
DROP TABLE IF EXISTS oauth_refresh_tokens CASCADE;
DROP INDEX IF EXISTS uq_device_active_fingerprint;
ALTER TABLE devices
    DROP COLUMN IF EXISTS bound_at,
    DROP COLUMN IF EXISTS key_fingerprint,
    DROP COLUMN IF EXISTS team_id,
    DROP COLUMN IF EXISTS user_id;
DROP TABLE IF EXISTS team_memberships CASCADE;
DROP TABLE IF EXISTS user_identities CASCADE;

COMMIT;
