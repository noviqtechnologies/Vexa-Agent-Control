-- Revert Migration 000008
BEGIN;

ALTER TABLE devices DROP COLUMN IF EXISTS identity_verified;
ALTER TABLE devices DROP COLUMN IF EXISTS identity_source;

DROP TABLE IF EXISTS request_attributions CASCADE;
DROP TABLE IF EXISTS assignments CASCADE;

COMMIT;
