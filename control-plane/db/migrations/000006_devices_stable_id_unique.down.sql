-- Rollback: 000006 — Drop unique indexes
BEGIN;

DROP INDEX IF EXISTS idx_devices_stable_device_id;
DROP INDEX IF EXISTS idx_device_certs_serial;

COMMIT;
