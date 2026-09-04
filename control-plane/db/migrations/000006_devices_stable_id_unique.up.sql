-- Migration: 000006 — Add unique index on devices(stable_device_id) and device_certificates(serial_number) for ON CONFLICT upserts
BEGIN;

CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_stable_device_id ON devices(stable_device_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_device_certs_serial ON device_certificates(serial_number);

COMMIT;
