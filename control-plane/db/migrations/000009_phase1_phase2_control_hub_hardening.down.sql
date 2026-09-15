-- Migration: 000009 (down) — Rollback Phase 1 & 2 Control Hub Hardening
BEGIN;

DROP TABLE IF EXISTS audit_checkpoints CASCADE;
DROP TABLE IF EXISTS device_keys CASCADE;

ALTER TABLE devices DROP COLUMN IF EXISTS capability_vector;
ALTER TABLE devices DROP COLUMN IF EXISTS last_freshness;
ALTER TABLE devices DROP COLUMN IF EXISTS verified_target_states;

ALTER TABLE audit_events DROP COLUMN IF EXISTS event_hash;
ALTER TABLE audit_events DROP COLUMN IF EXISTS prev_event_hash;
ALTER TABLE audit_events DROP COLUMN IF EXISTS sequence_number;

ALTER TABLE telemetry_events DROP COLUMN IF EXISTS event_hash;
ALTER TABLE telemetry_events DROP COLUMN IF EXISTS prev_event_hash;
ALTER TABLE telemetry_events DROP COLUMN IF EXISTS sequence_number;

COMMIT;
