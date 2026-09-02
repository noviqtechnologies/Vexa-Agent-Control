-- Migration: 000004 DOWN — Remove owner_type and budget_period from virtual_keys

BEGIN;

ALTER TABLE virtual_keys
    DROP COLUMN IF EXISTS owner_type,
    DROP COLUMN IF EXISTS budget_period;

COMMIT;
