-- Migration: 000004 — Add owner_type and budget_period columns to virtual_keys
-- Fixes: ERROR: column "owner_type" does not exist (SQLSTATE 42703)
--        These columns were added to the Go model but never migrated to existing databases.

BEGIN;

ALTER TABLE virtual_keys
    ADD COLUMN IF NOT EXISTS owner_type    TEXT NOT NULL DEFAULT 'user',
    ADD COLUMN IF NOT EXISTS budget_period TEXT NOT NULL DEFAULT 'monthly';

COMMIT;
