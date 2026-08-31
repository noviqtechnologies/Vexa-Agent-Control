-- Migration: 000002 rollback — Pillar 1 & 2 teardown
-- Drops virtual_keys and provider_keys tables and all associated indexes.
-- WARNING: This permanently destroys all virtual key and encrypted provider key data.

BEGIN;

-- Drop provider vault first (no FK deps)
DROP TABLE IF EXISTS provider_keys CASCADE;

-- Drop virtual key table
DROP TABLE IF EXISTS virtual_keys CASCADE;

COMMIT;
