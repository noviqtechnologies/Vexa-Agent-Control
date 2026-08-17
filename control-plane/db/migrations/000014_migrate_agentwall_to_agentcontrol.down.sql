-- Migration: 000014_migrate_agentwall_to_agentcontrol.down.sql
-- Purpose: Revert 000014 migration.

BEGIN;

-- No-op revert for text updates
SELECT 1;

COMMIT;
