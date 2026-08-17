-- Migration: 000014_migrate_agentwall_to_agentcontrol.up.sql
-- Purpose: Formalize transition from AgentWall to Vexa Agent Control in PostgreSQL database.

BEGIN;

-- 1. Update any policy contents containing legacy agentwall references
UPDATE policies
SET content = REPLACE(content, 'agentwall', 'agentcontrol')
WHERE content LIKE '%agentwall%';

UPDATE policies
SET content = REPLACE(content, 'AgentWall', 'AgentControl')
WHERE content LIKE '%AgentWall%';

COMMIT;
