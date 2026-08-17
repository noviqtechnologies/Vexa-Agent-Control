-- Script: teardown_legacy_db.sql
-- Purpose: Cleanly drop the legacy `agentwall` PostgreSQL database and user role
-- Execute only after verifying full migration to `agentcontrol`.

-- Disconnect any active sessions to legacy agentwall DB
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = 'agentwall' AND pid <> pg_backend_pid();

-- Drop legacy database
DROP DATABASE IF EXISTS agentwall;

-- Optionally drop legacy user
DROP USER IF EXISTS agentwall;
