-- Rollback: 000007 — Drop device_compliance_reports table
BEGIN;

DROP TABLE IF EXISTS device_compliance_reports CASCADE;

COMMIT;
