-- Migration: 000010_device_governance.down.sql
-- Description: Rollback device governance and compliance tables.

BEGIN;

DROP TABLE IF EXISTS device_tamper_events CASCADE;
DROP TABLE IF EXISTS device_ide_status CASCADE;
DROP TABLE IF EXISTS device_compliance_reports CASCADE;
DROP TABLE IF EXISTS device_enrollments CASCADE;

COMMIT;
