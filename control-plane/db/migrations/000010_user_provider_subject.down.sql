-- Migration: 000010 — Rollback User Provider Subject & Issuer

BEGIN;

DROP INDEX IF EXISTS uq_users_org_provider_subject;

ALTER TABLE users 
DROP COLUMN IF EXISTS provider_subject,
DROP COLUMN IF EXISTS provider_issuer;

COMMIT;
