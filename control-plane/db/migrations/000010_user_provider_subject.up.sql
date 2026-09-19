-- Migration: 000010 — User Provider Subject & Issuer for OIDC
-- Adds provider_subject and provider_issuer columns to users table
-- with a unique index ensuring 1:1 durable mapping per auth provider.

BEGIN;

ALTER TABLE users 
ADD COLUMN IF NOT EXISTS provider_subject TEXT,
ADD COLUMN IF NOT EXISTS provider_issuer TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS uq_users_org_provider_subject 
ON users (organization_id, auth_provider_id, provider_subject) 
WHERE provider_subject IS NOT NULL;

COMMIT;
