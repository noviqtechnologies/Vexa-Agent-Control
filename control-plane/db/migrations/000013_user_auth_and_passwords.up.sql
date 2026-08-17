-- Migration: 000012_user_auth_and_passwords.up.sql
-- Description: Allow users without external auth_provider_id and add tenant-scoped email uniqueness

BEGIN;

-- 1. Make auth_provider_id nullable so local tenant users and bootstrap users can exist without OAuth provider
ALTER TABLE users ALTER COLUMN auth_provider_id DROP NOT NULL;

-- 2. Add composite index / unique constraint on (tenant_id, LOWER(email))
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_email_unique ON users(tenant_id, LOWER(email));

COMMIT;
