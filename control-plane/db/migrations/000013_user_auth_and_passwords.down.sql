-- Migration: 000012_user_auth_and_passwords.down.sql

BEGIN;

DROP INDEX IF EXISTS idx_users_tenant_email_unique;

COMMIT;
