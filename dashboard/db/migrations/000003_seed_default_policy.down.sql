-- Rollback: remove the seeded default policy (v1.0.0 only).
-- Does NOT remove admin-saved policies.
BEGIN;
DELETE FROM policies WHERE version = 'v1.0.0';
COMMIT;
