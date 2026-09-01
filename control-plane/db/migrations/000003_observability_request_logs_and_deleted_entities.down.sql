-- Revert Migration 000003

BEGIN;

DROP INDEX IF EXISTS idx_audit_events_action;
DROP INDEX IF EXISTS idx_audit_events_resource;
DROP INDEX IF EXISTS idx_audit_events_tenant_time;

DROP INDEX IF EXISTS idx_virtual_keys_deleted;
ALTER TABLE virtual_keys
    DROP COLUMN IF EXISTS deleted_reason,
    DROP COLUMN IF EXISTS deleted_by,
    DROP COLUMN IF EXISTS deleted_at;

DROP INDEX IF EXISTS idx_spend_reservations_created_desc;
DROP INDEX IF EXISTS idx_spend_reservations_vk;
DROP INDEX IF EXISTS idx_spend_reservations_session;

ALTER TABLE spend_reservations
    DROP COLUMN IF EXISTS status_code,
    DROP COLUMN IF EXISTS request_type,
    DROP COLUMN IF EXISTS tags,
    DROP COLUMN IF EXISTS end_user_id,
    DROP COLUMN IF EXISTS internal_user_id,
    DROP COLUMN IF EXISTS session_id,
    DROP COLUMN IF EXISTS virtual_key_alias,
    DROP COLUMN IF EXISTS virtual_key_prefix,
    DROP COLUMN IF EXISTS virtual_key_hash,
    DROP COLUMN IF EXISTS virtual_key_id,
    DROP COLUMN IF EXISTS cached_tokens,
    DROP COLUMN IF EXISTS output_tokens,
    DROP COLUMN IF EXISTS input_tokens,
    DROP COLUMN IF EXISTS ttft_ms;

COMMIT;
