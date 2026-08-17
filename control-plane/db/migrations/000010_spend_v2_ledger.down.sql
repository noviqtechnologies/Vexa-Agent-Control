-- Migration: 000009_spend_v2_ledger.down.sql

BEGIN;

DROP TABLE IF EXISTS spend_v2_increase_requests CASCADE;
DROP TABLE IF EXISTS spend_idempotency CASCADE;
DROP TABLE IF EXISTS spend_events CASCADE;
DROP TABLE IF EXISTS spend_reservations CASCADE;
DROP TABLE IF EXISTS price_book_items CASCADE;
DROP TABLE IF EXISTS price_book_versions CASCADE;
DROP TABLE IF EXISTS budget_windows CASCADE;
DROP TABLE IF EXISTS spend_policy_versions CASCADE;
DROP TABLE IF EXISTS spend_policies CASCADE;

COMMIT;
