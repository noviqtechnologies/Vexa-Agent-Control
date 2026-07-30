BEGIN;

CREATE TABLE spend_budgets (
    scope_type TEXT NOT NULL,
    scope_key  TEXT NOT NULL DEFAULT '',
    cap_cents  BIGINT NOT NULL,
    period     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_type, scope_key)
);

CREATE TABLE spend_snapshots (
    agent_id     TEXT NOT NULL REFERENCES agents(agent_id),
    period_start TIMESTAMPTZ NOT NULL,
    spent_cents  BIGINT NOT NULL,
    cap_cents    BIGINT,
    is_estimated BOOLEAN NOT NULL DEFAULT true,
    pricing_table_version TEXT,
    synced_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, period_start)
);

CREATE TABLE spend_increase_requests (
    request_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id     TEXT NOT NULL REFERENCES agents(agent_id),
    current_cap  BIGINT NOT NULL,
    reason       TEXT,
    status       TEXT NOT NULL DEFAULT 'pending',
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at  TIMESTAMPTZ,
    resolved_by  TEXT,
    new_cap      BIGINT
);

COMMIT;
