BEGIN;

-- 1. Route Profiles: Versioned, immutable routing configurations
CREATE TABLE IF NOT EXISTS route_profiles (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    version               INT NOT NULL DEFAULT 1,
    content_digest        TEXT NOT NULL,
    api_family            TEXT NOT NULL DEFAULT 'chat_completions',
    match_model           TEXT NOT NULL DEFAULT '*',
    primary_provider      TEXT NOT NULL,
    primary_model         TEXT NOT NULL,
    fallback_provider     TEXT,
    fallback_model        TEXT,
    max_attempts          INT NOT NULL DEFAULT 2 CHECK (max_attempts BETWEEN 1 AND 2),
    deadline_ms           INT NOT NULL DEFAULT 30000,
    retry_classes         TEXT[] NOT NULL DEFAULT ARRAY['502', '503', '504', '429', 'connect_timeout', 'dns_error'],
    allowed_regions       TEXT[] NOT NULL DEFAULT ARRAY['*'],
    is_active             BOOLEAN NOT NULL DEFAULT false,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by            TEXT NOT NULL DEFAULT 'system',
    CONSTRAINT uq_route_profile_org_digest UNIQUE (organization_id, content_digest)
);

CREATE INDEX IF NOT EXISTS idx_route_profiles_org_active ON route_profiles(organization_id, is_active);
CREATE INDEX IF NOT EXISTS idx_route_profiles_lookup ON route_profiles(organization_id, api_family, match_model);

-- 2. Route Profile Activations: Immutable audit history of active profile deployments
CREATE TABLE IF NOT EXISTS route_profile_activations (
    id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id            UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    route_profile_id           UUID NOT NULL REFERENCES route_profiles(id) ON DELETE CASCADE,
    version                    INT NOT NULL,
    content_digest             TEXT NOT NULL,
    activated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_by               TEXT NOT NULL DEFAULT 'system',
    reason                     TEXT NOT NULL DEFAULT 'admin_activation',
    rollback_from_activation_id UUID REFERENCES route_profile_activations(id)
);

CREATE INDEX IF NOT EXISTS idx_route_activations_org ON route_profile_activations(organization_id, activated_at DESC);

-- 3. Broker Requests: Logical request admission & outcome lifecycle
CREATE TABLE IF NOT EXISTS broker_requests (
    request_id                 TEXT PRIMARY KEY,
    organization_id            UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    idempotency_key            TEXT,
    trace_id                   TEXT,
    principal_device_id        TEXT,
    principal_user_id          TEXT,
    route_profile_id           UUID REFERENCES route_profiles(id),
    policy_version_id          TEXT,
    requested_provider         TEXT NOT NULL,
    requested_model            TEXT NOT NULL,
    stream                     BOOLEAN NOT NULL DEFAULT false,
    status                     TEXT NOT NULL DEFAULT 'admitted', -- admitted | in_flight | succeeded | failed | denied
    terminal_reason_code       TEXT,
    spend_reservation_id       TEXT,
    settled_microcents         BIGINT NOT NULL DEFAULT 0,
    request_hash               TEXT,
    cached_response            JSONB,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at               TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_broker_requests_org_created ON broker_requests(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_broker_requests_idempotency ON broker_requests(organization_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_broker_requests_trace ON broker_requests(trace_id) WHERE trace_id IS NOT NULL;

-- 4. Broker Attempts: Ordered upstream execution records per logical request
CREATE TABLE IF NOT EXISTS broker_attempts (
    attempt_id                 TEXT PRIMARY KEY,
    request_id                 TEXT NOT NULL REFERENCES broker_requests(request_id) ON DELETE CASCADE,
    attempt_number             INT NOT NULL CHECK (attempt_number BETWEEN 1 AND 2),
    target_type                TEXT NOT NULL CHECK (target_type IN ('primary', 'fallback')),
    provider                   TEXT NOT NULL,
    model                      TEXT NOT NULL,
    started_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at               TIMESTAMPTZ,
    latency_ms                 INT NOT NULL DEFAULT 0,
    http_status                INT NOT NULL DEFAULT 0,
    error_class                TEXT,
    error_message_redacted     TEXT,
    stream_committed           BOOLEAN NOT NULL DEFAULT false,
    input_tokens               BIGINT NOT NULL DEFAULT 0,
    output_tokens              BIGINT NOT NULL DEFAULT 0,
    cached_tokens              BIGINT NOT NULL DEFAULT 0,
    usage_source               TEXT NOT NULL DEFAULT 'provider_reported',
    CONSTRAINT uq_broker_attempt_req_num UNIQUE (request_id, attempt_number)
);

CREATE INDEX IF NOT EXISTS idx_broker_attempts_req_num ON broker_attempts(request_id, attempt_number ASC);

COMMIT;
