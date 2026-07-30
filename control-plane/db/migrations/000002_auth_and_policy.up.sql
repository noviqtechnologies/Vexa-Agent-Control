BEGIN;

-- ─── auth_providers ────────────────────────────────────────────────────────────
CREATE TYPE auth_provider_type AS ENUM ('local', 'github', 'google');

CREATE TABLE auth_providers (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type          auth_provider_type NOT NULL,
    name          TEXT NOT NULL,
    client_id     TEXT,
    client_secret TEXT,
    issuer_url    TEXT,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    email_domains TEXT[] NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Ensure only one local provider can exist
CREATE UNIQUE INDEX idx_auth_providers_local_unique ON auth_providers (type) WHERE type = 'local';

-- ─── users ──────────────────────────────────────────────────────────────────────
CREATE TABLE users (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_provider_id UUID NOT NULL REFERENCES auth_providers(id) ON DELETE CASCADE,
    email            TEXT NOT NULL,
    password_hash    TEXT, -- only for local users
    is_admin         BOOLEAN NOT NULL DEFAULT false,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(auth_provider_id, email)
);

-- ─── policies ───────────────────────────────────────────────────────────────────
-- AgentWall uses policy YAML. We will store it in DB to allow dynamic updates via UI.
CREATE TABLE policies (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version    TEXT NOT NULL UNIQUE,
    content    TEXT NOT NULL, -- The YAML content
    is_active  BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Ensure only one active policy
CREATE UNIQUE INDEX idx_policies_active_unique ON policies (is_active) WHERE is_active = true;

COMMIT;
