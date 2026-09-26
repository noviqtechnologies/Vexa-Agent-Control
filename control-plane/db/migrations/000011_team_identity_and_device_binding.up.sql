BEGIN;

-- 1. Immutable User Identities (Single Source of Truth)
CREATE TABLE IF NOT EXISTS user_identities (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id    UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider_id        UUID NOT NULL REFERENCES auth_providers(id) ON DELETE CASCADE,
    identity_issuer    TEXT NOT NULL,
    identity_subject   TEXT NOT NULL,
    identity_email     TEXT,
    email_verified     BOOLEAN NOT NULL DEFAULT false,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_user_identity_org_provider_issuer_subject 
        UNIQUE (organization_id, provider_id, identity_issuer, identity_subject)
);

CREATE INDEX IF NOT EXISTS idx_user_identities_lookup 
    ON user_identities(organization_id, provider_id, identity_issuer, identity_subject);
CREATE INDEX IF NOT EXISTS idx_user_identities_user 
    ON user_identities(user_id);

-- Backfill from existing users table if provider_subject is present
INSERT INTO user_identities (user_id, organization_id, provider_id, identity_issuer, identity_subject, identity_email, email_verified)
SELECT 
    u.id, 
    u.organization_id, 
    ap.id, 
    COALESCE(u.provider_issuer, 'accounts.google.com'), 
    u.provider_subject, 
    u.email, 
    true
FROM users u
JOIN auth_providers ap ON ap.organization_id = u.organization_id 
    AND (u.auth_provider_id = ap.id OR (u.auth_provider_id IS NULL AND ap.type != 'local'))
WHERE u.provider_subject IS NOT NULL AND u.provider_subject != ''
ON CONFLICT DO NOTHING;

-- 2. First-Class Team Memberships
CREATE TABLE IF NOT EXISTS team_memberships (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id    UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id            TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role               TEXT NOT NULL DEFAULT 'MEMBER',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_team_membership UNIQUE (team_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_team_memberships_user ON team_memberships(user_id);

-- Auto-assign existing users to 'default' team
INSERT INTO team_memberships (organization_id, team_id, user_id, role)
SELECT u.organization_id, 'default', u.id, 'MEMBER'
FROM users u
ON CONFLICT DO NOTHING;

-- 3. Clean Devices Association
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS user_id          UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS team_id          TEXT REFERENCES teams(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS key_fingerprint  TEXT,
    ADD COLUMN IF NOT EXISTS bound_at         TIMESTAMPTZ;

CREATE UNIQUE INDEX IF NOT EXISTS uq_device_active_fingerprint
    ON devices(key_fingerprint)
    WHERE state != 'REVOKED' AND key_fingerprint IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_devices_user_id
    ON devices(user_id);

-- 4. Transactional Token Family Rotation Table
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    family_id          UUID NOT NULL,
    parent_token_id    UUID REFERENCES oauth_refresh_tokens(id),
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id    UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id            TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    device_id          UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    token_hash         TEXT NOT NULL UNIQUE,
    consumed_at        TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ,
    expires_at         TIMESTAMPTZ NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family 
    ON oauth_refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_active_lookup 
    ON oauth_refresh_tokens(token_hash) 
    WHERE revoked_at IS NULL AND consumed_at IS NULL;

-- 5. Append-Only Admission & Attribution Ledger
CREATE TABLE IF NOT EXISTS broker_admissions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id         TEXT NOT NULL UNIQUE,
    organization_id    UUID NOT NULL REFERENCES organizations(id),
    team_id            TEXT NOT NULL,
    user_id            UUID NOT NULL REFERENCES users(id),
    device_id          UUID NOT NULL REFERENCES devices(id),
    credential_id      TEXT NOT NULL,
    policy_version     TEXT NOT NULL,
    provider           TEXT NOT NULL,
    model              TEXT NOT NULL,
    estimated_cost     NUMERIC(12, 6) DEFAULT 0,
    settled_cost       NUMERIC(12, 6) DEFAULT 0,
    status             TEXT NOT NULL, -- ADMITTED | SETTLED | REJECTED | FAILED
    admitted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    settled_at         TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_broker_admissions_user ON broker_admissions(user_id, admitted_at DESC);
CREATE INDEX IF NOT EXISTS idx_broker_admissions_team ON broker_admissions(team_id, admitted_at DESC);

COMMIT;
