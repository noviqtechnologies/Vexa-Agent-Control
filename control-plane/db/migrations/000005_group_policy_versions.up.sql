CREATE TABLE IF NOT EXISTS group_policy_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    claims JSONB NOT NULL, -- The group claims to match
    tools JSONB NOT NULL, -- Array of tool rules
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT NOT NULL,
    active BOOLEAN DEFAULT false,
    UNIQUE(group_id, version)
);

CREATE INDEX idx_group_policy_versions_group_id ON group_policy_versions(group_id);
CREATE INDEX idx_group_policy_versions_active ON group_policy_versions(group_id) WHERE active = true;
