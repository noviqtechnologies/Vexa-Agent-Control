CREATE TABLE IF NOT EXISTS provider_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider VARCHAR(255) NOT NULL,
    api_key_encrypted TEXT NOT NULL,
    api_key_masked VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Note: We only allow one active key per provider for simplicity right now.
CREATE UNIQUE INDEX idx_provider_keys_provider ON provider_keys(provider);
