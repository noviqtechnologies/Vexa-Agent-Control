package store

import (
	"context"
	"time"
)

type ProviderKey struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	Provider        string    `json:"provider"`
	KeyAlias        string    `json:"key_alias,omitempty"`
	Version         int       `json:"version,omitempty"`
	Status          string    `json:"status,omitempty"` // ACTIVE, RETIRING, REVOKED
	APIKeyMasked    string    `json:"api_key_masked"`
	APIKeyEncrypted string    `json:"api_key_encrypted,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// EnsureProviderKeysSchema guarantees schema consistency for the provider_keys table.
func (s *Store) EnsureProviderKeysSchema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	q := `
		CREATE TABLE IF NOT EXISTS provider_keys (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			provider TEXT NOT NULL,
			key_alias TEXT NOT NULL DEFAULT 'default',
			version INT NOT NULL DEFAULT 1,
			status TEXT NOT NULL DEFAULT 'ACTIVE',
			api_key_masked TEXT NOT NULL DEFAULT '',
			api_key_encrypted TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (tenant_id, provider)
		);

		DO $$
		BEGIN
			IF EXISTS (
				SELECT 1 FROM information_schema.columns 
				WHERE table_name = 'provider_keys' AND column_name = 'key_preview'
			) AND NOT EXISTS (
				SELECT 1 FROM information_schema.columns 
				WHERE table_name = 'provider_keys' AND column_name = 'api_key_masked'
			) THEN
				ALTER TABLE provider_keys RENAME COLUMN key_preview TO api_key_masked;
			END IF;

			IF EXISTS (
				SELECT 1 FROM information_schema.columns 
				WHERE table_name = 'provider_keys' AND column_name = 'encrypted_key'
			) AND NOT EXISTS (
				SELECT 1 FROM information_schema.columns 
				WHERE table_name = 'provider_keys' AND column_name = 'api_key_encrypted'
			) THEN
				ALTER TABLE provider_keys RENAME COLUMN encrypted_key TO api_key_encrypted;
			END IF;
		END $$;

		ALTER TABLE provider_keys ADD COLUMN IF NOT EXISTS key_alias TEXT NOT NULL DEFAULT 'default';
		ALTER TABLE provider_keys ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 1;
		ALTER TABLE provider_keys ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'ACTIVE';
		ALTER TABLE provider_keys ADD COLUMN IF NOT EXISTS api_key_masked TEXT NOT NULL DEFAULT '';
		ALTER TABLE provider_keys ADD COLUMN IF NOT EXISTS api_key_encrypted TEXT NOT NULL DEFAULT '';
		CREATE UNIQUE INDEX IF NOT EXISTS idx_provider_keys_provider ON provider_keys(tenant_id, provider);
	`
	_, err := s.pool.Exec(ctx, q)
	return err
}

func (s *Store) InsertProviderKey(ctx context.Context, tenantID string, k *ProviderKey) error {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	k.TenantID = tenantID
	if k.KeyAlias == "" {
		k.KeyAlias = "default"
	}
	if k.Version <= 0 {
		k.Version = 1
	}
	if k.Status == "" {
		k.Status = "ACTIVE"
	}
	q := `
		INSERT INTO provider_keys (tenant_id, provider, key_alias, version, status, api_key_encrypted, api_key_masked)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, provider) 
		DO UPDATE SET api_key_encrypted = EXCLUDED.api_key_encrypted, 
		              api_key_masked = EXCLUDED.api_key_masked,
		              key_alias = EXCLUDED.key_alias,
		              version = EXCLUDED.version,
		              status = EXCLUDED.status,
		              updated_at = now()
		RETURNING id, created_at
	`
	return s.pool.QueryRow(ctx, q, tenantID, k.Provider, k.KeyAlias, k.Version, k.Status, k.APIKeyEncrypted, k.APIKeyMasked).
		Scan(&k.ID, &k.CreatedAt)
}

func (s *Store) ListProviderKeys(ctx context.Context, tenantID string) ([]ProviderKey, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	q := `SELECT id, tenant_id, provider, key_alias, version, status, api_key_masked, created_at FROM provider_keys WHERE tenant_id = $1 ORDER BY created_at DESC`
	rows, err := s.pool.Query(ctx, q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []ProviderKey
	for rows.Next() {
		var k ProviderKey
		if err := rows.Scan(&k.ID, &k.TenantID, &k.Provider, &k.KeyAlias, &k.Version, &k.Status, &k.APIKeyMasked, &k.CreatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (s *Store) DeleteProviderKey(ctx context.Context, tenantID, id string) error {
	if tenantID != "" {
		q := `DELETE FROM provider_keys WHERE id = $1 AND tenant_id = $2`
		_, err := s.pool.Exec(ctx, q, id, tenantID)
		return err
	}
	q := `DELETE FROM provider_keys WHERE id = $1`
	_, err := s.pool.Exec(ctx, q, id)
	return err
}

func (s *Store) GetProviderKeyByProvider(ctx context.Context, tenantID, provider string) (*ProviderKey, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	q := `SELECT id, tenant_id, provider, key_alias, version, status, api_key_masked, api_key_encrypted, created_at 
	      FROM provider_keys 
	      WHERE tenant_id = $1 AND LOWER(provider) = LOWER($2) AND status = 'ACTIVE'
	      LIMIT 1`
	var k ProviderKey
	err := s.pool.QueryRow(ctx, q, tenantID, provider).Scan(
		&k.ID, &k.TenantID, &k.Provider, &k.KeyAlias, &k.Version, &k.Status, &k.APIKeyMasked, &k.APIKeyEncrypted, &k.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &k, nil
}
