package store

import (
	"context"
	"time"
)

type ProviderKey struct {
	ID              string    `json:"id"`
	OrganizationID  string    `json:"organization_id"`
	TenantID        string    `json:"tenant_id"` // Alias
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
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			provider TEXT NOT NULL,
			key_alias TEXT NOT NULL DEFAULT 'default',
			version INT NOT NULL DEFAULT 1,
			status TEXT NOT NULL DEFAULT 'ACTIVE',
			api_key_masked TEXT NOT NULL DEFAULT '',
			api_key_encrypted TEXT NOT NULL DEFAULT '',
			is_default BOOLEAN NOT NULL DEFAULT true,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT uq_provider_alias UNIQUE (organization_id, provider, key_alias)
		);
		ALTER TABLE provider_keys ADD COLUMN IF NOT EXISTS key_alias TEXT NOT NULL DEFAULT 'default';
		ALTER TABLE provider_keys ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 1;
		ALTER TABLE provider_keys ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'ACTIVE';
		CREATE INDEX IF NOT EXISTS idx_provider_keys_org ON provider_keys(organization_id, provider);
	`
	_, err := s.pool.Exec(ctx, q)
	return err
}

func (s *Store) InsertProviderKey(ctx context.Context, organizationID string, k *ProviderKey) error {
	if s.pool == nil {
		return nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	k.OrganizationID = organizationID
	k.TenantID = organizationID
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
		INSERT INTO provider_keys (organization_id, provider, key_alias, version, status, api_key_encrypted, api_key_masked)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (organization_id, provider, key_alias) 
		DO UPDATE SET api_key_encrypted = EXCLUDED.api_key_encrypted, 
		              api_key_masked = EXCLUDED.api_key_masked,
		              version = EXCLUDED.version,
		              status = EXCLUDED.status,
		              updated_at = now()
		RETURNING id, created_at
	`
	err := s.pool.QueryRow(ctx, q, organizationID, k.Provider, k.KeyAlias, k.Version, k.Status, k.APIKeyEncrypted, k.APIKeyMasked).
		Scan(&k.ID, &k.CreatedAt)
	return err
}

func (s *Store) ListProviderKeys(ctx context.Context, organizationID string) ([]ProviderKey, error) {
	if s.pool == nil {
		return []ProviderKey{}, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	q := `
		SELECT id, organization_id, provider, key_alias, version, status, api_key_masked, created_at
		FROM provider_keys
		WHERE organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid
		ORDER BY provider ASC
	`
	rows, err := s.pool.Query(ctx, q, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []ProviderKey
	for rows.Next() {
		var k ProviderKey
		if err := rows.Scan(
			&k.ID, &k.OrganizationID, &k.Provider, &k.KeyAlias, &k.Version, &k.Status, &k.APIKeyMasked, &k.CreatedAt,
		); err != nil {
			return nil, err
		}
		k.TenantID = k.OrganizationID
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *Store) GetProviderKey(ctx context.Context, organizationID, provider string) (*ProviderKey, error) {
	if s.pool == nil {
		return nil, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	q := `
		SELECT id, organization_id, provider, key_alias, version, status, api_key_masked, api_key_encrypted, created_at
		FROM provider_keys
		WHERE provider = $2 AND (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
		LIMIT 1
	`
	var k ProviderKey
	err := s.pool.QueryRow(ctx, q, organizationID, provider).Scan(
		&k.ID, &k.OrganizationID, &k.Provider, &k.KeyAlias, &k.Version, &k.Status, &k.APIKeyMasked, &k.APIKeyEncrypted, &k.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	k.TenantID = k.OrganizationID
	return &k, nil
}

func (s *Store) GetProviderKeyByProvider(ctx context.Context, organizationID, provider string) (*ProviderKey, error) {
	return s.GetProviderKey(ctx, organizationID, provider)
}

func (s *Store) DeleteProviderKey(ctx context.Context, organizationID, provider string) error {
	if s.pool == nil {
		return nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	q := `DELETE FROM provider_keys WHERE provider = $2 AND (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)`
	_, err := s.pool.Exec(ctx, q, organizationID, provider)
	return err
}
