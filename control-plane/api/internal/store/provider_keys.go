package store

import (
	"context"
	"time"
)

type ProviderKey struct {
	ID             string    `json:"id"`
	Provider       string    `json:"provider"`
	APIKeyMasked   string    `json:"api_key_masked"`
	APIKeyEncrypted string   `json:"api_key_encrypted,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

func (s *Store) InsertProviderKey(ctx context.Context, k *ProviderKey) error {
	q := `
		INSERT INTO provider_keys (provider, api_key_encrypted, api_key_masked)
		VALUES ($1, $2, $3)
		ON CONFLICT (provider) 
		DO UPDATE SET api_key_encrypted = EXCLUDED.api_key_encrypted, api_key_masked = EXCLUDED.api_key_masked
		RETURNING id, created_at
	`
	return s.pool.QueryRow(ctx, q, k.Provider, k.APIKeyEncrypted, k.APIKeyMasked).
		Scan(&k.ID, &k.CreatedAt)
}

func (s *Store) ListProviderKeys(ctx context.Context) ([]ProviderKey, error) {
	q := `SELECT id, provider, api_key_masked, created_at FROM provider_keys ORDER BY created_at DESC`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []ProviderKey
	for rows.Next() {
		var k ProviderKey
		if err := rows.Scan(&k.ID, &k.Provider, &k.APIKeyMasked, &k.CreatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (s *Store) DeleteProviderKey(ctx context.Context, id string) error {
	q := `DELETE FROM provider_keys WHERE id = $1`
	_, err := s.pool.Exec(ctx, q, id)
	return err
}

func (s *Store) GetProviderKeyByProvider(ctx context.Context, provider string) (*ProviderKey, error) {
	q := `SELECT id, provider, api_key_masked, api_key_encrypted, created_at FROM provider_keys WHERE LOWER(provider) = LOWER($1)`
	var k ProviderKey
	err := s.pool.QueryRow(ctx, q, provider).Scan(&k.ID, &k.Provider, &k.APIKeyMasked, &k.APIKeyEncrypted, &k.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

