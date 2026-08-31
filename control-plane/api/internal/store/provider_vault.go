package store

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/kms"
)

var (
	ErrProviderKeyNotFound = errors.New("provider key not found")
)

type ProviderKeyMeta struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Provider  string    `json:"provider"`
	KeyAlias  string    `json:"key_alias"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// InsertEncryptedProviderKey encrypts a provider API key using AES-256-GCM with tenant-bound AAD and persists it.
func (s *Store) InsertEncryptedProviderKey(
	ctx context.Context,
	tenantID, provider, keyAlias, plainSecret string,
	kmsProvider kms.KMSProvider,
) error {
	if tenantID == "" || provider == "" || plainSecret == "" {
		return errors.New("tenant_id, provider, and secret are required")
	}

	version := 1
	aad := []byte(fmt.Sprintf("%s|%s|%s|%d", tenantID, provider, keyAlias, version))

	cipherBytes, err := kmsProvider.Encrypt(ctx, []byte(plainSecret), aad)
	if err != nil {
		return fmt.Errorf("encrypt provider key: %w", err)
	}

	cipherHex := hex.EncodeToString(cipherBytes)
	now := time.Now().UTC()

	query := `
	INSERT INTO provider_keys (
		id, tenant_id, provider, key_alias, key_ciphertext, version, created_at, updated_at
	) VALUES (
		gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7
	)
	ON CONFLICT (tenant_id, provider) DO UPDATE
	SET key_alias = EXCLUDED.key_alias,
	    key_ciphertext = EXCLUDED.key_ciphertext,
	    version = provider_keys.version + 1,
	    updated_at = EXCLUDED.updated_at`

	_, err = s.pool.Exec(ctx, query, tenantID, provider, keyAlias, cipherHex, version, now, now)
	return err
}

// GetDecryptedProviderKey retrieves and decrypts the provider key using tenant-bound AAD.
func (s *Store) GetDecryptedProviderKey(
	ctx context.Context,
	tenantID, provider string,
	kmsProvider kms.KMSProvider,
) (string, error) {
	query := `
	SELECT key_alias, key_ciphertext, version
	FROM provider_keys
	WHERE tenant_id = $1 AND provider = $2`

	var keyAlias, cipherHex string
	var version int

	err := s.pool.QueryRow(ctx, query, tenantID, provider).Scan(&keyAlias, &cipherHex, &version)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrProviderKeyNotFound
		}
		return "", err
	}

	cipherBytes, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext hex: %w", err)
	}

	aad := []byte(fmt.Sprintf("%s|%s|%s|%d", tenantID, provider, keyAlias, version))
	plainBytes, err := kmsProvider.Decrypt(ctx, cipherBytes, aad)
	if err != nil {
		return "", fmt.Errorf("decrypt provider key: %w", err)
	}

	return string(plainBytes), nil
}

// ListEncryptedProviderKeys lists metadata for all configured provider keys without decrypting secrets.
func (s *Store) ListEncryptedProviderKeys(ctx context.Context, tenantID string) ([]ProviderKeyMeta, error) {
	query := `
	SELECT id, tenant_id, provider, key_alias, version, created_at, updated_at
	FROM provider_keys
	WHERE tenant_id = $1
	ORDER BY provider ASC`

	rows, err := s.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []ProviderKeyMeta
	for rows.Next() {
		var m ProviderKeyMeta
		if err := rows.Scan(&m.ID, &m.TenantID, &m.Provider, &m.KeyAlias, &m.Version, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, m)
	}

	return list, nil
}

func (s *Store) DeleteEncryptedProviderKey(ctx context.Context, tenantID, provider string) error {
	query := `DELETE FROM provider_keys WHERE tenant_id = $1 AND provider = $2`
	tag, err := s.pool.Exec(ctx, query, tenantID, provider)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrProviderKeyNotFound
	}
	return nil
}
