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
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	TenantID       string    `json:"tenant_id"` // Alias for backward compatibility
	Provider       string    `json:"provider"`
	KeyAlias       string    `json:"key_alias"`
	Version        int       `json:"version"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func maskSecret(s string) string {
	if len(s) > 8 {
		return s[:3] + "..." + s[len(s)-4:]
	}
	return "***"
}

// InsertEncryptedProviderKey encrypts a provider API key using AES-256-GCM envelope encryption and persists it to provider_keys.
func (s *Store) InsertEncryptedProviderKey(
	ctx context.Context,
	orgID, provider, keyAlias, plainSecret string,
	kmsProvider kms.KMSProvider,
) error {
	if s.pool == nil {
		return errors.New("database pool not initialized")
	}
	if orgID == "" {
		orgID = DefaultOrgID
	}
	if keyAlias == "" {
		keyAlias = "default"
	}
	if provider == "" || plainSecret == "" {
		return errors.New("provider and plainSecret are required")
	}

	version := 1
	aad := []byte(fmt.Sprintf("%s|%s|%s|%d", orgID, provider, keyAlias, version))

	cipherBytes, err := kmsProvider.Encrypt(ctx, []byte(plainSecret), aad)
	if err != nil {
		return fmt.Errorf("encrypt provider key: %w", err)
	}

	cipherHex := hex.EncodeToString(cipherBytes)
	masked := maskSecret(plainSecret)
	now := time.Now().UTC()

	query := `
	INSERT INTO provider_keys (
		id, organization_id, provider, key_alias, version, status, api_key_encrypted, api_key_masked, created_at, updated_at
	) VALUES (
		gen_random_uuid(), $1, $2, $3, $4, 'ACTIVE', $5, $6, $7, $8
	)
	ON CONFLICT (organization_id, provider, key_alias) DO UPDATE
	SET api_key_encrypted = EXCLUDED.api_key_encrypted,
	    api_key_masked = EXCLUDED.api_key_masked,
	    version = provider_keys.version + 1,
	    status = 'ACTIVE',
	    updated_at = EXCLUDED.updated_at`

	_, err = s.pool.Exec(ctx, query, orgID, provider, keyAlias, version, cipherHex, masked, now, now)
	return err
}

// GetDecryptedProviderKey retrieves and decrypts the provider key using organization-bound AAD.
func (s *Store) GetDecryptedProviderKey(
	ctx context.Context,
	orgID, provider string,
	kmsProvider kms.KMSProvider,
) (string, error) {
	if s.pool == nil {
		return "", errors.New("database pool not initialized")
	}
	if orgID == "" {
		orgID = DefaultOrgID
	}

	query := `
	SELECT key_alias, api_key_encrypted, version
	FROM provider_keys
	WHERE provider = $2 
	  AND (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
	ORDER BY created_at DESC
	LIMIT 1`

	var keyAlias, cipherHex string
	var version int

	err := s.pool.QueryRow(ctx, query, orgID, provider).Scan(&keyAlias, &cipherHex, &version)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrProviderKeyNotFound
		}
		return "", err
	}

	if cipherHex == "" {
		return "", ErrProviderKeyNotFound
	}

	cipherBytes, err := hex.DecodeString(cipherHex)
	if err != nil {
		// If stored as plaintext in legacy rows, return directly
		return cipherHex, nil
	}

	aad := []byte(fmt.Sprintf("%s|%s|%s|%d", orgID, provider, keyAlias, version))
	plainBytes, err := kmsProvider.Decrypt(ctx, cipherBytes, aad)
	if err != nil {
		// Fallback try with version 1 or raw unversioned aad
		fallbackAAD := []byte(fmt.Sprintf("%s|%s|%s|1", orgID, provider, keyAlias))
		if p2, err2 := kmsProvider.Decrypt(ctx, cipherBytes, fallbackAAD); err2 == nil {
			return string(p2), nil
		}
		return "", fmt.Errorf("decrypt provider key: %w", err)
	}

	return string(plainBytes), nil
}

// ListEncryptedProviderKeys lists metadata for all configured provider keys without decrypting secrets.
func (s *Store) ListEncryptedProviderKeys(ctx context.Context, orgID string) ([]ProviderKeyMeta, error) {
	if s.pool == nil {
		return []ProviderKeyMeta{}, nil
	}
	if orgID == "" {
		orgID = DefaultOrgID
	}

	query := `
	SELECT id, organization_id, provider, key_alias, version, created_at, updated_at
	FROM provider_keys
	WHERE organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid
	ORDER BY provider ASC`

	rows, err := s.pool.Query(ctx, query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []ProviderKeyMeta
	for rows.Next() {
		var m ProviderKeyMeta
		if err := rows.Scan(&m.ID, &m.OrganizationID, &m.Provider, &m.KeyAlias, &m.Version, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		m.TenantID = m.OrganizationID
		list = append(list, m)
	}

	return list, nil
}

// DeleteEncryptedProviderKey removes a provider key entry.
func (s *Store) DeleteEncryptedProviderKey(ctx context.Context, orgID, provider string) error {
	if s.pool == nil {
		return nil
	}
	if orgID == "" {
		orgID = DefaultOrgID
	}
	query := `DELETE FROM provider_keys WHERE (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid) AND provider = $2`
	tag, err := s.pool.Exec(ctx, query, orgID, provider)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrProviderKeyNotFound
	}
	return nil
}
