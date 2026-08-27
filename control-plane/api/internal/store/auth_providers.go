package store

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

// EnsureAuthProvidersSchema guarantees schema consistency for the auth_providers table and its indexes.
func (s *Store) EnsureAuthProvidersSchema(ctx context.Context) error {
	q := `
		CREATE TABLE IF NOT EXISTS auth_providers (
			id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			name          TEXT NOT NULL,
			type          TEXT NOT NULL,
			issuer_url    TEXT,
			client_id     TEXT,
			client_secret TEXT,
			enabled       BOOLEAN NOT NULL DEFAULT true,
			email_domains TEXT[] NOT NULL DEFAULT '{}',
			created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
		);

		DO $$
		BEGIN
			IF EXISTS (
				SELECT 1 FROM information_schema.columns 
				WHERE table_name = 'auth_providers' AND column_name = 'client_secret_enc'
			) AND NOT EXISTS (
				SELECT 1 FROM information_schema.columns 
				WHERE table_name = 'auth_providers' AND column_name = 'client_secret'
			) THEN
				ALTER TABLE auth_providers RENAME COLUMN client_secret_enc TO client_secret;
			END IF;
		END $$;

		ALTER TABLE auth_providers ADD COLUMN IF NOT EXISTS client_secret TEXT;
		ALTER TABLE auth_providers ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT true;
		ALTER TABLE auth_providers ADD COLUMN IF NOT EXISTS email_domains TEXT[] NOT NULL DEFAULT '{}';

		DO $$
		BEGIN
			IF EXISTS (
				SELECT 1 FROM information_schema.columns 
				WHERE table_name = 'auth_providers' AND column_name = 'type' AND data_type = 'USER-DEFINED'
			) THEN
				DROP INDEX IF EXISTS idx_auth_providers_local_unique;
				DROP INDEX IF EXISTS idx_auth_providers_tenant;
				ALTER TABLE auth_providers ALTER COLUMN type TYPE TEXT USING type::TEXT;
			END IF;
		END $$;

		CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_providers_local_unique ON auth_providers (tenant_id, type) WHERE type = 'local';
		CREATE INDEX IF NOT EXISTS idx_auth_providers_tenant ON auth_providers(tenant_id, type);
	`
	_, err := s.pool.Exec(ctx, q)
	return err
}

func (s *Store) ListAuthProviders(ctx context.Context, tenantID string) ([]model.AuthProvider, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, type, name, client_id, client_secret, issuer_url, enabled, email_domains, created_at, updated_at
		FROM auth_providers
		WHERE tenant_id = $1
		ORDER BY created_at ASC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	providers := make([]model.AuthProvider, 0)
	for rows.Next() {
		var p model.AuthProvider
		if err := rows.Scan(
			&p.ID, &p.TenantID, &p.Type, &p.Name, &p.ClientID, &p.ClientSecret, &p.IssuerURL,
			&p.Enabled, &p.EmailDomains, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}
	return providers, rows.Err()
}

func (s *Store) GetAuthProvider(ctx context.Context, tenantID, id string) (*model.AuthProvider, error) {
	var p model.AuthProvider
	var err error
	if tenantID != "" {
		err = s.pool.QueryRow(ctx, `
			SELECT id, tenant_id, type, name, client_id, client_secret, issuer_url, enabled, email_domains, created_at, updated_at
			FROM auth_providers
			WHERE id = $1 AND tenant_id = $2
		`, id, tenantID).Scan(
			&p.ID, &p.TenantID, &p.Type, &p.Name, &p.ClientID, &p.ClientSecret, &p.IssuerURL,
			&p.Enabled, &p.EmailDomains, &p.CreatedAt, &p.UpdatedAt,
		)
	} else {
		err = s.pool.QueryRow(ctx, `
			SELECT id, tenant_id, type, name, client_id, client_secret, issuer_url, enabled, email_domains, created_at, updated_at
			FROM auth_providers
			WHERE id = $1
		`, id).Scan(
			&p.ID, &p.TenantID, &p.Type, &p.Name, &p.ClientID, &p.ClientSecret, &p.IssuerURL,
			&p.Enabled, &p.EmailDomains, &p.CreatedAt, &p.UpdatedAt,
		)
	}

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &p, err
}

func (s *Store) GetAuthProviderByType(ctx context.Context, tenantID, providerType string) (*model.AuthProvider, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	var p model.AuthProvider
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, type, name, client_id, client_secret, issuer_url, enabled, email_domains, created_at, updated_at
		FROM auth_providers
		WHERE tenant_id = $1 AND type = $2
		LIMIT 1
	`, tenantID, providerType).Scan(
		&p.ID, &p.TenantID, &p.Type, &p.Name, &p.ClientID, &p.ClientSecret, &p.IssuerURL,
		&p.Enabled, &p.EmailDomains, &p.CreatedAt, &p.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &p, err
}

func (s *Store) UpsertAuthProvider(ctx context.Context, tenantID string, p *model.AuthProvider) error {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	p.TenantID = tenantID

	if p.ID != "" {
		_, err := s.pool.Exec(ctx, `
			UPDATE auth_providers SET
				name = $1, client_id = $2, client_secret = $3, issuer_url = $4,
				enabled = $5, email_domains = $6, updated_at = now()
			WHERE id = $7 AND tenant_id = $8
		`, p.Name, p.ClientID, p.ClientSecret, p.IssuerURL, p.Enabled, p.EmailDomains, p.ID, tenantID)
		return err
	}

	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO auth_providers (tenant_id, type, name, client_id, client_secret, issuer_url, enabled, email_domains, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), now())
		ON CONFLICT (tenant_id, type) WHERE type = 'local'
		DO UPDATE SET
			name = EXCLUDED.name,
			client_id = EXCLUDED.client_id,
			client_secret = EXCLUDED.client_secret,
			issuer_url = EXCLUDED.issuer_url,
			email_domains = EXCLUDED.email_domains,
			enabled = EXCLUDED.enabled,
			updated_at = now()
		RETURNING id
	`, tenantID, p.Type, p.Name, p.ClientID, p.ClientSecret, p.IssuerURL, p.Enabled, p.EmailDomains).Scan(&id)
	
	if err == nil {
		p.ID = id
	}
	return err
}

func (s *Store) CountAuthProviders(ctx context.Context, tenantID string) (int, error) {
	var count int
	var err error
	if tenantID != "" {
		err = s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM auth_providers WHERE tenant_id = $1", tenantID).Scan(&count)
	} else {
		err = s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM auth_providers").Scan(&count)
	}
	return count, err
}
