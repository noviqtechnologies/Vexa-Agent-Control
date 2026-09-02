package store

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

// EnsureAuthProvidersSchema guarantees schema consistency for the auth_providers table and its indexes.
func (s *Store) EnsureAuthProvidersSchema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	q := `
		CREATE TABLE IF NOT EXISTS auth_providers (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			name            TEXT NOT NULL,
			type            TEXT NOT NULL,
			issuer_url      TEXT,
			client_id       TEXT,
			client_secret   TEXT,
			enabled         BOOLEAN NOT NULL DEFAULT true,
			email_domains   TEXT[] NOT NULL DEFAULT '{}',
			created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT uq_auth_provider_org_type UNIQUE (organization_id, type)
		);
	`
	_, err := s.pool.Exec(ctx, q)
	return err
}

func (s *Store) ListAuthProviders(ctx context.Context, organizationID string) ([]model.AuthProvider, error) {
	if s.pool == nil {
		return []model.AuthProvider{}, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, organization_id, type, name, COALESCE(client_id, ''), COALESCE(client_secret, ''), COALESCE(issuer_url, ''), enabled, email_domains, created_at, updated_at
		FROM auth_providers
		WHERE organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid
		ORDER BY created_at ASC
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	providers := make([]model.AuthProvider, 0)
	for rows.Next() {
		var p model.AuthProvider
		if err := rows.Scan(
			&p.ID, &p.OrganizationID, &p.Type, &p.Name, &p.ClientID, &p.ClientSecret, &p.IssuerURL,
			&p.Enabled, &p.EmailDomains, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}
	return providers, rows.Err()
}

func (s *Store) GetAuthProvider(ctx context.Context, organizationID, id string) (*model.AuthProvider, error) {
	if s.pool == nil {
		return nil, nil
	}
	var p model.AuthProvider
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	err := s.pool.QueryRow(ctx, `
		SELECT id, organization_id, type, name, COALESCE(client_id, ''), COALESCE(client_secret, ''), COALESCE(issuer_url, ''), enabled, email_domains, created_at, updated_at
		FROM auth_providers
		WHERE id::text = $1 AND (organization_id::text = $2 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
	`, id, organizationID).Scan(
		&p.ID, &p.OrganizationID, &p.Type, &p.Name, &p.ClientID, &p.ClientSecret, &p.IssuerURL,
		&p.Enabled, &p.EmailDomains, &p.CreatedAt, &p.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &p, err
}

func (s *Store) GetAuthProviderByType(ctx context.Context, organizationID, provType string) (*model.AuthProvider, error) {
	if s.pool == nil {
		return nil, nil
	}
	var p model.AuthProvider
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	err := s.pool.QueryRow(ctx, `
		SELECT id, organization_id, type, name, COALESCE(client_id, ''), COALESCE(client_secret, ''), COALESCE(issuer_url, ''), enabled, email_domains, created_at, updated_at
		FROM auth_providers
		WHERE type = $1 AND (organization_id::text = $2 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
		LIMIT 1
	`, provType, organizationID).Scan(
		&p.ID, &p.OrganizationID, &p.Type, &p.Name, &p.ClientID, &p.ClientSecret, &p.IssuerURL,
		&p.Enabled, &p.EmailDomains, &p.CreatedAt, &p.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &p, err
}

func (s *Store) CreateAuthProvider(ctx context.Context, p *model.AuthProvider) error {
	if s.pool == nil {
		return nil
	}
	if p.OrganizationID == "" {
		p.OrganizationID = DefaultOrgID
	}
	return s.pool.QueryRow(ctx, `
		INSERT INTO auth_providers (organization_id, type, name, client_id, client_secret, issuer_url, enabled, email_domains)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at, updated_at
	`, p.OrganizationID, p.Type, p.Name, p.ClientID, p.ClientSecret, p.IssuerURL, p.Enabled, p.EmailDomains).Scan(
		&p.ID, &p.CreatedAt, &p.UpdatedAt,
	)
}

func (s *Store) UpdateAuthProvider(ctx context.Context, p *model.AuthProvider) error {
	if s.pool == nil {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE auth_providers
		SET name = $2,
		    client_id = $3,
		    client_secret = COALESCE(NULLIF($4, ''), client_secret),
		    issuer_url = $5,
		    enabled = $6,
		    email_domains = $7,
		    updated_at = now()
		WHERE id::text = $1
	`, p.ID, p.Name, p.ClientID, p.ClientSecret, p.IssuerURL, p.Enabled, p.EmailDomains)
	return err
}

func (s *Store) UpsertAuthProvider(ctx context.Context, organizationID string, p *model.AuthProvider) error {
	if s.pool == nil {
		return nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	p.OrganizationID = organizationID
	if p.ID != "" {
		existing, _ := s.GetAuthProvider(ctx, organizationID, p.ID)
		if existing != nil {
			return s.UpdateAuthProvider(ctx, p)
		}
	}
	existing, _ := s.GetAuthProviderByType(ctx, organizationID, p.Type)
	if existing != nil {
		p.ID = existing.ID
		return s.UpdateAuthProvider(ctx, p)
	}
	return s.CreateAuthProvider(ctx, p)
}
