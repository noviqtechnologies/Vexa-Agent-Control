package store

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/model"
)

func (s *Store) ListAuthProviders(ctx context.Context) ([]model.AuthProvider, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, type, name, client_id, client_secret, issuer_url, enabled, email_domains, created_at, updated_at
		FROM auth_providers
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	providers := make([]model.AuthProvider, 0)
	for rows.Next() {
		var p model.AuthProvider
		if err := rows.Scan(
			&p.ID, &p.Type, &p.Name, &p.ClientID, &p.ClientSecret, &p.IssuerURL,
			&p.Enabled, &p.EmailDomains, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}
	return providers, rows.Err()
}

func (s *Store) GetAuthProvider(ctx context.Context, id string) (*model.AuthProvider, error) {
	var p model.AuthProvider
	err := s.pool.QueryRow(ctx, `
		SELECT id, type, name, client_id, client_secret, issuer_url, enabled, email_domains, created_at, updated_at
		FROM auth_providers
		WHERE id = $1
	`, id).Scan(
		&p.ID, &p.Type, &p.Name, &p.ClientID, &p.ClientSecret, &p.IssuerURL,
		&p.Enabled, &p.EmailDomains, &p.CreatedAt, &p.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &p, err
}

func (s *Store) UpsertAuthProvider(ctx context.Context, p *model.AuthProvider) error {
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO auth_providers (type, name, client_id, client_secret, issuer_url, enabled, email_domains, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())
		ON CONFLICT (type) WHERE type = 'local'
		DO UPDATE SET
			name = EXCLUDED.name,
			enabled = EXCLUDED.enabled,
			email_domains = EXCLUDED.email_domains,
			updated_at = now()
		RETURNING id
	`, p.Type, p.Name, p.ClientID, p.ClientSecret, p.IssuerURL, p.Enabled, p.EmailDomains).Scan(&id)
	
	if err != nil {
		// If it's an update by ID for OAuth types that don't have a unique constraint on type alone
		if p.ID != "" {
			_, err = s.pool.Exec(ctx, `
				UPDATE auth_providers SET
					name = $1, client_id = $2, client_secret = $3, issuer_url = $4,
					enabled = $5, email_domains = $6, updated_at = now()
				WHERE id = $7
			`, p.Name, p.ClientID, p.ClientSecret, p.IssuerURL, p.Enabled, p.EmailDomains, p.ID)
		}
	} else {
		p.ID = id
	}
	
	return err
}

func (s *Store) CountAuthProviders(ctx context.Context) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM auth_providers").Scan(&count)
	return count, err
}
