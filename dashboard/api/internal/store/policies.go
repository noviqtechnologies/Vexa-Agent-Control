package store

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/model"
)

func (s *Store) GetActivePolicy(ctx context.Context) (*model.Policy, error) {
	var p model.Policy
	err := s.pool.QueryRow(ctx, `
		SELECT id, version, content, is_active, created_at, updated_at
		FROM policies
		WHERE is_active = true
	`).Scan(
		&p.ID, &p.Version, &p.Content, &p.IsActive, &p.CreatedAt, &p.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &p, err
}

func (s *Store) SavePolicy(ctx context.Context, p *model.Policy) error {
	// If this one is active, deactivate all others first in a transaction
	return s.InTx(ctx, func(tx pgx.Tx) error {
		if p.IsActive {
			_, err := tx.Exec(ctx, "UPDATE policies SET is_active = false WHERE is_active = true")
			if err != nil {
				return err
			}
		}

		var id string
		err := tx.QueryRow(ctx, `
			INSERT INTO policies (version, content, is_active, created_at, updated_at)
			VALUES ($1, $2, $3, now(), now())
			ON CONFLICT (version) DO UPDATE SET
				content = EXCLUDED.content,
				is_active = EXCLUDED.is_active,
				updated_at = now()
			RETURNING id
		`, p.Version, p.Content, p.IsActive).Scan(&id)
		
		if err == nil {
			p.ID = id
		}
		return err
	})
}
