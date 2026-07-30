package store

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/model"
)

func (s *Store) GetUserByEmail(ctx context.Context, authProviderID, email string) (*model.User, error) {
	var u model.User
	err := s.pool.QueryRow(ctx, `
		SELECT id, auth_provider_id, email, password_hash, is_admin, created_at, updated_at
		FROM users
		WHERE (auth_provider_id::text = $1 OR $1 = '')
		  AND LOWER(email) = LOWER($2)
		ORDER BY created_at DESC
		LIMIT 1
	`, authProviderID, email).Scan(
		&u.ID, &u.AuthProviderID, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &u, err
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	var u model.User
	err := s.pool.QueryRow(ctx, `
		SELECT id, auth_provider_id, email, password_hash, is_admin, created_at, updated_at
		FROM users
		WHERE id = $1
	`, id).Scan(
		&u.ID, &u.AuthProviderID, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &u, err
}

func (s *Store) UpsertUser(ctx context.Context, u *model.User) error {
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO users (auth_provider_id, email, password_hash, is_admin, created_at, updated_at)
		VALUES ($1, $2, $3, $4, now(), now())
		ON CONFLICT (auth_provider_id, email)
		DO UPDATE SET
			password_hash = EXCLUDED.password_hash,
			is_admin = EXCLUDED.is_admin,
			updated_at = now()
		RETURNING id
	`, u.AuthProviderID, u.Email, u.PasswordHash, u.IsAdmin).Scan(&id)
	
	if err == nil {
		u.ID = id
	}
	return err
}

func (s *Store) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, auth_provider_id, email, is_admin, created_at, updated_at
		FROM users
		ORDER BY email ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]model.User, 0)
	for rows.Next() {
		var u model.User
		if err := rows.Scan(
			&u.ID, &u.AuthProviderID, &u.Email, &u.IsAdmin, &u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM users WHERE id = $1", id)
	return err
}
