package store

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

func (s *Store) GetUserByEmail(ctx context.Context, organizationID, authProviderID, email string) (*model.User, error) {
	if s.pool == nil {
		return nil, nil
	}
	var u model.User
	var authProvID *string

	if organizationID == "" {
		organizationID = DefaultOrgID
	}

	err := s.pool.QueryRow(ctx, `
		SELECT id, organization_id, auth_provider_id::text, email, COALESCE(password_hash, ''), is_admin, role, created_at, updated_at
		FROM users
		WHERE (auth_provider_id::text = $1 OR $1 = '')
		  AND LOWER(email) = LOWER($2)
		  AND (organization_id::text = $3 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
		ORDER BY created_at DESC
		LIMIT 1
	`, authProviderID, email, organizationID).Scan(
		&u.ID, &u.OrganizationID, &authProvID, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.Role, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	u.AuthProviderID = authProvID
	return &u, err
}

func (s *Store) GetUserByEmailOnly(ctx context.Context, email string) (*model.User, error) {
	return s.GetUserByEmail(ctx, DefaultOrgID, "", email)
}

func (s *Store) FindUsersByEmail(ctx context.Context, email string) ([]model.User, error) {
	if s.pool == nil {
		return []model.User{}, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, organization_id, auth_provider_id::text, email, COALESCE(password_hash, ''), is_admin, role, created_at, updated_at
		FROM users
		WHERE LOWER(email) = LOWER($1)
		ORDER BY updated_at DESC
	`, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]model.User, 0)
	for rows.Next() {
		var u model.User
		var authProvID *string
		if err := rows.Scan(
			&u.ID, &u.OrganizationID, &authProvID, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.Role, &u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, err
		}
		u.AuthProviderID = authProvID
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	if s.pool == nil {
		return nil, nil
	}
	var u model.User
	var authProvID *string
	err := s.pool.QueryRow(ctx, `
		SELECT id, organization_id, auth_provider_id::text, email, COALESCE(password_hash, ''), is_admin, role, created_at, updated_at
		FROM users
		WHERE id::text = $1
	`, id).Scan(
		&u.ID, &u.OrganizationID, &authProvID, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.Role, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	u.AuthProviderID = authProvID
	return &u, err
}

func (s *Store) ListUsers(ctx context.Context, organizationID string) ([]model.User, error) {
	if s.pool == nil {
		return []model.User{}, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, organization_id, auth_provider_id::text, email, COALESCE(password_hash, ''), is_admin, role, created_at, updated_at
		FROM users
		WHERE organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid
		ORDER BY created_at ASC
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]model.User, 0)
	for rows.Next() {
		var u model.User
		var authProvID *string
		if err := rows.Scan(
			&u.ID, &u.OrganizationID, &authProvID, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.Role, &u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, err
		}
		u.AuthProviderID = authProvID
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) CreateUser(ctx context.Context, u *model.User) error {
	if s.pool == nil {
		return nil
	}
	if u.OrganizationID == "" {
		u.OrganizationID = DefaultOrgID
	}
	if u.Role == "" {
		if u.IsAdmin {
			u.Role = "ADMIN"
		} else {
			u.Role = "MEMBER"
		}
	}
	return s.pool.QueryRow(ctx, `
		INSERT INTO users (organization_id, auth_provider_id, email, password_hash, is_admin, role)
		VALUES ($1, $2, LOWER($3), $4, $5, $6)
		RETURNING id, created_at, updated_at
	`, u.OrganizationID, u.AuthProviderID, u.Email, u.PasswordHash, u.IsAdmin, u.Role).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
}

func (s *Store) UpdateUser(ctx context.Context, u *model.User) error {
	if s.pool == nil {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE users
		SET password_hash = COALESCE(NULLIF($2, ''), password_hash),
		    is_admin = $3,
		    role = COALESCE(NULLIF($4, ''), role),
		    updated_at = now()
		WHERE id::text = $1
	`, u.ID, u.PasswordHash, u.IsAdmin, u.Role)
	return err
}

func (s *Store) UpdateUserPassword(ctx context.Context, organizationID, id, passwordHash string) error {
	if s.pool == nil {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE users
		SET password_hash = $2,
		    updated_at = now()
		WHERE id::text = $1
	`, id, passwordHash)
	return err
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	if s.pool == nil {
		return nil
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id::text = $1`, id)
	return err
}

func (s *Store) UpsertUser(ctx context.Context, u *model.User) error {
	if s.pool == nil {
		return nil
	}
	if u.OrganizationID == "" {
		u.OrganizationID = DefaultOrgID
	}
	existing, _ := s.GetUserByEmail(ctx, u.OrganizationID, "", u.Email)
	if existing != nil {
		u.ID = existing.ID
		return s.UpdateUser(ctx, u)
	}
	return s.CreateUser(ctx, u)
}
