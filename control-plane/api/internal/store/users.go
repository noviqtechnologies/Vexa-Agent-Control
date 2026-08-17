package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

func (s *Store) GetUserByEmail(ctx context.Context, tenantID, authProviderID, email string) (*model.User, error) {
	var u model.User
	var err error

	if tenantID != "" {
		err = s.pool.QueryRow(ctx, `
			SELECT id, tenant_id, COALESCE(auth_provider_id::text, ''), email, COALESCE(password_hash, ''), is_admin, is_saas_operator, created_at, updated_at
			FROM users
			WHERE (auth_provider_id::text = $1 OR $1 = '')
			  AND LOWER(email) = LOWER($2)
			  AND tenant_id = $3
			ORDER BY created_at DESC
			LIMIT 1
		`, authProviderID, email, tenantID).Scan(
			&u.ID, &u.TenantID, &u.AuthProviderID, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.IsSaaSOperator, &u.CreatedAt, &u.UpdatedAt,
		)
	} else {
		err = s.pool.QueryRow(ctx, `
			SELECT id, tenant_id, COALESCE(auth_provider_id::text, ''), email, COALESCE(password_hash, ''), is_admin, is_saas_operator, created_at, updated_at
			FROM users
			WHERE (auth_provider_id::text = $1 OR $1 = '')
			  AND LOWER(email) = LOWER($2)
			ORDER BY created_at DESC
			LIMIT 1
		`, authProviderID, email).Scan(
			&u.ID, &u.TenantID, &u.AuthProviderID, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.IsSaaSOperator, &u.CreatedAt, &u.UpdatedAt,
		)
	}

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &u, err
}

func (s *Store) GetUserByEmailOnly(ctx context.Context, email string) (*model.User, error) {
	var u model.User
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, COALESCE(auth_provider_id::text, ''), email, COALESCE(password_hash, ''), is_admin, is_saas_operator, created_at, updated_at
		FROM users
		WHERE LOWER(email) = LOWER($1)
		ORDER BY (password_hash IS NOT NULL AND password_hash != '') DESC, created_at DESC
		LIMIT 1
	`, email).Scan(
		&u.ID, &u.TenantID, &u.AuthProviderID, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.IsSaaSOperator, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &u, err
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	var u model.User
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, COALESCE(auth_provider_id::text, ''), email, COALESCE(password_hash, ''), is_admin, is_saas_operator, created_at, updated_at
		FROM users
		WHERE id = $1
	`, id).Scan(
		&u.ID, &u.TenantID, &u.AuthProviderID, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.IsSaaSOperator, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &u, err
}

// EnsureUsersSchema guarantees schema consistency for the users table and its indexes.
func (s *Store) EnsureUsersSchema(ctx context.Context) error {
	q := `
		ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
		ALTER TABLE users ADD COLUMN IF NOT EXISTS is_saas_operator BOOLEAN NOT NULL DEFAULT false;
		ALTER TABLE users ALTER COLUMN auth_provider_id DROP NOT NULL;
		CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_email_unique ON users(tenant_id, LOWER(email));
	`
	_, err := s.pool.Exec(ctx, q)
	return err
}

func (s *Store) UpsertUser(ctx context.Context, u *model.User) error {
	if u.TenantID == "" {
		u.TenantID = "00000000-0000-0000-0000-000000000001"
	}

	// 1. Check if user already exists
	existing, err := s.GetUserByEmail(ctx, u.TenantID, "", u.Email)
	if err == nil && existing != nil {
		u.ID = existing.ID
		var authProviderID *string
		if u.AuthProviderID != "" {
			authProviderID = &u.AuthProviderID
		} else if existing.AuthProviderID != "" {
			authProviderID = &existing.AuthProviderID
		}

		pwdHash := existing.PasswordHash
		if u.PasswordHash != "" {
			pwdHash = u.PasswordHash
		}

		_, updateErr := s.pool.Exec(ctx, `
			UPDATE users SET
				auth_provider_id = NULLIF($1, '')::uuid,
				password_hash = $2,
				is_admin = $3,
				is_saas_operator = $4,
				updated_at = now()
			WHERE id = $5
		`, authProviderID, pwdHash, u.IsAdmin, u.IsSaaSOperator, existing.ID)
		return updateErr
	}

	// 2. Insert new user record
	var id string
	insertErr := s.pool.QueryRow(ctx, `
		INSERT INTO users (tenant_id, auth_provider_id, email, password_hash, is_admin, is_saas_operator, created_at, updated_at)
		VALUES ($1, NULLIF($2, '')::uuid, $3, $4, $5, $6, now(), now())
		RETURNING id
	`, u.TenantID, u.AuthProviderID, u.Email, u.PasswordHash, u.IsAdmin, u.IsSaaSOperator).Scan(&id)

	if insertErr != nil {
		// Fallback in case of concurrent insert race
		existing2, err2 := s.GetUserByEmail(ctx, u.TenantID, "", u.Email)
		if err2 == nil && existing2 != nil {
			u.ID = existing2.ID
			return nil
		}
		return insertErr
	}

	u.ID = id
	return nil
}

func (s *Store) UpdateUserPassword(ctx context.Context, tenantID, id, passwordHash string) error {
	if tenantID != "" {
		_, err := s.pool.Exec(ctx, `
			UPDATE users 
			SET password_hash = $1, updated_at = now() 
			WHERE id = $2 AND tenant_id = $3
		`, passwordHash, id, tenantID)
		return err
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE users 
		SET password_hash = $1, updated_at = now() 
		WHERE id = $2
	`, passwordHash, id)
	return err
}

func (s *Store) ListUsers(ctx context.Context, tenantID string) ([]model.User, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, COALESCE(auth_provider_id::text, ''), email, COALESCE(password_hash, ''), is_admin, is_saas_operator, created_at, updated_at
		FROM users
		WHERE tenant_id = $1
		ORDER BY email ASC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]model.User, 0)
	for rows.Next() {
		var u model.User
		if err := rows.Scan(
			&u.ID, &u.TenantID, &u.AuthProviderID, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.IsSaaSOperator, &u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) DeleteUser(ctx context.Context, tenantID, id string) error {
	u, err := s.GetUserByID(ctx, id)
	if err != nil {
		return err
	}
	if u == nil {
		return errors.New("user not found")
	}
	if u.IsAdmin || u.IsSaaSOperator {
		return errors.New("admin role users cannot be deleted")
	}

	if tenantID != "" {
		_, err := s.pool.Exec(ctx, "DELETE FROM users WHERE id = $1 AND tenant_id = $2", id, tenantID)
		return err
	}
	_, err = s.pool.Exec(ctx, "DELETE FROM users WHERE id = $1", id)
	return err
}

