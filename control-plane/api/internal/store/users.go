package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

// EnsureUsersSchema guarantees schema consistency for the users table and its columns.
func (s *Store) EnsureUsersSchema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	q := `
		ALTER TABLE users 
		ADD COLUMN IF NOT EXISTS provider_subject TEXT,
		ADD COLUMN IF NOT EXISTS provider_issuer TEXT;

		CREATE UNIQUE INDEX IF NOT EXISTS uq_users_org_provider_subject 
		ON users (organization_id, auth_provider_id, provider_subject) 
		WHERE provider_subject IS NOT NULL;
	`
	_, err := s.pool.Exec(ctx, q)
	return err
}

func (s *Store) GetUserByEmail(ctx context.Context, organizationID, authProviderID, email string) (*model.User, error) {
	if s.pool == nil {
		return nil, nil
	}
	var u model.User
	var authProvID, provSub, provIss *string

	if organizationID == "" {
		organizationID = DefaultOrgID
	}

	err := s.pool.QueryRow(ctx, `
		SELECT id, organization_id, auth_provider_id::text, provider_subject, provider_issuer, email, COALESCE(password_hash, ''), is_admin, role, created_at, updated_at
		FROM users
		WHERE (auth_provider_id::text = $1 OR $1 = '')
		  AND LOWER(email) = LOWER($2)
		  AND (organization_id::text = $3 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
		ORDER BY created_at DESC
		LIMIT 1
	`, authProviderID, email, organizationID).Scan(
		&u.ID, &u.OrganizationID, &authProvID, &provSub, &provIss, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.Role, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	u.AuthProviderID = authProvID
	u.ProviderSubject = provSub
	u.ProviderIssuer = provIss
	return &u, err
}

func (s *Store) GetUserByEmailOnly(ctx context.Context, email string) (*model.User, error) {
	return s.GetUserByEmail(ctx, DefaultOrgID, "", email)
}

func (s *Store) GetUserByProviderSubject(ctx context.Context, organizationID, authProviderID, providerSubject string) (*model.User, error) {
	if s.pool == nil || providerSubject == "" {
		return nil, nil
	}
	var u model.User
	var authProvID, provSub, provIss *string

	if organizationID == "" {
		organizationID = DefaultOrgID
	}

	err := s.pool.QueryRow(ctx, `
		SELECT id, organization_id, auth_provider_id::text, provider_subject, provider_issuer, email, COALESCE(password_hash, ''), is_admin, role, created_at, updated_at
		FROM users
		WHERE (auth_provider_id::text = $1 OR $1 = '')
		  AND provider_subject = $2
		  AND (organization_id::text = $3 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
		ORDER BY created_at DESC
		LIMIT 1
	`, authProviderID, providerSubject, organizationID).Scan(
		&u.ID, &u.OrganizationID, &authProvID, &provSub, &provIss, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.Role, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	u.AuthProviderID = authProvID
	u.ProviderSubject = provSub
	u.ProviderIssuer = provIss
	return &u, err
}

func (s *Store) FindUsersByEmail(ctx context.Context, email string) ([]model.User, error) {
	if s.pool == nil {
		return []model.User{}, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, organization_id, auth_provider_id::text, provider_subject, provider_issuer, email, COALESCE(password_hash, ''), is_admin, role, created_at, updated_at
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
		var authProvID, provSub, provIss *string
		if err := rows.Scan(
			&u.ID, &u.OrganizationID, &authProvID, &provSub, &provIss, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.Role, &u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, err
		}
		u.AuthProviderID = authProvID
		u.ProviderSubject = provSub
		u.ProviderIssuer = provIss
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	if s.pool == nil {
		return nil, nil
	}
	var u model.User
	var authProvID, provSub, provIss *string
	err := s.pool.QueryRow(ctx, `
		SELECT id, organization_id, auth_provider_id::text, provider_subject, provider_issuer, email, COALESCE(password_hash, ''), is_admin, role, created_at, updated_at
		FROM users
		WHERE id::text = $1
	`, id).Scan(
		&u.ID, &u.OrganizationID, &authProvID, &provSub, &provIss, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.Role, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	u.AuthProviderID = authProvID
	u.ProviderSubject = provSub
	u.ProviderIssuer = provIss
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
		SELECT id, organization_id, auth_provider_id::text, provider_subject, provider_issuer, email, COALESCE(password_hash, ''), is_admin, role, created_at, updated_at
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
		var authProvID, provSub, provIss *string
		if err := rows.Scan(
			&u.ID, &u.OrganizationID, &authProvID, &provSub, &provIss, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.Role, &u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, err
		}
		u.AuthProviderID = authProvID
		u.ProviderSubject = provSub
		u.ProviderIssuer = provIss
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
		INSERT INTO users (organization_id, auth_provider_id, provider_subject, provider_issuer, email, password_hash, is_admin, role)
		VALUES ($1, $2, $3, $4, LOWER($5), $6, $7, $8)
		RETURNING id, created_at, updated_at
	`, u.OrganizationID, u.AuthProviderID, u.ProviderSubject, u.ProviderIssuer, u.Email, u.PasswordHash, u.IsAdmin, u.Role).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
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
		    provider_subject = COALESCE($5, provider_subject),
		    provider_issuer = COALESCE($6, provider_issuer),
		    updated_at = now()
		WHERE id::text = $1
	`, u.ID, u.PasswordHash, u.IsAdmin, u.Role, u.ProviderSubject, u.ProviderIssuer)
	return err
}

func (s *Store) BackfillUserProviderSubject(ctx context.Context, organizationID, authProviderID, userID, providerSubject, providerIssuer string) error {
	if s.pool == nil {
		return nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	res, err := s.pool.Exec(ctx, `
		UPDATE users 
		SET provider_subject = $1, provider_issuer = $2, updated_at = now() 
		WHERE id::text = $3 
		  AND (organization_id::text = $4 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid) 
		  AND (auth_provider_id::text = $5 OR $5 = '') 
		  AND provider_subject IS NULL;
	`, providerSubject, providerIssuer, userID, organizationID, authProviderID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("no user matched for provider_subject backfill or provider_subject was already set")
	}
	return nil
}

func (s *Store) LinkUserProviderSubject(ctx context.Context, userID, authProviderID, providerSubject, providerIssuer string) error {
	if s.pool == nil {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE users 
		SET auth_provider_id = $2::uuid, provider_subject = $3, provider_issuer = $4, updated_at = now() 
		WHERE id::text = $1;
	`, userID, authProviderID, providerSubject, providerIssuer)
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

// BootstrapAdmin ensures the customer organization, default team, local auth provider,
// and the initial administrator user exist with current configured credentials.
func (s *Store) BootstrapAdmin(ctx context.Context, orgID, orgName, email, passwordHash string) error {
	if s.pool == nil || email == "" {
		return nil
	}
	email = strings.TrimSpace(strings.ToLower(email))

	if orgID == "" {
		orgID = DefaultOrgID
	}
	if orgName == "" {
		orgName = "Primary Organization"
	}

	// 1. Ensure Organization exists with configured name and contact email
	_, err := s.pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug, contact_email, license_tier, max_devices, status)
		VALUES ($1, $2, 'default', $3, 'team', 50, 'active')
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			contact_email = EXCLUDED.contact_email,
			updated_at = now()
	`, orgID, orgName, email)
	if err != nil {
		return fmt.Errorf("bootstrap organization: %w", err)
	}

	// 2. Ensure Default Team exists
	_, err = s.pool.Exec(ctx, `
		INSERT INTO teams (id, organization_id, name, description)
		VALUES ('default', $1, 'Default Team', 'Default team workspace')
		ON CONFLICT (id) DO NOTHING
	`, orgID)
	if err != nil {
		return fmt.Errorf("bootstrap team: %w", err)
	}

	// 3. Ensure Local Auth Provider exists
	const localAuthID = "00000000-0000-0000-0000-000000000002"
	_, err = s.pool.Exec(ctx, `
		INSERT INTO auth_providers (id, organization_id, name, type, enabled)
		VALUES ($1, $2, 'Local Password Authentication', 'local', true)
		ON CONFLICT (organization_id, type) DO NOTHING
	`, localAuthID, orgID)
	if err != nil {
		return fmt.Errorf("bootstrap auth provider: %w", err)
	}

	// 4. Ensure Admin User exists with role OWNER, is_admin true, and given password_hash
	if passwordHash != "" {
		provID := localAuthID
		_, err = s.pool.Exec(ctx, `
			INSERT INTO users (organization_id, auth_provider_id, email, password_hash, is_admin, role)
			VALUES ($1, $2, $3, $4, true, 'OWNER')
			ON CONFLICT (organization_id, email) DO UPDATE SET
				auth_provider_id = EXCLUDED.auth_provider_id,
				password_hash    = EXCLUDED.password_hash,
				is_admin         = true,
				role             = 'OWNER',
				updated_at       = now()
		`, orgID, provID, email, passwordHash)
		if err != nil {
			return fmt.Errorf("bootstrap admin user: %w", err)
		}
	}

	return nil
}

// BootstrapTenantAdmin ensures the tenant organization, default team, local auth provider,
// and the initial tenant administrator user exist with current configured credentials.
func (s *Store) BootstrapTenantAdmin(ctx context.Context, orgName, email, passwordHash string) error {
	return s.BootstrapAdmin(ctx, DefaultOrgID, orgName, email, passwordHash)
}
