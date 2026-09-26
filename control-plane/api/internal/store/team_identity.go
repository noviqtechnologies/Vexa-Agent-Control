package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrTokenReused   = errors.New("refresh token reused: token family revoked")
	ErrTokenExpired  = errors.New("refresh token expired")
	ErrTokenRevoked  = errors.New("refresh token revoked")
	ErrTokenNotFound = errors.New("refresh token not found")
)

type UserIdentity struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id"`
	OrganizationID string    `json:"organization_id"`
	ProviderID     string    `json:"provider_id"`
	IdentityIssuer string    `json:"identity_issuer"`
	IdentitySubject string   `json:"identity_subject"`
	IdentityEmail  string    `json:"identity_email"`
	EmailVerified  bool      `json:"email_verified"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type OAuthRefreshToken struct {
	ID             string     `json:"id"`
	FamilyID       string     `json:"family_id"`
	ParentTokenID  *string    `json:"parent_token_id,omitempty"`
	UserID         string     `json:"user_id"`
	OrganizationID string     `json:"organization_id"`
	TeamID         string     `json:"team_id"`
	DeviceID       string     `json:"device_id"`
	TokenHash      string     `json:"token_hash"`
	ConsumedAt     *time.Time `json:"consumed_at,omitempty"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	ExpiresAt      time.Time  `json:"expires_at"`
	CreatedAt      time.Time  `json:"created_at"`
}

type BrokerAdmission struct {
	ID             string     `json:"id"`
	RequestID      string     `json:"request_id"`
	OrganizationID string     `json:"organization_id"`
	TeamID         string     `json:"team_id"`
	UserID         string     `json:"user_id"`
	DeviceID       string     `json:"device_id"`
	CredentialID   string     `json:"credential_id"`
	PolicyVersion  string     `json:"policy_version"`
	Provider       string     `json:"provider"`
	Model          string     `json:"model"`
	EstimatedCost  float64    `json:"estimated_cost"`
	SettledCost    float64    `json:"settled_cost"`
	Status         string     `json:"status"` // ADMITTED | SETTLED | REJECTED | FAILED
	AdmittedAt     time.Time  `json:"admitted_at"`
	SettledAt      *time.Time `json:"settled_at,omitempty"`
}

// FindUserIdentity locates a canonical user identity tuple
func (s *Store) FindUserIdentity(
	ctx context.Context,
	orgID, providerID, issuer, subject string,
) (*UserIdentity, error) {
	if s.pool == nil {
		return nil, errors.New("database pool not initialized")
	}

	query := `
	SELECT id, user_id, organization_id, provider_id, identity_issuer, identity_subject, identity_email, email_verified, created_at, updated_at
	FROM user_identities
	WHERE organization_id = $1 AND provider_id = $2 AND identity_issuer = $3 AND identity_subject = $4
	LIMIT 1`

	var u UserIdentity
	err := s.pool.QueryRow(ctx, query, orgID, providerID, issuer, subject).Scan(
		&u.ID, &u.UserID, &u.OrganizationID, &u.ProviderID, &u.IdentityIssuer, &u.IdentitySubject,
		&u.IdentityEmail, &u.EmailVerified, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

// UpsertUserIdentity records canonical identity and ensures unique binding
func (s *Store) UpsertUserIdentity(ctx context.Context, u *UserIdentity) error {
	if s.pool == nil {
		return errors.New("database pool not initialized")
	}

	query := `
	INSERT INTO user_identities (
		organization_id, provider_id, user_id, identity_issuer, identity_subject, identity_email, email_verified, created_at, updated_at
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, now(), now()
	)
	ON CONFLICT (organization_id, provider_id, identity_issuer, identity_subject) DO UPDATE
	SET identity_email = EXCLUDED.identity_email,
	    email_verified = EXCLUDED.email_verified,
	    updated_at = now()
	RETURNING id, created_at, updated_at`

	return s.pool.QueryRow(
		ctx, query,
		u.OrganizationID, u.ProviderID, u.UserID, u.IdentityIssuer, u.IdentitySubject, u.IdentityEmail, u.EmailVerified,
	).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
}

// GetUserTeam returns the primary team for a user (defaults to 'default')
func (s *Store) GetUserTeam(ctx context.Context, orgID, userID string) (string, error) {
	if s.pool == nil {
		return "default", nil
	}

	var teamID string
	err := s.pool.QueryRow(ctx, `
		SELECT team_id
		FROM team_memberships
		WHERE organization_id = $1 AND user_id = $2
		ORDER BY created_at ASC
		LIMIT 1
	`, orgID, userID).Scan(&teamID)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "default", nil
		}
		return "default", err
	}
	return teamID, nil
}

// CreateRefreshTokenFamily creates an initial refresh token row
func (s *Store) CreateRefreshTokenFamily(ctx context.Context, token *OAuthRefreshToken) error {
	if s.pool == nil {
		return errors.New("database pool not initialized")
	}

	query := `
	INSERT INTO oauth_refresh_tokens (
		family_id, user_id, organization_id, team_id, device_id, token_hash, expires_at, created_at
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, now()
	)
	RETURNING id, created_at`

	return s.pool.QueryRow(
		ctx, query,
		token.FamilyID, token.UserID, token.OrganizationID, token.TeamID, token.DeviceID, token.TokenHash, token.ExpiresAt,
	).Scan(&token.ID, &token.CreatedAt)
}

// RotateRefreshToken executes atomic token rotation under SELECT ... FOR UPDATE
func (s *Store) RotateRefreshToken(
	ctx context.Context,
	currentTokenHash, nextTokenHash string,
	nextExpiry time.Time,
) (*OAuthRefreshToken, error) {
	if s.pool == nil {
		return nil, errors.New("database pool not initialized")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Lock row for update
	selectQuery := `
	SELECT id, family_id, user_id, organization_id, team_id, device_id, token_hash, consumed_at, revoked_at, expires_at, created_at
	FROM oauth_refresh_tokens
	WHERE token_hash = $1
	FOR UPDATE`

	var current OAuthRefreshToken
	err = tx.QueryRow(ctx, selectQuery, currentTokenHash).Scan(
		&current.ID, &current.FamilyID, &current.UserID, &current.OrganizationID,
		&current.TeamID, &current.DeviceID, &current.TokenHash,
		&current.ConsumedAt, &current.RevokedAt, &current.ExpiresAt, &current.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}

	// 1. Check if token family was already revoked
	if current.RevokedAt != nil {
		return nil, ErrTokenRevoked
	}

	// 2. Replay detection: if already consumed, revoke the ENTIRE token family!
	if current.ConsumedAt != nil {
		_, _ = tx.Exec(ctx, `UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE family_id = $1`, current.FamilyID)
		_ = tx.Commit(ctx)
		return nil, ErrTokenReused
	}

	// 3. Expiration check
	if time.Now().After(current.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// 4. Mark current token as consumed
	now := time.Now().UTC()
	_, err = tx.Exec(ctx, `UPDATE oauth_refresh_tokens SET consumed_at = $1 WHERE id = $2`, now, current.ID)
	if err != nil {
		return nil, fmt.Errorf("consume token: %w", err)
	}

	// 5. Insert new successor token
	parentID := current.ID
	next := OAuthRefreshToken{
		FamilyID:       current.FamilyID,
		ParentTokenID:  &parentID,
		UserID:         current.UserID,
		OrganizationID: current.OrganizationID,
		TeamID:         current.TeamID,
		DeviceID:       current.DeviceID,
		TokenHash:      nextTokenHash,
		ExpiresAt:      nextExpiry,
		CreatedAt:      now,
	}

	insertQuery := `
	INSERT INTO oauth_refresh_tokens (
		family_id, parent_token_id, user_id, organization_id, team_id, device_id, token_hash, expires_at, created_at
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9
	)
	RETURNING id`

	err = tx.QueryRow(
		ctx, insertQuery,
		next.FamilyID, next.ParentTokenID, next.UserID, next.OrganizationID, next.TeamID, next.DeviceID, next.TokenHash, next.ExpiresAt, next.CreatedAt,
	).Scan(&next.ID)
	if err != nil {
		return nil, fmt.Errorf("insert successor token: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit rotation tx: %w", err)
	}

	return &next, nil
}

// RecordBrokerAdmission records the admission record before upstream dispatch
func (s *Store) RecordBrokerAdmission(ctx context.Context, a *BrokerAdmission) error {
	if s.pool == nil {
		return nil
	}

	query := `
	INSERT INTO broker_admissions (
		request_id, organization_id, team_id, user_id, device_id, credential_id, policy_version,
		provider, model, estimated_cost, status, admitted_at
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now()
	)
	RETURNING id, admitted_at`

	return s.pool.QueryRow(
		ctx, query,
		a.RequestID, a.OrganizationID, a.TeamID, a.UserID, a.DeviceID, a.CredentialID, a.PolicyVersion,
		a.Provider, a.Model, a.EstimatedCost, a.Status,
	).Scan(&a.ID, &a.AdmittedAt)
}

// SettleBrokerAdmission records the settled cost upon stream or request completion
func (s *Store) SettleBrokerAdmission(ctx context.Context, requestID string, settledCost float64, status string) error {
	if s.pool == nil {
		return nil
	}

	query := `
	UPDATE broker_admissions
	SET settled_cost = $2, status = $3, settled_at = now()
	WHERE request_id = $1`

	_, err := s.pool.Exec(ctx, query, requestID, settledCost, status)
	return err
}
