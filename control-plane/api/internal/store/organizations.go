package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

// EnsureOrganizationsSchema guarantees schema consistency for the tenants table.
func (s *Store) EnsureOrganizationsSchema(ctx context.Context) error {
	q := `
		ALTER TABLE tenants ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';
		ALTER TABLE tenants ADD COLUMN IF NOT EXISTS contact_email TEXT NOT NULL DEFAULT '';
		ALTER TABLE tenants ADD COLUMN IF NOT EXISTS license_tier TEXT NOT NULL DEFAULT 'community';
		ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_seats INTEGER NOT NULL DEFAULT 10;
		ALTER TABLE tenants ADD COLUMN IF NOT EXISTS license_key_jwt TEXT;
		ALTER TABLE tenants ADD COLUMN IF NOT EXISTS is_trial BOOLEAN NOT NULL DEFAULT false;
		ALTER TABLE tenants ADD COLUMN IF NOT EXISTS trial_days INTEGER NOT NULL DEFAULT 0;
		ALTER TABLE tenants ADD COLUMN IF NOT EXISTS trial_ends_at TIMESTAMPTZ;
		ALTER TABLE tenants ADD COLUMN IF NOT EXISTS license_expires_at TIMESTAMPTZ;
		ALTER TABLE tenants ADD COLUMN IF NOT EXISTS gateway_secret TEXT;
		ALTER TABLE tenants ADD COLUMN IF NOT EXISTS policy_read_secret TEXT;
		ALTER TABLE tenants ADD COLUMN IF NOT EXISTS bootstrap_token_hash TEXT;
		ALTER TABLE tenants ADD COLUMN IF NOT EXISTS bootstrap_token_hint TEXT;
		ALTER TABLE tenants ADD COLUMN IF NOT EXISTS bootstrap_consumed_at TIMESTAMPTZ;
		ALTER TABLE tenants ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

		-- Auto-repair legacy trial rows where trial_ends_at was left NULL
		UPDATE tenants
		SET trial_ends_at = created_at + (COALESCE(NULLIF(trial_days, 0), 30) * interval '1 day'),
		    license_expires_at = COALESCE(license_expires_at, created_at + (COALESCE(NULLIF(trial_days, 0), 30) * interval '1 day'))
		WHERE is_trial = true AND trial_ends_at IS NULL;
	`
	_, err := s.pool.Exec(ctx, q)
	return err
}

func GenerateSecureToken(prefix string, byteLength int) string {
	b := make([]byte, byteLength)
	rand.Read(b)
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// CreateOrganization inserts a new tenant and generates its secrets and bootstrap credentials.
// Returns the raw bootstrap token (to show once to the operator) and the created organization.
func (s *Store) CreateOrganization(ctx context.Context, org *model.Organization) (string, error) {
	if org.GatewaySecret == "" {
		org.GatewaySecret = GenerateSecureToken("gw_sec_", 24)
	}
	if org.PolicyReadSecret == "" {
		org.PolicyReadSecret = GenerateSecureToken("pr_sec_", 24)
	}

	rawBootstrapToken := GenerateSecureToken("bt_", 16)
	org.BootstrapTokenHash = HashToken(rawBootstrapToken)
	if len(rawBootstrapToken) >= 6 {
		org.BootstrapTokenHint = rawBootstrapToken[len(rawBootstrapToken)-4:]
	}

	if org.Status == "" {
		org.Status = model.OrgStatusActive
	}

	q := `
		INSERT INTO tenants (
			name, slug, contact_email, license_tier, max_seats, license_key_jwt,
			is_trial, trial_days, trial_ends_at, license_expires_at,
			gateway_secret, policy_read_secret, bootstrap_token_hash, bootstrap_token_hint,
			status, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10,
			$11, $12, $13, $14,
			$15, now(), now()
		)
		RETURNING id, created_at, updated_at
	`

	err := s.pool.QueryRow(ctx, q,
		org.Name, org.Slug, org.ContactEmail, org.LicenseTier, org.MaxSeats, org.LicenseKeyJWT,
		org.IsTrial, org.TrialDays, org.TrialEndsAt, org.LicenseExpiresAt,
		org.GatewaySecret, org.PolicyReadSecret, org.BootstrapTokenHash, org.BootstrapTokenHint,
		string(org.Status),
	).Scan(&org.ID, &org.CreatedAt, &org.UpdatedAt)

	if err != nil {
		return "", fmt.Errorf("create organization: %w", err)
	}

	// Seed default authoritative spend policy ($100/mo) for the new tenant
	var policyID string
	seedErr := s.pool.QueryRow(ctx, `
		INSERT INTO spend_policies (
			organization_id, scope_type, scope_id, currency, period_type,
			limit_microcents, action, effective_from, status
		) VALUES (
			$1, 'organization', $1, 'USD', 'monthly',
			10000000000, 'hard_deny', now(), 'PUBLISHED'
		) ON CONFLICT (organization_id, scope_type, scope_id, period_type) DO UPDATE SET updated_at = now()
		RETURNING policy_id
	`, org.ID).Scan(&policyID)
	if seedErr == nil && policyID != "" {
		_, _ = s.pool.Exec(ctx, `
			INSERT INTO spend_policy_versions (
				policy_id, version, snapshot_json, published_by, published_at
			) VALUES (
				$1, 1, '{"scope_type":"organization","limit_microcents":10000000000,"period_type":"monthly"}'::jsonb,
				'system', now()
			) ON CONFLICT (policy_id, version) DO NOTHING
		`, policyID)
	}

	// Seed default baseline security policy (v1.0.0) with full isolation for the new tenant
	baselinePolicyYAML := `# Vexa Agent Control Default Baseline Policy
version: "1.0.0"
default_action: "allow"
fail_closed: true
rules:
  - name: "block_sensitive_files"
    action: "deny"
    description: "Prevent access to sensitive system paths"
`
	_, _ = s.pool.Exec(ctx, `
		INSERT INTO policies (tenant_id, version, content, is_active, created_at, updated_at)
		VALUES ($1, '1.0.0', $2, true, now(), now())
		ON CONFLICT (tenant_id, version) DO NOTHING
	`, org.ID, baselinePolicyYAML)

	return rawBootstrapToken, nil
}

func (s *Store) ListOrganizations(ctx context.Context) ([]model.OrgSummary, error) {
	q := `
		SELECT 
			id, name, slug, contact_email, license_tier, max_seats,
			is_trial, trial_days, trial_ends_at, license_expires_at,
			status, created_at, (bootstrap_consumed_at IS NULL AND bootstrap_token_hash IS NOT NULL) AS has_bootstrap
		FROM tenants
		ORDER BY created_at DESC
	`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	defer rows.Close()

	now := time.Now().UTC()
	var list []model.OrgSummary
	for rows.Next() {
		var o model.OrgSummary
		var statusStr string
		if err := rows.Scan(
			&o.ID, &o.Name, &o.Slug, &o.ContactEmail, &o.LicenseTier, &o.MaxSeats,
			&o.IsTrial, &o.TrialDays, &o.TrialEndsAt, &o.LicenseExpiresAt,
			&statusStr, &o.CreatedAt, &o.HasBootstrap,
		); err != nil {
			return nil, err
		}
		o.Status = model.OrganizationStatus(statusStr)

		// Calculate days remaining with fallback
		var expiryTarget *time.Time
		if o.IsTrial {
			if o.TrialEndsAt != nil {
				expiryTarget = o.TrialEndsAt
			} else if o.TrialDays > 0 {
				fallback := o.CreatedAt.AddDate(0, 0, o.TrialDays)
				expiryTarget = &fallback
			} else if o.LicenseExpiresAt != nil {
				expiryTarget = o.LicenseExpiresAt
			}
		} else if o.LicenseExpiresAt != nil {
			expiryTarget = o.LicenseExpiresAt
		}

		if expiryTarget != nil {
			diff := expiryTarget.Sub(now)
			days := int(math.Ceil(diff.Hours() / 24.0))
			if days < 0 {
				days = 0
			}
			o.DaysRemaining = days
		} else {
			o.DaysRemaining = 9999
		}

		list = append(list, o)
	}
	return list, rows.Err()
}

func (s *Store) GetOrganization(ctx context.Context, id string) (*model.Organization, error) {
	q := `
		SELECT 
			id, name, slug, contact_email, license_tier, max_seats, license_key_jwt,
			is_trial, trial_days, trial_ends_at, license_expires_at,
			gateway_secret, policy_read_secret, bootstrap_token_hash, bootstrap_token_hint,
			bootstrap_consumed_at, status, created_at, updated_at
		FROM tenants
		WHERE id = $1
	`
	var o model.Organization
	var statusStr string
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&o.ID, &o.Name, &o.Slug, &o.ContactEmail, &o.LicenseTier, &o.MaxSeats, &o.LicenseKeyJWT,
		&o.IsTrial, &o.TrialDays, &o.TrialEndsAt, &o.LicenseExpiresAt,
		&o.GatewaySecret, &o.PolicyReadSecret, &o.BootstrapTokenHash, &o.BootstrapTokenHint,
		&o.BootstrapConsumedAt, &statusStr, &o.CreatedAt, &o.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	o.Status = model.OrganizationStatus(statusStr)
	return &o, nil
}

func (s *Store) GetOrganizationBySlug(ctx context.Context, slug string) (*model.Organization, error) {
	q := `
		SELECT 
			id, name, slug, contact_email, license_tier, max_seats, license_key_jwt,
			is_trial, trial_days, trial_ends_at, license_expires_at,
			gateway_secret, policy_read_secret, bootstrap_token_hash, bootstrap_token_hint,
			bootstrap_consumed_at, status, created_at, updated_at
		FROM tenants
		WHERE slug = $1
	`
	var o model.Organization
	var statusStr string
	err := s.pool.QueryRow(ctx, q, slug).Scan(
		&o.ID, &o.Name, &o.Slug, &o.ContactEmail, &o.LicenseTier, &o.MaxSeats, &o.LicenseKeyJWT,
		&o.IsTrial, &o.TrialDays, &o.TrialEndsAt, &o.LicenseExpiresAt,
		&o.GatewaySecret, &o.PolicyReadSecret, &o.BootstrapTokenHash, &o.BootstrapTokenHint,
		&o.BootstrapConsumedAt, &statusStr, &o.CreatedAt, &o.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	o.Status = model.OrganizationStatus(statusStr)
	return &o, nil
}

func (s *Store) UpdateOrganization(ctx context.Context, id string, req model.UpdateOrgReq) error {
	q := `
		UPDATE tenants
		SET name = $1, contact_email = $2, license_tier = $3, max_seats = $4, updated_at = now()
		WHERE id = $5
	`
	_, err := s.pool.Exec(ctx, q, req.Name, req.ContactEmail, req.LicenseTier, req.MaxSeats, id)
	return err
}

func (s *Store) UpdateOrganizationStatus(ctx context.Context, id string, status model.OrganizationStatus) error {
	q := `UPDATE tenants SET status = $1, updated_at = now() WHERE id = $2`
	_, err := s.pool.Exec(ctx, q, string(status), id)
	return err
}

func (s *Store) UpdateLicense(ctx context.Context, id string, licenseJWT string, expiresAt time.Time, isTrial bool, trialDays int) error {
	var trialEndsAt *time.Time
	if isTrial {
		trialEndsAt = &expiresAt
	}
	q := `
		UPDATE tenants
		SET license_key_jwt = $1, license_expires_at = $2, is_trial = $3, trial_days = $4, trial_ends_at = $5, updated_at = now()
		WHERE id = $6
	`
	_, err := s.pool.Exec(ctx, q, licenseJWT, expiresAt, isTrial, trialDays, trialEndsAt, id)
	return err
}

func (s *Store) RegenerateBootstrapToken(ctx context.Context, id string) (string, error) {
	rawToken := GenerateSecureToken("bt_", 16)
	tokenHash := HashToken(rawToken)
	var hint string
	if len(rawToken) >= 6 {
		hint = rawToken[len(rawToken)-4:]
	}

	q := `
		UPDATE tenants
		SET bootstrap_token_hash = $1, bootstrap_token_hint = $2, bootstrap_consumed_at = NULL, updated_at = now()
		WHERE id = $3
	`
	_, err := s.pool.Exec(ctx, q, tokenHash, hint, id)
	if err != nil {
		return "", err
	}
	return rawToken, nil
}

func (s *Store) ResolveBootstrapToken(ctx context.Context, rawToken string) (*model.Organization, error) {
	tokenHash := HashToken(rawToken)
	q := `
		SELECT 
			id, name, slug, contact_email, license_tier, max_seats, license_key_jwt,
			is_trial, trial_days, trial_ends_at, license_expires_at,
			gateway_secret, policy_read_secret, bootstrap_token_hash, bootstrap_token_hint,
			bootstrap_consumed_at, status, created_at, updated_at
		FROM tenants
		WHERE bootstrap_token_hash = $1 AND bootstrap_consumed_at IS NULL
	`
	var o model.Organization
	var statusStr string
	err := s.pool.QueryRow(ctx, q, tokenHash).Scan(
		&o.ID, &o.Name, &o.Slug, &o.ContactEmail, &o.LicenseTier, &o.MaxSeats, &o.LicenseKeyJWT,
		&o.IsTrial, &o.TrialDays, &o.TrialEndsAt, &o.LicenseExpiresAt,
		&o.GatewaySecret, &o.PolicyReadSecret, &o.BootstrapTokenHash, &o.BootstrapTokenHint,
		&o.BootstrapConsumedAt, &statusStr, &o.CreatedAt, &o.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	o.Status = model.OrganizationStatus(statusStr)
	return &o, nil
}

func (s *Store) ConsumeBootstrapToken(ctx context.Context, id string) error {
	q := `UPDATE tenants SET bootstrap_consumed_at = now(), updated_at = now() WHERE id = $1`
	_, err := s.pool.Exec(ctx, q, id)
	return err
}

func (s *Store) GetOrganizationStats(ctx context.Context) (*model.PlatformStats, error) {
	q := `
		SELECT
			(SELECT COUNT(*) FROM tenants),
			(SELECT COUNT(*) FROM tenants WHERE is_trial = true AND COALESCE(trial_ends_at, created_at + (COALESCE(NULLIF(trial_days, 0), 30) * interval '1 day')) > now()),
			(SELECT COUNT(*) FROM tenants WHERE (is_trial = true AND COALESCE(trial_ends_at, created_at + (COALESCE(NULLIF(trial_days, 0), 30) * interval '1 day')) BETWEEN now() AND now() + INTERVAL '7 days') OR (is_trial = false AND license_expires_at BETWEEN now() AND now() + INTERVAL '7 days')),
			(SELECT COALESCE(SUM(max_seats), 0) FROM tenants)
	`
	var stats model.PlatformStats
	err := s.pool.QueryRow(ctx, q).Scan(
		&stats.TotalOrganizations,
		&stats.ActiveTrials,
		&stats.ExpiringWithin7d,
		&stats.TotalSeats,
	)
	return &stats, err
}
