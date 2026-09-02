package store

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

const DefaultOrgID = "00000000-0000-0000-0000-000000000001"

// EnsureOrganizationsSchema guarantees schema consistency for the organizations table
// and all foundational enum types required by downstream tables (devices, telemetry, etc.).
func (s *Store) EnsureOrganizationsSchema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	// Create enum types idempotently. PostgreSQL does not support
	// "CREATE TYPE IF NOT EXISTS" natively, so we use the exception-block pattern.
	enumQ := `
		DO $$ BEGIN
			CREATE TYPE event_decision AS ENUM ('allowed', 'denied', 'warned');
		EXCEPTION WHEN duplicate_object THEN NULL; END $$;

		DO $$ BEGIN
			CREATE TYPE alert_severity AS ENUM ('info', 'warning', 'critical');
		EXCEPTION WHEN duplicate_object THEN NULL; END $$;

		DO $$ BEGIN
			CREATE TYPE agent_status AS ENUM ('active', 'inactive', 'revoked');
		EXCEPTION WHEN duplicate_object THEN NULL; END $$;

		DO $$ BEGIN
			CREATE TYPE device_state AS ENUM ('PENDING', 'COMPLIANT', 'NON_COMPLIANT', 'REVOKED');
		EXCEPTION WHEN duplicate_object THEN NULL; END $$;

		DO $$ BEGIN
			CREATE TYPE credential_status AS ENUM ('ACTIVE', 'EXPIRING_SOON', 'EXPIRED', 'REVOKED');
		EXCEPTION WHEN duplicate_object THEN NULL; END $$;

		DO $$ BEGIN
			CREATE TYPE token_status AS ENUM ('ACTIVE', 'CONSUMED', 'REVOKED', 'EXPIRED');
		EXCEPTION WHEN duplicate_object THEN NULL; END $$;
	`
	if _, err := s.pool.Exec(ctx, enumQ); err != nil {
		return fmt.Errorf("ensure enum types: %w", err)
	}

	q := `
		CREATE TABLE IF NOT EXISTS organizations (
			id UUID PRIMARY KEY DEFAULT '00000000-0000-0000-0000-000000000001'::uuid,
			name TEXT NOT NULL DEFAULT 'Primary Organization',
			slug TEXT NOT NULL DEFAULT 'default',
			contact_email TEXT NOT NULL DEFAULT 'admin@agentcontrol.local',
			license_tier TEXT NOT NULL DEFAULT 'team',
			license_key_jwt TEXT,
			max_devices INT NOT NULL DEFAULT 25,
			license_expires_at TIMESTAMPTZ,
			status TEXT NOT NULL DEFAULT 'active',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);

		INSERT INTO organizations (id, name, slug, contact_email, license_tier, max_devices, status)
		VALUES ('00000000-0000-0000-0000-000000000001', 'Primary Organization', 'default', 'admin@agentcontrol.local', 'team', 25, 'active')
		ON CONFLICT (id) DO NOTHING;

		UPDATE organizations
		SET license_tier = 'team', max_devices = GREATEST(max_devices, 25), updated_at = now()
		WHERE id = '00000000-0000-0000-0000-000000000001' AND license_tier = 'developer';
	`
	_, err := s.pool.Exec(ctx, q)
	return err
}


// GetOrganization returns the organization by ID or slug.
func (s *Store) GetOrganization(ctx context.Context, idOrSlug string) (*model.Organization, error) {
	if s.pool == nil {
		return &model.Organization{
			ID:          DefaultOrgID,
			Name:        "Primary Organization",
			Slug:        "default",
			LicenseTier: "team",
			MaxDevices:  25,
			Status:      model.OrgStatusActive,
		}, nil
	}

	q := `
		SELECT id, name, slug, contact_email, license_tier, max_devices,
		       COALESCE(license_key_jwt, ''), license_expires_at, status, created_at, updated_at
		FROM organizations
		WHERE id::text = $1 OR slug = $1
		LIMIT 1
	`
	if idOrSlug == "" {
		idOrSlug = DefaultOrgID
	}

	var org model.Organization
	var statusStr string
	err := s.pool.QueryRow(ctx, q, idOrSlug).Scan(
		&org.ID, &org.Name, &org.Slug, &org.ContactEmail, &org.LicenseTier, &org.MaxDevices,
		&org.LicenseKeyJWT, &org.LicenseExpiresAt, &statusStr, &org.CreatedAt, &org.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			// Return default organization fallback
			return s.GetPrimaryOrganization(ctx)
		}
		return nil, fmt.Errorf("get organization: %w", err)
	}
	org.Status = model.OrganizationStatus(statusStr)

	// Attach active enrolled device count
	count, _ := s.CountEnrolledDevices(ctx, org.ID)
	org.EnrolledDevices = count

	return &org, nil
}

// GetPrimaryOrganization returns the single authoritative organization record.
func (s *Store) GetPrimaryOrganization(ctx context.Context) (*model.Organization, error) {
	if s.pool == nil {
		return &model.Organization{
			ID:          DefaultOrgID,
			Name:        "Primary Organization",
			Slug:        "default",
			LicenseTier: "team",
			MaxDevices:  25,
			Status:      model.OrgStatusActive,
		}, nil
	}

	q := `
		SELECT id, name, slug, contact_email, license_tier, max_devices,
		       COALESCE(license_key_jwt, ''), license_expires_at, status, created_at, updated_at
		FROM organizations
		ORDER BY created_at ASC
		LIMIT 1
	`
	var org model.Organization
	var statusStr string
	err := s.pool.QueryRow(ctx, q).Scan(
		&org.ID, &org.Name, &org.Slug, &org.ContactEmail, &org.LicenseTier, &org.MaxDevices,
		&org.LicenseKeyJWT, &org.LicenseExpiresAt, &statusStr, &org.CreatedAt, &org.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			// Seed and return
			_ = s.EnsureOrganizationsSchema(ctx)
			return &model.Organization{
				ID:          DefaultOrgID,
				Name:        "Primary Organization",
				Slug:        "default",
				LicenseTier: "team",
				MaxDevices:  25,
				Status:      model.OrgStatusActive,
			}, nil
		}
		return nil, fmt.Errorf("get primary organization: %w", err)
	}
	org.Status = model.OrganizationStatus(statusStr)

	count, _ := s.CountEnrolledDevices(ctx, org.ID)
	org.EnrolledDevices = count

	return &org, nil
}

// UpdateOrganization updates organization name and contact email.
func (s *Store) UpdateOrganization(ctx context.Context, orgID, name, contactEmail string) error {
	if s.pool == nil {
		return nil
	}
	if orgID == "" {
		orgID = DefaultOrgID
	}
	q := `
		UPDATE organizations
		SET name = COALESCE(NULLIF($2, ''), name),
		    contact_email = COALESCE(NULLIF($3, ''), contact_email),
		    updated_at = now()
		WHERE id::text = $1 OR id = '00000000-0000-0000-0000-000000000001'::uuid
	`
	_, err := s.pool.Exec(ctx, q, orgID, name, contactEmail)
	return err
}

// UpdateLicenseKey activates a validated license key and updates tier entitlements.
func (s *Store) UpdateLicenseKey(ctx context.Context, orgID, licenseKeyJWT, tier string, maxDevices int, expiresAt *time.Time) error {
	if s.pool == nil {
		return nil
	}
	if orgID == "" {
		orgID = DefaultOrgID
	}
	q := `
		UPDATE organizations
		SET license_key_jwt = $2,
		    license_tier = $3,
		    max_devices = $4,
		    license_expires_at = $5,
		    updated_at = now()
		WHERE id::text = $1 OR id = '00000000-0000-0000-0000-000000000001'::uuid
	`
	_, err := s.pool.Exec(ctx, q, orgID, licenseKeyJWT, tier, maxDevices, expiresAt)
	return err
}

// CountEnrolledDevices returns the count of non-revoked enrolled devices.
// Returns 0 without error if the devices table does not yet exist (e.g. during fresh DB bootstrap).
func (s *Store) CountEnrolledDevices(ctx context.Context, orgID string) (int, error) {
	if s.pool == nil {
		return 0, nil
	}
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM devices 
		WHERE state != 'REVOKED'
	`).Scan(&count)
	if err != nil {
		// Gracefully handle "relation does not exist" (e.g. during fresh DB bootstrap)
		return 0, nil
	}
	return count, nil
}

// GetOrganizationSummary returns dashboard summary details.
func (s *Store) GetOrganizationSummary(ctx context.Context, orgID string) (*model.OrganizationSummary, error) {
	org, err := s.GetOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}

	var daysRemaining int
	if org.LicenseExpiresAt != nil {
		diff := time.Until(*org.LicenseExpiresAt)
		daysRemaining = int(math.Ceil(diff.Hours() / 24))
		if daysRemaining < 0 {
			daysRemaining = 0
		}
	} else {
		daysRemaining = 9999
	}

	return &model.OrganizationSummary{
		ID:               org.ID,
		Name:             org.Name,
		Slug:             org.Slug,
		ContactEmail:     org.ContactEmail,
		LicenseTier:      org.LicenseTier,
		MaxDevices:       org.MaxDevices,
		EnrolledDevices:  org.EnrolledDevices,
		LicenseExpiresAt: org.LicenseExpiresAt,
		DaysRemaining:    daysRemaining,
		Status:           org.Status,
		CreatedAt:        org.CreatedAt,
	}, nil
}
