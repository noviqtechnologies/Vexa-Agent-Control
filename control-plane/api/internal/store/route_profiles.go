package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

var (
	ErrRouteProfileNotFound = errors.New("route profile not found")
	ErrInvalidRouteProfile  = errors.New("invalid route profile")
)

// ComputeRouteProfileDigest generates a stable SHA-256 digest of route configuration.
func ComputeRouteProfileDigest(p *model.RouteProfile) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%d|%v|%v",
		p.APIFamily, p.MatchModel, p.PrimaryProvider, p.PrimaryModel,
		p.FallbackProvider, p.FallbackModel, p.MaxAttempts, p.DeadlineMs,
		p.RetryClasses, p.AllowedRegions,
	)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// CreateRouteProfile creates a new immutable candidate or versioned route profile.
func (s *Store) CreateRouteProfile(ctx context.Context, p *model.RouteProfile) error {
	if s.pool == nil {
		return errors.New("database pool uninitialized")
	}
	if p.OrganizationID == "" {
		p.OrganizationID = DefaultOrgID
	}
	if p.APIFamily == "" {
		p.APIFamily = "chat_completions"
	}
	if p.MatchModel == "" {
		p.MatchModel = "*"
	}
	if p.MaxAttempts <= 0 || p.MaxAttempts > 2 {
		p.MaxAttempts = 2
	}
	if p.DeadlineMs <= 0 {
		p.DeadlineMs = 30000
	}
	if len(p.RetryClasses) == 0 {
		p.RetryClasses = []string{"502", "503", "504", "429", "connect_timeout", "dns_error"}
	}
	if len(p.AllowedRegions) == 0 {
		p.AllowedRegions = []string{"*"}
	}
	if p.ContentDigest == "" {
		p.ContentDigest = ComputeRouteProfileDigest(p)
	}

	// Determine next version number for this organization and name
	var nextVer int
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(MAX(version), 0) + 1 
		FROM route_profiles 
		WHERE organization_id::text = $1 AND name = $2
	`, p.OrganizationID, p.Name).Scan(&nextVer)
	if err != nil {
		nextVer = 1
	}
	p.Version = nextVer

	var id string
	err = s.pool.QueryRow(ctx, `
		INSERT INTO route_profiles (
			organization_id, name, version, content_digest, api_family, match_model,
			primary_provider, primary_model, fallback_provider, fallback_model,
			max_attempts, deadline_ms, retry_classes, allowed_regions, is_active, created_by
		) VALUES (
			$1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
		)
		RETURNING id::text, created_at
	`,
		p.OrganizationID, p.Name, p.Version, p.ContentDigest, p.APIFamily, p.MatchModel,
		p.PrimaryProvider, p.PrimaryModel, p.FallbackProvider, p.FallbackModel,
		p.MaxAttempts, p.DeadlineMs, p.RetryClasses, p.AllowedRegions, p.IsActive, p.CreatedBy,
	).Scan(&id, &p.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to create route profile: %w", err)
	}
	p.ID = id
	return nil
}

// ListRouteProfiles lists route profiles for a tenant.
func (s *Store) ListRouteProfiles(ctx context.Context, orgID string) ([]*model.RouteProfile, error) {
	if s.pool == nil {
		return []*model.RouteProfile{}, nil
	}
	if orgID == "" {
		orgID = DefaultOrgID
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, organization_id, name, version, content_digest, api_family, match_model,
		       primary_provider, primary_model, fallback_provider, fallback_model,
		       max_attempts, deadline_ms, retry_classes, allowed_regions, is_active, created_at, created_by
		FROM route_profiles
		WHERE organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid
		ORDER BY created_at DESC
		LIMIT 100
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*model.RouteProfile
	for rows.Next() {
		var p model.RouteProfile
		var fallbackProv, fallbackMod *string
		if err := rows.Scan(
			&p.ID, &p.OrganizationID, &p.Name, &p.Version, &p.ContentDigest, &p.APIFamily, &p.MatchModel,
			&p.PrimaryProvider, &p.PrimaryModel, &fallbackProv, &fallbackMod,
			&p.MaxAttempts, &p.DeadlineMs, &p.RetryClasses, &p.AllowedRegions, &p.IsActive, &p.CreatedAt, &p.CreatedBy,
		); err != nil {
			return nil, err
		}
		if fallbackProv != nil {
			p.FallbackProvider = *fallbackProv
		}
		if fallbackMod != nil {
			p.FallbackModel = *fallbackMod
		}
		list = append(list, &p)
	}
	return list, nil
}

// GetRouteProfileByID fetches a specific profile by ID.
func (s *Store) GetRouteProfileByID(ctx context.Context, orgID, profileID string) (*model.RouteProfile, error) {
	if s.pool == nil {
		return nil, ErrRouteProfileNotFound
	}
	if orgID == "" {
		orgID = DefaultOrgID
	}
	var p model.RouteProfile
	var fallbackProv, fallbackMod *string
	err := s.pool.QueryRow(ctx, `
		SELECT id, organization_id, name, version, content_digest, api_family, match_model,
		       primary_provider, primary_model, fallback_provider, fallback_model,
		       max_attempts, deadline_ms, retry_classes, allowed_regions, is_active, created_at, created_by
		FROM route_profiles
		WHERE id::text = $1 AND (organization_id::text = $2 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
	`, profileID, orgID).Scan(
		&p.ID, &p.OrganizationID, &p.Name, &p.Version, &p.ContentDigest, &p.APIFamily, &p.MatchModel,
		&p.PrimaryProvider, &p.PrimaryModel, &fallbackProv, &fallbackMod,
		&p.MaxAttempts, &p.DeadlineMs, &p.RetryClasses, &p.AllowedRegions, &p.IsActive, &p.CreatedAt, &p.CreatedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRouteProfileNotFound
		}
		return nil, err
	}
	if fallbackProv != nil {
		p.FallbackProvider = *fallbackProv
	}
	if fallbackMod != nil {
		p.FallbackModel = *fallbackMod
	}
	return &p, nil
}

// GetActiveRouteProfile resolves the active profile matching API family and model.
func (s *Store) GetActiveRouteProfile(ctx context.Context, orgID, apiFamily, modelName string) (*model.RouteProfile, error) {
	if s.pool == nil {
		return nil, nil
	}
	if orgID == "" {
		orgID = DefaultOrgID
	}
	if apiFamily == "" {
		apiFamily = "chat_completions"
	}

	var p model.RouteProfile
	var fallbackProv, fallbackMod *string
	err := s.pool.QueryRow(ctx, `
		SELECT id, organization_id, name, version, content_digest, api_family, match_model,
		       primary_provider, primary_model, fallback_provider, fallback_model,
		       max_attempts, deadline_ms, retry_classes, allowed_regions, is_active, created_at, created_by
		FROM route_profiles
		WHERE is_active = true 
		  AND api_family = $1
		  AND (organization_id::text = $2 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
		  AND (match_model = '*' OR match_model = $3 OR (match_model LIKE '%*%' AND $3 LIKE REPLACE(match_model, '*', '%')))
		ORDER BY (match_model = $3) DESC, (match_model != '*') DESC, created_at DESC
		LIMIT 1
	`, apiFamily, orgID, modelName).Scan(
		&p.ID, &p.OrganizationID, &p.Name, &p.Version, &p.ContentDigest, &p.APIFamily, &p.MatchModel,
		&p.PrimaryProvider, &p.PrimaryModel, &fallbackProv, &fallbackMod,
		&p.MaxAttempts, &p.DeadlineMs, &p.RetryClasses, &p.AllowedRegions, &p.IsActive, &p.CreatedAt, &p.CreatedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if fallbackProv != nil {
		p.FallbackProvider = *fallbackProv
	}
	if fallbackMod != nil {
		p.FallbackModel = *fallbackMod
	}
	return &p, nil
}

// ActivateRouteProfile atomically activates a route profile and records an activation event.
func (s *Store) ActivateRouteProfile(ctx context.Context, orgID, profileID, activatedBy, reason string, rollbackFromID *string) (*model.RouteProfileActivation, error) {
	if s.pool == nil {
		return nil, errors.New("database pool uninitialized")
	}
	if orgID == "" {
		orgID = DefaultOrgID
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// 1. Fetch profile to activate
	var p model.RouteProfile
	err = tx.QueryRow(ctx, `
		SELECT id, version, content_digest, api_family, match_model
		FROM route_profiles
		WHERE id::text = $1 AND organization_id::text = $2
	`, profileID, orgID).Scan(&p.ID, &p.Version, &p.ContentDigest, &p.APIFamily, &p.MatchModel)
	if err != nil {
		return nil, fmt.Errorf("profile not found for activation: %w", err)
	}

	// 2. Deactivate conflicting active profiles for this scope
	_, err = tx.Exec(ctx, `
		UPDATE route_profiles
		SET is_active = false
		WHERE organization_id::text = $1 AND api_family = $2 AND match_model = $3 AND is_active = true
	`, orgID, p.APIFamily, p.MatchModel)
	if err != nil {
		return nil, fmt.Errorf("failed to deactivate prior profiles: %w", err)
	}

	// 3. Set target profile active
	_, err = tx.Exec(ctx, `
		UPDATE route_profiles
		SET is_active = true
		WHERE id::text = $1
	`, profileID)
	if err != nil {
		return nil, fmt.Errorf("failed to activate target profile: %w", err)
	}

	// 4. Record Activation
	var act model.RouteProfileActivation
	err = tx.QueryRow(ctx, `
		INSERT INTO route_profile_activations (
			organization_id, route_profile_id, version, content_digest, activated_by, reason, rollback_from_activation_id
		) VALUES (
			$1::uuid, $2::uuid, $3, $4, $5, $6, $7
		)
		RETURNING id::text, organization_id::text, route_profile_id::text, version, content_digest, activated_at, activated_by, reason
	`, orgID, profileID, p.Version, p.ContentDigest, activatedBy, reason, rollbackFromID).Scan(
		&act.ID, &act.OrganizationID, &act.RouteProfileID, &act.Version, &act.ContentDigest, &act.ActivatedAt, &act.ActivatedBy, &act.Reason,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to record activation event: %w", err)
	}
	act.RollbackFromActivationID = rollbackFromID

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &act, nil
}
