package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type GroupPolicyVersion struct {
	ID             string          `json:"id"`
	OrganizationID string          `json:"organization_id"`
	TenantID       string          `json:"tenant_id"` // Alias
	GroupID        string          `json:"group_id"`
	Version        int             `json:"version"`
	Claims         json.RawMessage `json:"claims"`
	Tools          json.RawMessage `json:"tools"`
	CreatedAt      time.Time       `json:"created_at"`
	CreatedBy      string          `json:"created_by"`
	Active         bool            `json:"active"`
}

// EnsureGroupPoliciesSchema guarantees schema consistency for the group_policy_versions table.
func (s *Store) EnsureGroupPoliciesSchema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	q := `
		CREATE TABLE IF NOT EXISTS group_policy_versions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
			version INT NOT NULL,
			claims JSONB NOT NULL DEFAULT '[]'::jsonb,
			tools JSONB NOT NULL DEFAULT '[]'::jsonb,
			created_by TEXT NOT NULL DEFAULT 'system',
			active BOOLEAN NOT NULL DEFAULT true,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT uq_team_policy_version UNIQUE (organization_id, team_id, version)
		);
	`
	_, err := s.pool.Exec(ctx, q)
	return err
}

// GetActiveGroupPolicy gets the active policy for a group/team.
func (s *Store) GetActiveGroupPolicy(ctx context.Context, organizationID, groupID string) (*GroupPolicyVersion, error) {
	if s.pool == nil {
		return nil, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	var p GroupPolicyVersion
	var claims, tools []byte

	err := s.pool.QueryRow(ctx, `
		SELECT id, organization_id, team_id, version, claims, tools, created_at, created_by, active
		FROM group_policy_versions
		WHERE (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
		  AND team_id = $2 AND active = true
	`, organizationID, groupID).Scan(
		&p.ID, &p.OrganizationID, &p.GroupID, &p.Version, &claims, &tools, &p.CreatedAt, &p.CreatedBy, &p.Active,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query active group policy: %w", err)
	}
	p.TenantID = p.OrganizationID
	p.Claims = json.RawMessage(claims)
	p.Tools = json.RawMessage(tools)
	return &p, nil
}

// PublishGroupPolicy creates a new version of the group policy and sets it to active.
func (s *Store) PublishGroupPolicy(ctx context.Context, organizationID, groupID string, claims json.RawMessage, tools json.RawMessage, createdBy string) (*GroupPolicyVersion, error) {
	if s.pool == nil {
		return nil, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Ensure team exists
	_, _ = tx.Exec(ctx, `
		INSERT INTO teams (id, organization_id, name)
		VALUES ($1, $2, $1)
		ON CONFLICT (id) DO NOTHING;
	`, groupID, organizationID)

	var currentVersion int
	err = tx.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM group_policy_versions WHERE organization_id::text = $1 AND team_id = $2`, organizationID, groupID).Scan(&currentVersion)
	if err != nil && err != pgx.ErrNoRows {
		return nil, fmt.Errorf("get max version: %w", err)
	}

	nextVersion := currentVersion + 1

	// Deactivate existing active version
	_, err = tx.Exec(ctx, `UPDATE group_policy_versions SET active = false WHERE organization_id::text = $1 AND team_id = $2 AND active = true`, organizationID, groupID)
	if err != nil {
		return nil, fmt.Errorf("deactivate current version: %w", err)
	}

	var p GroupPolicyVersion
	err = tx.QueryRow(ctx, `
		INSERT INTO group_policy_versions (organization_id, team_id, version, claims, tools, created_by, active, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, true, now())
		RETURNING id, organization_id, team_id, version, created_at, created_by, active
	`, organizationID, groupID, nextVersion, claims, tools, createdBy).Scan(
		&p.ID, &p.OrganizationID, &p.GroupID, &p.Version, &p.CreatedAt, &p.CreatedBy, &p.Active,
	)
	if err != nil {
		return nil, fmt.Errorf("insert group policy version: %w", err)
	}

	p.TenantID = p.OrganizationID
	p.Claims = claims
	p.Tools = tools

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return &p, nil
}

// ListGroupPolicies lists the active group policies for an organization.
func (s *Store) ListGroupPolicies(ctx context.Context, organizationID string) ([]*GroupPolicyVersion, error) {
	if s.pool == nil {
		return []*GroupPolicyVersion{}, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, organization_id, team_id, version, claims, tools, created_at, created_by, active
		FROM group_policy_versions
		WHERE (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
		  AND active = true
		ORDER BY team_id ASC
	`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("query group policies: %w", err)
	}
	defer rows.Close()

	var policies []*GroupPolicyVersion
	for rows.Next() {
		var p GroupPolicyVersion
		var claims, tools []byte
		if err := rows.Scan(&p.ID, &p.OrganizationID, &p.GroupID, &p.Version, &claims, &tools, &p.CreatedAt, &p.CreatedBy, &p.Active); err != nil {
			return nil, fmt.Errorf("scan group policy: %w", err)
		}
		p.TenantID = p.OrganizationID
		p.Claims = json.RawMessage(claims)
		p.Tools = json.RawMessage(tools)
		policies = append(policies, &p)
	}

	return policies, nil
}
