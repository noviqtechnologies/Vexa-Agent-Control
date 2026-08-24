package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type GroupPolicyVersion struct {
	ID        string          `json:"id"`
	TenantID  string          `json:"tenant_id"`
	GroupID   string          `json:"group_id"`
	Version   int             `json:"version"`
	Claims    json.RawMessage `json:"claims"`
	Tools     json.RawMessage `json:"tools"`
	CreatedAt time.Time       `json:"created_at"`
	CreatedBy string          `json:"created_by"`
	Active    bool            `json:"active"`
}

// EnsureGroupPoliciesSchema guarantees schema consistency for the group_policy_versions table.
func (s *Store) EnsureGroupPoliciesSchema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	q := `
		CREATE TABLE IF NOT EXISTS group_policy_versions (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			group_id TEXT NOT NULL,
			version INT NOT NULL,
			claims JSONB NOT NULL DEFAULT '[]'::jsonb,
			tools JSONB NOT NULL DEFAULT '[]'::jsonb,
			created_by TEXT NOT NULL DEFAULT 'system',
			active BOOLEAN NOT NULL DEFAULT true,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (tenant_id, group_id, version)
		);

		ALTER TABLE group_policy_versions ADD COLUMN IF NOT EXISTS created_by TEXT NOT NULL DEFAULT 'system';
		ALTER TABLE group_policy_versions ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT true;
		CREATE INDEX IF NOT EXISTS idx_group_policies_tenant ON group_policy_versions(tenant_id, group_id);
	`
	_, err := s.pool.Exec(ctx, q)
	return err
}

// GetActiveGroupPolicy gets the active policy for a group within a tenant.
func (s *Store) GetActiveGroupPolicy(ctx context.Context, tenantID, groupID string) (*GroupPolicyVersion, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	var p GroupPolicyVersion
	var claims, tools []byte

	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, group_id, version, claims, tools, created_at, created_by, active
		FROM group_policy_versions
		WHERE tenant_id = $1 AND group_id = $2 AND active = true
	`, tenantID, groupID).Scan(
		&p.ID, &p.TenantID, &p.GroupID, &p.Version, &claims, &tools, &p.CreatedAt, &p.CreatedBy, &p.Active,
	)
	if err == pgx.ErrNoRows {
		return nil, nil // Not found
	}
	if err != nil {
		return nil, fmt.Errorf("query active group policy: %w", err)
	}
	p.Claims = json.RawMessage(claims)
	p.Tools = json.RawMessage(tools)
	return &p, nil
}

// PublishGroupPolicy creates a new version of the group policy and sets it to active, deactivating the old one within tenant.
func (s *Store) PublishGroupPolicy(ctx context.Context, tenantID, groupID string, claims json.RawMessage, tools json.RawMessage, createdBy string) (*GroupPolicyVersion, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Get max version for this group within tenant
	var currentVersion int
	err = tx.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM group_policy_versions WHERE tenant_id = $1 AND group_id = $2`, tenantID, groupID).Scan(&currentVersion)
	if err != nil && err != pgx.ErrNoRows {
		return nil, fmt.Errorf("get max version: %w", err)
	}

	nextVersion := currentVersion + 1

	// Deactivate existing active version for this group within tenant
	_, err = tx.Exec(ctx, `UPDATE group_policy_versions SET active = false WHERE tenant_id = $1 AND group_id = $2 AND active = true`, tenantID, groupID)
	if err != nil {
		return nil, fmt.Errorf("deactivate current version: %w", err)
	}

	var p GroupPolicyVersion
	var outClaims, outTools []byte

	err = tx.QueryRow(ctx, `
		INSERT INTO group_policy_versions (tenant_id, group_id, version, claims, tools, created_by, active)
		VALUES ($1, $2, $3, $4, $5, $6, true)
		RETURNING id, tenant_id, group_id, version, claims, tools, created_at, created_by, active
	`, tenantID, groupID, nextVersion, claims, tools, createdBy).Scan(
		&p.ID, &p.TenantID, &p.GroupID, &p.Version, &outClaims, &outTools, &p.CreatedAt, &p.CreatedBy, &p.Active,
	)
	if err != nil {
		return nil, fmt.Errorf("insert group policy: %w", err)
	}
	p.Claims = json.RawMessage(outClaims)
	p.Tools = json.RawMessage(outTools)

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return &p, nil
}

// ListGroupPolicies returns a list of all active group policies for a tenant.
func (s *Store) ListGroupPolicies(ctx context.Context, tenantID string) ([]*GroupPolicyVersion, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, group_id, version, claims, tools, created_at, created_by, active
		FROM group_policy_versions
		WHERE tenant_id = $1 AND active = true
		ORDER BY group_id ASC
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query list group policies: %w", err)
	}
	defer rows.Close()

	var policies []*GroupPolicyVersion
	for rows.Next() {
		var p GroupPolicyVersion
		var claims, tools []byte
		if err := rows.Scan(&p.ID, &p.TenantID, &p.GroupID, &p.Version, &claims, &tools, &p.CreatedAt, &p.CreatedBy, &p.Active); err != nil {
			return nil, fmt.Errorf("scan list group policies: %w", err)
		}
		p.Claims = json.RawMessage(claims)
		p.Tools = json.RawMessage(tools)
		policies = append(policies, &p)
	}
	return policies, rows.Err()
}
