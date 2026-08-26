package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

func (s *Store) ListPolicies(ctx context.Context, tenantID string) ([]*model.Policy, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, version, content, is_active, created_at, updated_at
		FROM policies
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT 50
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*model.Policy
	for rows.Next() {
		var p model.Policy
		if err := rows.Scan(&p.ID, &p.Version, &p.Content, &p.IsActive, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		policies = append(policies, &p)
	}
	return policies, nil
}

func (s *Store) GetRawActivePolicy(ctx context.Context, tenantID string) (*model.Policy, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	var p model.Policy
	err := s.pool.QueryRow(ctx, `
		SELECT id, version, content, is_active, created_at, updated_at
		FROM policies
		WHERE is_active = true AND tenant_id = $1
	`, tenantID).Scan(
		&p.ID, &p.Version, &p.Content, &p.IsActive, &p.CreatedAt, &p.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) GetActivePolicy(ctx context.Context, tenantID string) (*model.Policy, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	p, err := s.GetRawActivePolicy(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}

	// Dynamic Assembly: Merge active group_policy_versions into the served policy YAML (FR-112)
	groupPolicies, err := s.ListGroupPolicies(ctx, tenantID)
	if err == nil && len(groupPolicies) > 0 {
		var groupsYaml strings.Builder
		groupsYaml.WriteString("\n\ngroups:\n")
		for _, gp := range groupPolicies {
			groupsYaml.WriteString(fmt.Sprintf("  - id: %q\n", gp.GroupID))
			
			// Parse claims
			var claimsList []string
			var claimsObj map[string]interface{}
			if err := json.Unmarshal(gp.Claims, &claimsList); err != nil {
				if err := json.Unmarshal(gp.Claims, &claimsObj); err == nil {
					if gVal, ok := claimsObj["groups"]; ok {
						if gSlice, ok := gVal.([]interface{}); ok {
							for _, item := range gSlice {
								if sItem, ok := item.(string); ok {
									claimsList = append(claimsList, sItem)
								}
							}
						}
					}
				}
			}
			if len(claimsList) == 0 {
				claimsList = append(claimsList, gp.GroupID)
			}

			groupsYaml.WriteString("    claims:\n")
			for _, c := range claimsList {
				groupsYaml.WriteString(fmt.Sprintf("      - %q\n", c))
			}

			// Parse tools
			var toolRules []map[string]interface{}
			if err := json.Unmarshal(gp.Tools, &toolRules); err == nil && len(toolRules) > 0 {
				groupsYaml.WriteString("    tools:\n")
				for _, tr := range toolRules {
					name, _ := tr["name"].(string)
					action, _ := tr["action"].(string)
					if name != "" {
						if action == "" {
							action = "allow"
						}
						groupsYaml.WriteString(fmt.Sprintf("      - name: %q\n        action: %q\n", name, action))
					}
				}
			}
		}
		p.Content += groupsYaml.String()
	}

	return p, nil
}

// EnsurePoliciesSchema ensures policies table has tenant_id and tenant-scoped unique active index.
func (s *Store) EnsurePoliciesSchema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	q := `
		ALTER TABLE policies ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;
		ALTER TABLE policies DROP CONSTRAINT IF EXISTS policies_version_key;
		DROP INDEX IF EXISTS idx_policies_active_unique;
		CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_tenant_version ON policies (tenant_id, version);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_tenant_active_unique ON policies (tenant_id, is_active) WHERE is_active = true;
	`
	_, err := s.pool.Exec(ctx, q)
	return err
}

func (s *Store) SavePolicy(ctx context.Context, tenantID string, p *model.Policy) error {
	if tenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	// If this one is active, deactivate all others within tenant first in a transaction
	return s.InTx(ctx, func(tx pgx.Tx) error {
		if p.IsActive {
			// Ensure obsolete global index is dropped and per-tenant index exists
			_, _ = tx.Exec(ctx, "ALTER TABLE policies DROP CONSTRAINT IF EXISTS policies_version_key")
			_, _ = tx.Exec(ctx, "DROP INDEX IF EXISTS idx_policies_active_unique")
			_, _ = tx.Exec(ctx, "CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_tenant_version ON policies (tenant_id, version)")
			_, _ = tx.Exec(ctx, "CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_tenant_active_unique ON policies (tenant_id, is_active) WHERE is_active = true")

			_, err := tx.Exec(ctx, "UPDATE policies SET is_active = false WHERE is_active = true AND (tenant_id = $1 OR tenant_id IS NULL)", tenantID)
			if err != nil {
				return err
			}
		}

		var id string
		err := tx.QueryRow(ctx, `
			INSERT INTO policies (tenant_id, version, content, is_active, created_at, updated_at)
			VALUES ($1, $2, $3, $4, now(), now())
			ON CONFLICT (tenant_id, version) DO UPDATE SET
				content = EXCLUDED.content,
				is_active = EXCLUDED.is_active,
				updated_at = now()
			RETURNING id
		`, tenantID, p.Version, p.Content, p.IsActive).Scan(&id)
		
		if err == nil {
			p.ID = id
		}
		return err
	})
}
