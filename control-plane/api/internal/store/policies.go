package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

func (s *Store) ListPolicies(ctx context.Context, organizationID string) ([]*model.Policy, error) {
	if s.pool == nil {
		return []*model.Policy{}, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, version, content, is_active, created_at, updated_at
		FROM policies
		WHERE organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid
		ORDER BY created_at DESC
		LIMIT 50
	`, organizationID)
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

func (s *Store) GetRawActivePolicy(ctx context.Context, organizationID string) (*model.Policy, error) {
	if s.pool == nil {
		return nil, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	var p model.Policy
	err := s.pool.QueryRow(ctx, `
		SELECT id, version, content, is_active, created_at, updated_at
		FROM policies
		WHERE is_active = true AND (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
		ORDER BY updated_at DESC
		LIMIT 1
	`, organizationID).Scan(
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

func (s *Store) GetActivePolicy(ctx context.Context, organizationID string) (*model.Policy, error) {
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	p, err := s.GetRawActivePolicy(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}

	// Dynamic Assembly: Merge active group_policy_versions into the served policy YAML
	groupPolicies, err := s.ListGroupPolicies(ctx, organizationID)
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

// EnsurePoliciesSchema ensures policies table exists.
func (s *Store) EnsurePoliciesSchema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	q := `
		CREATE TABLE IF NOT EXISTS policies (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			version         TEXT NOT NULL,
			content         TEXT NOT NULL,
			is_active       BOOLEAN NOT NULL DEFAULT false,
			created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT uq_policies_org_version UNIQUE (organization_id, version)
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_active_unique ON policies (organization_id, is_active) WHERE is_active = true;
	`
	_, err := s.pool.Exec(ctx, q)
	return err
}

func (s *Store) SavePolicy(ctx context.Context, organizationID string, p *model.Policy) error {
	if s.pool == nil {
		return nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	err := s.InTx(ctx, func(tx pgx.Tx) error {
		if p.IsActive {
			_, err := tx.Exec(ctx, "UPDATE policies SET is_active = false WHERE is_active = true AND (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)", organizationID)
			if err != nil {
				return err
			}
		}

		var id string
		err := tx.QueryRow(ctx, `
			INSERT INTO policies (organization_id, version, content, is_active, created_at, updated_at)
			VALUES ($1, $2, $3, $4, now(), now())
			ON CONFLICT (organization_id, version) DO UPDATE SET
				content = EXCLUDED.content,
				is_active = EXCLUDED.is_active,
				updated_at = now()
			RETURNING id
		`, organizationID, p.Version, p.Content, p.IsActive).Scan(&id)
		
		if err == nil {
			p.ID = id
		}
		return err
	})
	if err != nil {
		return err
	}

	_ = s.InsertAuditEvent(ctx, organizationID, &AuditEvent{
		OrganizationID: organizationID,
		TenantID:       organizationID,
		TableName:      "policies",
		Action:         "updated",
		ChangedBy:      "admin",
		ActorRole:      "admin",
		AffectedItemID: p.Version,
		UpdatedValue: map[string]interface{}{
			"id":        p.ID,
			"version":   p.Version,
			"is_active": p.IsActive,
		},
		Outcome: "SUCCESS",
	})

	return nil
}
