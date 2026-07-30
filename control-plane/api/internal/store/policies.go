package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/model"
)

func (s *Store) ListPolicies(ctx context.Context) ([]*model.Policy, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, version, content, is_active, created_at, updated_at
		FROM policies
		ORDER BY created_at DESC
		LIMIT 50
	`)
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

func (s *Store) GetRawActivePolicy(ctx context.Context) (*model.Policy, error) {
	var p model.Policy
	err := s.pool.QueryRow(ctx, `
		SELECT id, version, content, is_active, created_at, updated_at
		FROM policies
		WHERE is_active = true
	`).Scan(
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

func (s *Store) GetActivePolicy(ctx context.Context) (*model.Policy, error) {
	p, err := s.GetRawActivePolicy(ctx)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}

	// Dynamic Assembly: Merge active group_policy_versions into the served policy YAML (FR-112)
	groupPolicies, err := s.ListGroupPolicies(ctx)
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

func (s *Store) SavePolicy(ctx context.Context, p *model.Policy) error {
	// If this one is active, deactivate all others first in a transaction
	return s.InTx(ctx, func(tx pgx.Tx) error {
		if p.IsActive {
			_, err := tx.Exec(ctx, "UPDATE policies SET is_active = false WHERE is_active = true")
			if err != nil {
				return err
			}
		}

		var id string
		err := tx.QueryRow(ctx, `
			INSERT INTO policies (version, content, is_active, created_at, updated_at)
			VALUES ($1, $2, $3, now(), now())
			ON CONFLICT (version) DO UPDATE SET
				content = EXCLUDED.content,
				is_active = EXCLUDED.is_active,
				updated_at = now()
			RETURNING id
		`, p.Version, p.Content, p.IsActive).Scan(&id)
		
		if err == nil {
			p.ID = id
		}
		return err
	})
}
