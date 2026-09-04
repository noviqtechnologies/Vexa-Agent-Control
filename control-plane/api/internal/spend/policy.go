package spend

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// ── POLICY MANAGEMENT & EFFECTIVE BUDGETS ────────────────────────────────────

func (s *Store) CreatePolicy(ctx context.Context, p *SpendPolicy) error {
	return s.pool.QueryRow(ctx, `
		INSERT INTO spend_policies (
			organization_id, scope_type, scope_id, currency, period_type,
			limit_microcents, action, effective_from, status
		) VALUES ($1, $2, $3, 'USD', $4, $5, $6, now(), 'DRAFT')
		ON CONFLICT (organization_id, scope_type, scope_id, period_type)
		DO UPDATE SET limit_microcents = EXCLUDED.limit_microcents, action = EXCLUDED.action, updated_at = now()
		RETURNING policy_id, created_at, updated_at
	`, p.OrganizationID, p.ScopeType, p.ScopeID, p.PeriodType, p.LimitMicrocents, p.Action).
		Scan(&p.PolicyID, &p.CreatedAt, &p.UpdatedAt)
}

func (s *Store) PublishPolicy(ctx context.Context, orgID, policyID, publishedBy string) (*SpendPolicyVersion, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var p SpendPolicy
	err = tx.QueryRow(ctx, `
		SELECT policy_id, organization_id, scope_type, scope_id, currency, period_type, limit_microcents, action
		FROM spend_policies
		WHERE policy_id = $1 AND organization_id = $2
		FOR UPDATE
	`, policyID, orgID).Scan(
		&p.PolicyID, &p.OrganizationID, &p.ScopeType, &p.ScopeID, &p.Currency, &p.PeriodType, &p.LimitMicrocents, &p.Action,
	)
	if err != nil {
		return nil, fmt.Errorf("policy not found: %w", err)
	}

	var nextVersion int
	err = tx.QueryRow(ctx, `
		SELECT COALESCE(MAX(version), 0) + 1 FROM spend_policy_versions WHERE policy_id = $1
	`, policyID).Scan(&nextVersion)
	if err != nil {
		return nil, err
	}

	snapshotBytes, _ := json.Marshal(p)
	var pv SpendPolicyVersion
	err = tx.QueryRow(ctx, `
		INSERT INTO spend_policy_versions (policy_id, version, snapshot_json, published_by, published_at)
		VALUES ($1, $2, $3, $4, now())
		RETURNING policy_version_id, version, published_at
	`, policyID, nextVersion, snapshotBytes, publishedBy).Scan(&pv.PolicyVersionID, &pv.Version, &pv.PublishedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy version: %w", err)
	}
	pv.PolicyID = policyID
	pv.PublishedBy = publishedBy
	pv.SnapshotJSON = string(snapshotBytes)

	_, err = tx.Exec(ctx, `UPDATE spend_policies SET status = 'PUBLISHED', updated_at = now() WHERE policy_id = $1`, policyID)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return &pv, nil
}

// EnsureDefaultPolicyForOrg ensures an organization has at least a default monthly policy ($100/mo) seeded and published.
func (s *Store) EnsureDefaultPolicyForOrg(ctx context.Context, orgID string) error {
	if s.pool == nil || orgID == "" {
		return nil
	}
	var count int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM spend_policies WHERE organization_id = $1`, orgID).Scan(&count)
	if err != nil || count > 0 {
		return err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var policyID string
	err = tx.QueryRow(ctx, `
		INSERT INTO spend_policies (
			organization_id, scope_type, scope_id, currency, period_type,
			limit_microcents, action, effective_from, status
		) VALUES (
			$1, 'organization', $1, 'USD', 'monthly',
			10000000000, 'hard_deny', now(), 'PUBLISHED'
		) ON CONFLICT (organization_id, scope_type, scope_id, period_type) DO UPDATE SET updated_at = now()
		RETURNING policy_id
	`, orgID).Scan(&policyID)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO spend_policy_versions (
			policy_id, version, snapshot_json, published_by, published_at
		) VALUES (
			$1, 1, '{"scope_type":"organization","limit_microcents":10000000000,"period_type":"monthly"}'::jsonb,
			'system', now()
		) ON CONFLICT (policy_id, version) DO NOTHING
	`, policyID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *Store) ListPolicies(ctx context.Context, orgID string) ([]SpendPolicy, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT policy_id, organization_id, scope_type, scope_id, currency, period_type, limit_microcents, action, effective_from, status, created_at, updated_at
		FROM spend_policies
		WHERE organization_id = $1
		ORDER BY scope_type, scope_id, period_type
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []SpendPolicy
	for rows.Next() {
		var p SpendPolicy
		if err := rows.Scan(&p.PolicyID, &p.OrganizationID, &p.ScopeType, &p.ScopeID, &p.Currency, &p.PeriodType, &p.LimitMicrocents, &p.Action, &p.EffectiveFrom, &p.Status, &p.CreatedAt, &p.UpdatedAt); err == nil {
			res = append(res, p)
		}
	}
	return res, rows.Err()
}

// ResolveEffectivePolicies resolves active published spend policies at a given timestamp.
func (s *Store) ResolveEffectivePolicies(ctx context.Context, orgID, projectID, provider string, at time.Time) ([]SpendPolicy, error) {
	if s.pool == nil {
		return []SpendPolicy{}, nil
	}

	if at.IsZero() {
		at = time.Now().UTC()
	}

	rows, err := s.pool.Query(ctx, `
		SELECT p.policy_id::text, p.organization_id::text, p.scope_type, p.scope_id, p.currency,
		       p.period_type, p.limit_microcents, p.action, p.effective_from, p.effective_to, p.status,
		       p.created_at, p.updated_at
		FROM spend_policies p
		WHERE p.organization_id = $1
		  AND p.status = 'PUBLISHED'
		  AND p.effective_from <= $2
		  AND (p.effective_to IS NULL OR p.effective_to > $2)
		  AND (
		    p.scope_type = 'organization'
		    OR (p.scope_type = 'project' AND p.scope_id = $3)
		    OR (p.scope_type = 'provider' AND LOWER(p.scope_id) = LOWER($4))
		  )
		ORDER BY 
		    CASE p.scope_type 
		        WHEN 'organization' THEN 1 
		        WHEN 'project' THEN 2 
		        WHEN 'provider' THEN 3 
		    END,
		    p.created_at DESC
	`, orgID, at, projectID, provider)
	if err != nil {
		return nil, fmt.Errorf("resolve effective policies: %w", err)
	}
	defer rows.Close()

	policies := make([]SpendPolicy, 0)
	for rows.Next() {
		var p SpendPolicy
		var effTo *time.Time
		if err := rows.Scan(
			&p.PolicyID, &p.OrganizationID, &p.ScopeType, &p.ScopeID, &p.Currency,
			&p.PeriodType, &p.LimitMicrocents, &p.Action, &p.EffectiveFrom, &effTo, &p.Status,
			&p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			continue
		}
		p.EffectiveTo = effTo
		policies = append(policies, p)
	}
	return policies, rows.Err()
}
