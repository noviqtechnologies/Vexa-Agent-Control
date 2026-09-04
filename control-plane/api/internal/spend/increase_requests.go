package spend

import (
	"context"
	"encoding/json"
	"fmt"
)

// ── INCREASE REQUESTS ────────────────────────────────────────────────────────

func (s *Store) CreateIncreaseRequest(ctx context.Context, r *IncreaseRequestV2) error {
	return s.pool.QueryRow(ctx, `
		INSERT INTO spend_v2_increase_requests (
			organization_id, project_id, requested_limit_microcents, current_limit_microcents, reason, created_by
		) VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING request_id, created_at
	`, r.OrganizationID, r.ProjectID, r.RequestedLimitMicrocents, r.CurrentLimitMicrocents, r.Reason, r.CreatedBy).
		Scan(&r.RequestID, &r.CreatedAt)
}

func (s *Store) ResolveIncreaseRequest(ctx context.Context, orgID, reqID, status, decidedBy, decisionReason string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var req IncreaseRequestV2
	err = tx.QueryRow(ctx, `
		SELECT request_id, organization_id, project_id, requested_limit_microcents, current_limit_microcents, reason, status
		FROM spend_v2_increase_requests
		WHERE request_id = $1 AND organization_id = $2
		FOR UPDATE
	`, reqID, orgID).Scan(
		&req.RequestID, &req.OrganizationID, &req.ProjectID, &req.RequestedLimitMicrocents, &req.CurrentLimitMicrocents, &req.Reason, &req.Status,
	)
	if err != nil {
		return fmt.Errorf("increase request not found: %w", err)
	}

	var polVerID *string
	if status == "APPROVED" {
		// Create or update project policy with requested limit
		p := SpendPolicy{
			OrganizationID:  orgID,
			ScopeType:       ScopeProject,
			ScopeID:         req.ProjectID,
			PeriodType:      PeriodMonthly,
			LimitMicrocents: req.RequestedLimitMicrocents,
			Action:          ActionHardDeny,
		}
		var polID string
		err = tx.QueryRow(ctx, `
			INSERT INTO spend_policies (organization_id, scope_type, scope_id, currency, period_type, limit_microcents, action, status)
			VALUES ($1, 'project', $2, 'USD', 'monthly', $3, 'hard_deny', 'PUBLISHED')
			ON CONFLICT (organization_id, scope_type, scope_id, period_type)
			DO UPDATE SET limit_microcents = EXCLUDED.limit_microcents, updated_at = now()
			RETURNING policy_id
		`, orgID, req.ProjectID, req.RequestedLimitMicrocents).Scan(&polID)
		if err != nil {
			return fmt.Errorf("failed to upsert policy on approval: %w", err)
		}

		var nextVer int
		_ = tx.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) + 1 FROM spend_policy_versions WHERE policy_id = $1`, polID).Scan(&nextVer)

		p.PolicyID = polID
		snapBytes, _ := json.Marshal(p)
		var vID string
		err = tx.QueryRow(ctx, `
			INSERT INTO spend_policy_versions (policy_id, version, snapshot_json, published_by, published_at)
			VALUES ($1, $2, $3, $4, now())
			RETURNING policy_version_id
		`, polID, nextVer, snapBytes, decidedBy).Scan(&vID)
		if err == nil {
			polVerID = &vID
		}
	}

	_, err = tx.Exec(ctx, `
		UPDATE spend_v2_increase_requests
		SET status = $1, decided_by = $2, decision_reason = $3, resulting_policy_version_id = $4, decided_at = now()
		WHERE request_id = $5 AND organization_id = $6
	`, status, decidedBy, decisionReason, polVerID, reqID, orgID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *Store) ListIncreaseRequests(ctx context.Context, orgID string) ([]IncreaseRequestV2, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT request_id, organization_id, project_id, requested_limit_microcents, current_limit_microcents,
		       reason, status, created_by, decided_by, decision_reason, resulting_policy_version_id, created_at, decided_at
		FROM spend_v2_increase_requests
		WHERE organization_id = $1
		ORDER BY created_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []IncreaseRequestV2
	for rows.Next() {
		var r IncreaseRequestV2
		if err := rows.Scan(
			&r.RequestID, &r.OrganizationID, &r.ProjectID, &r.RequestedLimitMicrocents, &r.CurrentLimitMicrocents,
			&r.Reason, &r.Status, &r.CreatedBy, &r.DecidedBy, &r.DecisionReason, &r.ResultingPolicyVersionID,
			&r.CreatedAt, &r.DecidedAt,
		); err == nil {
			res = append(res, r)
		}
	}
	return res, rows.Err()
}
