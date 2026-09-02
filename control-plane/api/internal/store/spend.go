package store

import (
	"context"
	"time"
)

type SpendBudget struct {
	ScopeType string    `json:"scope_type"`
	ScopeKey  string    `json:"scope_key"`
	CapCents  int64     `json:"cap_cents"`
	Period    string    `json:"period"`
	UpdatedAt time.Time `json:"updated_at"`
}

type SpendSnapshot struct {
	AgentID             string    `json:"agent_id"`
	PeriodStart         time.Time `json:"period_start"`
	SpentCents          int64     `json:"spent_cents"`
	CapCents            *int64    `json:"cap_cents"`
	IsEstimated         bool      `json:"is_estimated"`
	PricingTableVersion string    `json:"pricing_table_version"`
	SyncedAt            time.Time `json:"synced_at"`
}

type IncreaseRequest struct {
	RequestID   string     `json:"request_id"`
	AgentID     string     `json:"agent_id"`
	CurrentCap  int64      `json:"current_cap"`
	Reason      *string    `json:"reason"`
	Status      string     `json:"status"`
	SubmittedAt time.Time  `json:"submitted_at"`
	ResolvedAt  *time.Time `json:"resolved_at"`
	ResolvedBy  *string    `json:"resolved_by"`
	NewCap      *int64     `json:"new_cap"`
}

func (s *Store) UpsertSpendBudget(ctx context.Context, organizationID string, b *SpendBudget) error {
	if s.pool == nil {
		return nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO spend_policies (organization_id, scope_type, scope_id, limit_microcents, period_type, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, now(), now())
		ON CONFLICT (organization_id, scope_type, scope_id, period_type) DO UPDATE SET
			limit_microcents = EXCLUDED.limit_microcents,
			updated_at       = now()
	`, organizationID, b.ScopeType, b.ScopeKey, b.CapCents*10000, b.Period)
	return err
}

func (s *Store) ListSpendBudgets(ctx context.Context, organizationID string) ([]SpendBudget, error) {
	if s.pool == nil {
		return []SpendBudget{}, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	rows, err := s.pool.Query(ctx, `
		SELECT scope_type, scope_id, (limit_microcents / 10000)::bigint, period_type, updated_at 
		FROM spend_policies 
		WHERE organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid
		ORDER BY scope_type, scope_id
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []SpendBudget
	for rows.Next() {
		var b SpendBudget
		if err := rows.Scan(&b.ScopeType, &b.ScopeKey, &b.CapCents, &b.Period, &b.UpdatedAt); err != nil {
			return nil, err
		}
		res = append(res, b)
	}
	return res, rows.Err()
}

func (s *Store) UpsertSpendSnapshot(ctx context.Context, organizationID string, snap *SpendSnapshot) error {
	if s.pool == nil {
		return nil
	}
	return nil
}

func (s *Store) ListSpendSnapshots(ctx context.Context, organizationID string) ([]SpendSnapshot, error) {
	if s.pool == nil {
		return []SpendSnapshot{}, nil
	}
	return []SpendSnapshot{}, nil
}

func (s *Store) InsertIncreaseRequest(ctx context.Context, organizationID string, r *IncreaseRequest) error {
	if s.pool == nil {
		return nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO spend_v2_increase_requests (organization_id, requested_limit_microcents, current_limit_microcents, reason, status, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, now())
	`, organizationID, r.CurrentCap*10000, r.CurrentCap*10000, r.Reason, r.Status, r.AgentID)
	return err
}

func (s *Store) ResolveIncreaseRequest(ctx context.Context, organizationID, id string, status string, resolvedBy string, newCap *int64) error {
	if s.pool == nil {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE spend_v2_increase_requests 
		SET status = $2, decided_at = now(), decided_by = $3
		WHERE request_id::text = $1
	`, id, status, resolvedBy)
	return err
}

func (s *Store) ListIncreaseRequests(ctx context.Context, organizationID string) ([]IncreaseRequest, error) {
	if s.pool == nil {
		return []IncreaseRequest{}, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	rows, err := s.pool.Query(ctx, `
		SELECT request_id::text, created_by, (current_limit_microcents / 10000)::bigint, reason, status, created_at, decided_at, decided_by, (requested_limit_microcents / 10000)::bigint
		FROM spend_v2_increase_requests 
		WHERE organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid
		ORDER BY created_at DESC
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []IncreaseRequest
	for rows.Next() {
		var b IncreaseRequest
		if err := rows.Scan(&b.RequestID, &b.AgentID, &b.CurrentCap, &b.Reason, &b.Status, &b.SubmittedAt, &b.ResolvedAt, &b.ResolvedBy, &b.NewCap); err != nil {
			return nil, err
		}
		res = append(res, b)
	}
	return res, rows.Err()
}
