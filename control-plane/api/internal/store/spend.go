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

func (s *Store) UpsertSpendBudget(ctx context.Context, tenantID string, b *SpendBudget) error {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO spend_budgets (tenant_id, scope_type, scope_key, cap_cents, period, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, now(), now())
		ON CONFLICT (scope_type, scope_key) DO UPDATE SET
			tenant_id  = EXCLUDED.tenant_id,
			cap_cents  = EXCLUDED.cap_cents,
			period     = EXCLUDED.period,
			updated_at = now()
	`, tenantID, b.ScopeType, b.ScopeKey, b.CapCents, b.Period)
	return err
}

func (s *Store) ListSpendBudgets(ctx context.Context, tenantID string) ([]SpendBudget, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT scope_type, scope_key, cap_cents, period, updated_at 
		FROM spend_budgets 
		WHERE tenant_id = $1 
		ORDER BY scope_type, scope_key
	`, tenantID)
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

func (s *Store) UpsertSpendSnapshot(ctx context.Context, tenantID string, snap *SpendSnapshot) error {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO spend_snapshots (tenant_id, agent_id, period_start, spent_cents, cap_cents, is_estimated, pricing_table_version, synced_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now())
		ON CONFLICT (agent_id, period_start) DO UPDATE SET
			tenant_id   = EXCLUDED.tenant_id,
			spent_cents = EXCLUDED.spent_cents,
			cap_cents   = EXCLUDED.cap_cents,
			synced_at   = now()
	`, tenantID, snap.AgentID, snap.PeriodStart, snap.SpentCents, snap.CapCents, snap.IsEstimated, snap.PricingTableVersion)
	return err
}

func (s *Store) ListSpendSnapshots(ctx context.Context, tenantID string) ([]SpendSnapshot, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT agent_id, period_start, spent_cents, cap_cents, is_estimated, pricing_table_version, synced_at 
		FROM spend_snapshots 
		WHERE tenant_id = $1 
		ORDER BY period_start DESC, agent_id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []SpendSnapshot
	for rows.Next() {
		var b SpendSnapshot
		if err := rows.Scan(&b.AgentID, &b.PeriodStart, &b.SpentCents, &b.CapCents, &b.IsEstimated, &b.PricingTableVersion, &b.SyncedAt); err != nil {
			return nil, err
		}
		res = append(res, b)
	}
	return res, rows.Err()
}

func (s *Store) InsertIncreaseRequest(ctx context.Context, tenantID string, r *IncreaseRequest) error {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO spend_increase_requests (tenant_id, agent_id, current_cap, reason, status, submitted_at)
		VALUES ($1, $2, $3, $4, $5, now())
	`, tenantID, r.AgentID, r.CurrentCap, r.Reason, r.Status)
	return err
}

func (s *Store) ResolveIncreaseRequest(ctx context.Context, tenantID, id string, status string, resolvedBy string, newCap *int64) error {
	if tenantID != "" {
		_, err := s.pool.Exec(ctx, `
			UPDATE spend_increase_requests 
			SET status = $2, resolved_at = now(), resolved_by = $3, new_cap = $4
			WHERE request_id = $1 AND tenant_id = $5
		`, id, status, resolvedBy, newCap, tenantID)
		return err
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE spend_increase_requests 
		SET status = $2, resolved_at = now(), resolved_by = $3, new_cap = $4
		WHERE request_id = $1
	`, id, status, resolvedBy, newCap)
	return err
}

func (s *Store) ListIncreaseRequests(ctx context.Context, tenantID string) ([]IncreaseRequest, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT request_id, agent_id, current_cap, reason, status, submitted_at, resolved_at, resolved_by, new_cap 
		FROM spend_increase_requests 
		WHERE tenant_id = $1 
		ORDER BY submitted_at DESC
	`, tenantID)
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
