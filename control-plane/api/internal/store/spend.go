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
	RequestID   string    `json:"request_id"`
	AgentID     string    `json:"agent_id"`
	CurrentCap  int64     `json:"current_cap"`
	Reason      *string   `json:"reason"`
	Status      string    `json:"status"`
	SubmittedAt time.Time `json:"submitted_at"`
	ResolvedAt  *time.Time `json:"resolved_at"`
	ResolvedBy  *string   `json:"resolved_by"`
	NewCap      *int64    `json:"new_cap"`
}

func (s *Store) UpsertSpendBudget(ctx context.Context, b *SpendBudget) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO spend_budgets (scope_type, scope_key, cap_cents, period, created_at, updated_at)
		VALUES ($1, $2, $3, $4, now(), now())
		ON CONFLICT (scope_type, scope_key) DO UPDATE SET
			cap_cents  = EXCLUDED.cap_cents,
			period     = EXCLUDED.period,
			updated_at = now()
	`, b.ScopeType, b.ScopeKey, b.CapCents, b.Period)
	return err
}

func (s *Store) ListSpendBudgets(ctx context.Context) ([]SpendBudget, error) {
	rows, err := s.pool.Query(ctx, "SELECT scope_type, scope_key, cap_cents, period, updated_at FROM spend_budgets ORDER BY scope_type, scope_key")
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

func (s *Store) UpsertSpendSnapshot(ctx context.Context, snap *SpendSnapshot) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO spend_snapshots (agent_id, period_start, spent_cents, cap_cents, is_estimated, pricing_table_version, synced_at)
		VALUES ($1, $2, $3, $4, $5, $6, now())
		ON CONFLICT (agent_id, period_start) DO UPDATE SET
			spent_cents = EXCLUDED.spent_cents,
			cap_cents   = EXCLUDED.cap_cents,
			synced_at   = now()
	`, snap.AgentID, snap.PeriodStart, snap.SpentCents, snap.CapCents, snap.IsEstimated, snap.PricingTableVersion)
	return err
}

func (s *Store) ListSpendSnapshots(ctx context.Context) ([]SpendSnapshot, error) {
	rows, err := s.pool.Query(ctx, "SELECT agent_id, period_start, spent_cents, cap_cents, is_estimated, pricing_table_version, synced_at FROM spend_snapshots ORDER BY period_start DESC, agent_id")
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

func (s *Store) InsertIncreaseRequest(ctx context.Context, r *IncreaseRequest) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO spend_increase_requests (agent_id, current_cap, reason, status, submitted_at)
		VALUES ($1, $2, $3, $4, now())
	`, r.AgentID, r.CurrentCap, r.Reason, r.Status)
	return err
}

func (s *Store) ResolveIncreaseRequest(ctx context.Context, id string, status string, resolvedBy string, newCap *int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE spend_increase_requests 
		SET status = $2, resolved_at = now(), resolved_by = $3, new_cap = $4
		WHERE request_id = $1
	`, id, status, resolvedBy, newCap)
	return err
}

func (s *Store) ListIncreaseRequests(ctx context.Context) ([]IncreaseRequest, error) {
	rows, err := s.pool.Query(ctx, "SELECT request_id, agent_id, current_cap, reason, status, submitted_at, resolved_at, resolved_by, new_cap FROM spend_increase_requests ORDER BY submitted_at DESC")
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
