package spend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func isSerializationError(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "40001" || pgErr.Code == "40P01"
	}
	return false
}

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// EnsureSchema creates spend v2 tables and seeds default price book if they do not exist
func (s *Store) EnsureSchema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	schemaSQL := `
		CREATE TABLE IF NOT EXISTS spend_policies (
			policy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL,
			scope_type VARCHAR(32) NOT NULL DEFAULT 'organization',
			scope_id VARCHAR(128) NOT NULL DEFAULT 'global',
			currency VARCHAR(8) NOT NULL DEFAULT 'USD',
			period_type VARCHAR(16) NOT NULL DEFAULT 'monthly',
			limit_microcents BIGINT NOT NULL,
			action VARCHAR(32) NOT NULL DEFAULT 'hard_deny',
			effective_from TIMESTAMPTZ NOT NULL DEFAULT now(),
			effective_to TIMESTAMPTZ,
			status VARCHAR(16) NOT NULL DEFAULT 'DRAFT',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT uq_spend_policy_scope UNIQUE (organization_id, scope_type, scope_id, period_type)
		);

		CREATE TABLE IF NOT EXISTS spend_policy_versions (
			policy_version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			policy_id UUID NOT NULL REFERENCES spend_policies(policy_id) ON DELETE CASCADE,
			version INT NOT NULL,
			snapshot_json JSONB NOT NULL,
			published_by VARCHAR(128) NOT NULL DEFAULT 'system',
			published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT uq_spend_policy_version UNIQUE (policy_id, version)
		);

		CREATE TABLE IF NOT EXISTS budget_windows (
			window_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL,
			policy_version_id UUID NOT NULL REFERENCES spend_policy_versions(policy_version_id) ON DELETE CASCADE,
			scope_type VARCHAR(32) NOT NULL,
			scope_id VARCHAR(128) NOT NULL,
			window_start TIMESTAMPTZ NOT NULL,
			window_end TIMESTAMPTZ NOT NULL,
			limit_microcents BIGINT NOT NULL,
			reserved_microcents BIGINT NOT NULL DEFAULT 0,
			settled_microcents BIGINT NOT NULL DEFAULT 0,
			version BIGINT NOT NULL DEFAULT 1,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT uq_budget_window UNIQUE (organization_id, policy_version_id, window_start),
			CONSTRAINT chk_window_bounds CHECK (window_end > window_start)
		);

		CREATE TABLE IF NOT EXISTS price_book_versions (
			price_book_version_id TEXT PRIMARY KEY,
			organization_id UUID NULL,
			source TEXT NOT NULL,
			published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			published_by TEXT NOT NULL,
			hash TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS price_book_items (
			item_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			price_book_version_id TEXT NOT NULL REFERENCES price_book_versions(price_book_version_id) ON DELETE CASCADE,
			provider TEXT NOT NULL,
			model_selector TEXT NOT NULL,
			input_rate_microcents_per_million BIGINT NOT NULL CHECK (input_rate_microcents_per_million >= 0),
			output_rate_microcents_per_million BIGINT NOT NULL CHECK (output_rate_microcents_per_million >= 0),
			cached_input_rate_microcents_per_million BIGINT NOT NULL DEFAULT 0 CHECK (cached_input_rate_microcents_per_million >= 0),
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT uq_price_book_item UNIQUE (price_book_version_id, provider, model_selector)
		);

		CREATE TABLE IF NOT EXISTS spend_reservations (
			reservation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL,
			request_id VARCHAR(128) NOT NULL,
			gateway_id VARCHAR(128) NOT NULL,
			project_id VARCHAR(128) NOT NULL DEFAULT 'default',
			state VARCHAR(32) NOT NULL DEFAULT 'AUTHORIZED',
			reserved_microcents BIGINT NOT NULL,
			settled_microcents BIGINT NOT NULL DEFAULT 0,
			currency VARCHAR(8) NOT NULL DEFAULT 'USD',
			expires_at TIMESTAMPTZ NOT NULL,
			policy_snapshot JSONB NOT NULL,
			price_book_version_id VARCHAR(64) NOT NULL,
			provider VARCHAR(64) NOT NULL,
			model VARCHAR(128) NOT NULL,
			input_tokens_estimated BIGINT NOT NULL DEFAULT 0,
			max_output_tokens BIGINT NOT NULL DEFAULT 0,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			settled_at TIMESTAMPTZ,
			released_at TIMESTAMPTZ,
			release_reason VARCHAR(64),
			CONSTRAINT uq_spend_reservation_req UNIQUE (organization_id, request_id)
		);

		CREATE TABLE IF NOT EXISTS spend_events (
			event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL,
			reservation_id UUID REFERENCES spend_reservations(reservation_id) ON DELETE SET NULL,
			request_id VARCHAR(128) NOT NULL,
			event_type VARCHAR(32) NOT NULL,
			amount_microcents BIGINT NOT NULL,
			currency VARCHAR(8) NOT NULL DEFAULT 'USD',
			usage_json JSONB NOT NULL DEFAULT '{}'::jsonb,
			provider_request_id VARCHAR(128),
			actor VARCHAR(128) NOT NULL,
			reason_code VARCHAR(64) NOT NULL,
			occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);

		CREATE TABLE IF NOT EXISTS spend_idempotency (
			organization_id UUID NOT NULL,
			operation VARCHAR(32) NOT NULL,
			idempotency_key VARCHAR(128) NOT NULL,
			payload_hash VARCHAR(64) NOT NULL,
			response_json JSONB NOT NULL,
			response_status INT NOT NULL DEFAULT 200,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			expires_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (organization_id, operation, idempotency_key)
		);

		CREATE TABLE IF NOT EXISTS spend_v2_increase_requests (
			request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL,
			project_id VARCHAR(128) NOT NULL DEFAULT 'default',
			requested_limit_microcents BIGINT NOT NULL,
			current_limit_microcents BIGINT NOT NULL DEFAULT 0,
			reason TEXT NOT NULL,
			status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
			created_by VARCHAR(128) NOT NULL,
			decided_by VARCHAR(128),
			decision_reason TEXT,
			resulting_policy_version_id UUID REFERENCES spend_policy_versions(policy_version_id) ON DELETE SET NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			decided_at TIMESTAMPTZ
		);

		INSERT INTO price_book_versions (price_book_version_id, source, published_by, hash)
		VALUES ('price-book-v1', 'default_seed', 'system', 'sha256:price-book-v1-seed')
		ON CONFLICT (price_book_version_id) DO NOTHING;

		INSERT INTO price_book_items (price_book_version_id, provider, model_selector, input_rate_microcents_per_million, output_rate_microcents_per_million, cached_input_rate_microcents_per_million)
		VALUES 
			('price-book-v1', 'openai', 'gpt-4o', 250000000, 1000000000, 125000000),
			('price-book-v1', 'openai', 'gpt-4o-mini', 15000000, 60000000, 7500000),
			('price-book-v1', 'openai', 'gpt-4-turbo', 1000000000, 3000000000, 500000000),
			('price-book-v1', 'anthropic', 'claude-3-5-sonnet-20241022', 300000000, 1500000000, 30000000),
			('price-book-v1', 'anthropic', 'claude-3-haiku-20240307', 25000000, 125000000, 2500000),
			('price-book-v1', 'groq', 'llama-3.3-70b-versatile', 59000000, 79000000, 0)
		ON CONFLICT (price_book_version_id, provider, model_selector) DO NOTHING;

		INSERT INTO spend_policies (
			policy_id, organization_id, scope_type, scope_id, currency, period_type,
			limit_microcents, action, effective_from, status
		) VALUES (
			'00000000-0000-0000-0000-000000000010', '00000000-0000-0000-0000-000000000001',
			'organization', '00000000-0000-0000-0000-000000000001', 'USD', 'monthly',
			10000000000, 'hard_deny', now(), 'PUBLISHED'
		) ON CONFLICT (organization_id, scope_type, scope_id, period_type) DO NOTHING;

		INSERT INTO spend_policy_versions (
			policy_version_id, policy_id, version, snapshot_json, published_by, published_at
		) VALUES (
			'00000000-0000-0000-0000-000000000020', '00000000-0000-0000-0000-000000000010',
			1, '{"scope_type":"organization","limit_microcents":10000000000,"period_type":"monthly"}'::jsonb,
			'system', now()
		) ON CONFLICT (policy_id, version) DO NOTHING;

		CREATE INDEX IF NOT EXISTS idx_spend_res_org_created 
			ON spend_reservations(organization_id, created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_spend_res_org_device 
			ON spend_reservations(organization_id, gateway_id, created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_spend_res_org_provider 
			ON spend_reservations(organization_id, provider, created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_spend_res_org_state 
			ON spend_reservations(organization_id, state, created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_spend_events_reservation 
			ON spend_events(reservation_id, occurred_at);
	`
	_, err := s.pool.Exec(ctx, schemaSQL)
	if err != nil {
		return err
	}

	return nil
}

// ComputePayloadHash returns sha256 hex string of any payload for idempotency checking
func ComputePayloadHash(payload interface{}) string {
	b, _ := json.Marshal(payload)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// GetWindowBoundsUTC calculates window start and end in UTC for daily or monthly periods
func GetWindowBoundsUTC(periodType string, t time.Time) (time.Time, time.Time) {
	utc := t.UTC()
	if periodType == PeriodMonthly {
		start := time.Date(utc.Year(), utc.Month(), 1, 0, 0, 0, 0, time.UTC)
		end := start.AddDate(0, 1, 0).Add(-time.Nanosecond)
		return start, end
	}
	// Default Daily
	start := time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 0, 1).Add(-time.Nanosecond)
	return start, end
}

// ── 1. AUTHORIZE ─────────────────────────────────────────────────────────────

func (s *Store) Authorize(ctx context.Context, orgID string, req *AuthorizeRequest) (*AuthorizeResponse, error) {
	const maxRetries = 5
	var backoff = 10 * time.Millisecond
	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err := s.authorizeTx(ctx, orgID, req)
		if err != nil && isSerializationError(err) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
				continue
			}
		}
		return resp, err
	}
	return nil, errors.New("spend authorization failed: maximum serialization retries exceeded")
}

func (s *Store) authorizeTx(ctx context.Context, orgID string, req *AuthorizeRequest) (*AuthorizeResponse, error) {
	if s.pool == nil {
		return nil, errors.New("database pool uninitialized")
	}
	if orgID == "" {
		return nil, errors.New("organization_id is required")
	}
	if req.ProjectID == "" {
		req.ProjectID = "default"
	}
	if req.Provider == "" {
		req.Provider = "openai"
	}

	payloadHash := req.RequestHash
	if payloadHash == "" {
		payloadHash = ComputePayloadHash(req)
	}

	// 1. Check idempotency record
	var cachedRespJSON []byte
	var cachedStatus int
	err := s.pool.QueryRow(ctx, `
		SELECT response_json, response_status FROM spend_idempotency
		WHERE organization_id = $1 AND operation = 'authorize' AND idempotency_key = $2
	`, orgID, req.IdempotencyKey).Scan(&cachedRespJSON, &cachedStatus)
	if err == nil {
		var resp AuthorizeResponse
		if err := json.Unmarshal(cachedRespJSON, &resp); err == nil {
			return &resp, nil
		}
	}

	// 2. Resolve Active Price Book item
	activePriceBookID := s.GetActivePriceBookVersionID(ctx)
	priceItem, err := s.GetPriceBookItem(ctx, activePriceBookID, req.Provider, req.Model)
	if err != nil || priceItem == nil {
		denyResp := &AuthorizeResponse{
			Decision:            "deny",
			ReasonCode:          ErrCodePriceUnknown,
			CorrelationID:       req.RequestID,
			DisclosureSafeScope: "price_book",
			PriceBookVersion:    activePriceBookID,
		}
		return denyResp, nil
	}

	// 3. Compute Bounded Reserve
	reserveMicrocents, err := priceItem.CalculateReserve(req.InputTokenEstimate, req.MaxOutputTokens)
	if err != nil {
		denyResp := &AuthorizeResponse{
			Decision:            "deny",
			ReasonCode:          ErrCodeOutputBoundMissing,
			CorrelationID:       req.RequestID,
			DisclosureSafeScope: "request_bounds",
		}
		return denyResp, nil
	}

	// 4. Begin Serializable / Row-Locked Transaction
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	now := time.Now().UTC()

	// 5. Query effective published policies (Org level, Project level, and Provider level)
	rows, err := tx.Query(ctx, `
		SELECT p.policy_id, p.scope_type, p.scope_id, p.period_type, p.limit_microcents, p.action,
		       pv.policy_version_id, pv.version
		FROM spend_policies p
		JOIN spend_policy_versions pv ON p.policy_id = pv.policy_id
		WHERE p.organization_id = $1 
		  AND p.status = 'PUBLISHED'
		  AND (
		    p.scope_type = 'organization' 
		    OR (p.scope_type = 'project' AND p.scope_id = $2)
		    OR (p.scope_type = 'provider' AND LOWER(p.scope_id) = LOWER($3))
		  )
		  AND (p.effective_to IS NULL OR p.effective_to > $4)
		ORDER BY pv.policy_version_id ASC
	`, orgID, req.ProjectID, req.Provider, now)
	if err != nil {
		return nil, fmt.Errorf("failed to query policies: %w", err)
	}

	type activePolicy struct {
		PolicyID        string
		ScopeType       string
		ScopeID         string
		PeriodType      string
		LimitMicrocents MoneyMicrocents
		Action          string
		PolicyVersionID string
		Version         int
	}

	var activePolicies []activePolicy
	for rows.Next() {
		var ap activePolicy
		if err := rows.Scan(&ap.PolicyID, &ap.ScopeType, &ap.ScopeID, &ap.PeriodType, &ap.LimitMicrocents, &ap.Action, &ap.PolicyVersionID, &ap.Version); err != nil {
			rows.Close()
			return nil, err
		}
		activePolicies = append(activePolicies, ap)
	}
	rows.Close()

	if len(activePolicies) == 0 {
		var defPolID, defPolVerID string
		err := tx.QueryRow(ctx, `
			INSERT INTO spend_policies (organization_id, scope_type, scope_id, currency, period_type, limit_microcents, action, status)
			VALUES ($1, 'organization', $1, 'USD', 'monthly', 10000000000, 'hard_deny', 'PUBLISHED')
			ON CONFLICT (organization_id, scope_type, scope_id, period_type)
			DO UPDATE SET status = 'PUBLISHED'
			RETURNING policy_id
		`, orgID).Scan(&defPolID)
		if err == nil {
			_ = tx.QueryRow(ctx, `
				INSERT INTO spend_policy_versions (policy_id, version, snapshot_json, published_by)
				VALUES ($1, 1, '{"scope_type":"organization","limit_microcents":10000000000,"period_type":"monthly"}'::jsonb, 'system')
				ON CONFLICT (policy_id, version) DO UPDATE SET published_at = now()
				RETURNING policy_version_id
			`, defPolID).Scan(&defPolVerID)

			if defPolVerID != "" {
				activePolicies = append(activePolicies, activePolicy{
					PolicyID:        defPolID,
					ScopeType:       "organization",
					ScopeID:         orgID,
					PeriodType:      PeriodMonthly,
					LimitMicrocents: 10_000_000_000,
					Action:          ActionHardDeny,
					PolicyVersionID: defPolVerID,
					Version:         1,
				})
			}
		}
	}

	var policyVersionsPinned []string
	var windowsToUpdate []string

	for _, pol := range activePolicies {
		policyVersionsPinned = append(policyVersionsPinned, pol.PolicyVersionID)
		wStart, wEnd := GetWindowBoundsUTC(pol.PeriodType, now)

		// Upsert budget window deterministically
		var windowID string
		var limitMicrocents, reservedMicrocents, settledMicrocents MoneyMicrocents
		var winVersion int64

		err = tx.QueryRow(ctx, `
			INSERT INTO budget_windows (
				organization_id, policy_version_id, scope_type, scope_id,
				window_start, window_end, limit_microcents, reserved_microcents, settled_microcents, version
			) VALUES ($1, $2, $3, $4, $5, $6, $7, 0, 0, 1)
			ON CONFLICT (organization_id, policy_version_id, window_start) 
			DO UPDATE SET limit_microcents = EXCLUDED.limit_microcents, updated_at = now()
			RETURNING window_id, limit_microcents, reserved_microcents, settled_microcents, version
		`, orgID, pol.PolicyVersionID, pol.ScopeType, pol.ScopeID, wStart, wEnd, pol.LimitMicrocents).
			Scan(&windowID, &limitMicrocents, &reservedMicrocents, &settledMicrocents, &winVersion)
		if err != nil {
			return nil, fmt.Errorf("failed to upsert budget window: %w", err)
		}

		// Row-lock the window for serializable check
		err = tx.QueryRow(ctx, `
			SELECT limit_microcents, reserved_microcents, settled_microcents
			FROM budget_windows
			WHERE window_id = $1
			FOR UPDATE
		`, windowID).Scan(&limitMicrocents, &reservedMicrocents, &settledMicrocents)
		if err != nil {
			return nil, fmt.Errorf("failed to lock budget window: %w", err)
		}

		// Enforce Hard Deny Budget Invariant: reserved + settled + reserve <= limit
		if pol.Action == ActionHardDeny {
			if reservedMicrocents+settledMicrocents+reserveMicrocents > limitMicrocents {
				denyResp := &AuthorizeResponse{
					Decision:            "deny",
					ReasonCode:          ErrCodeSpendBudgetExhausted,
					DisclosureSafeScope: pol.ScopeType,
					ResetAt:             &wEnd,
					CorrelationID:       req.RequestID,
				}
				// Save denial idempotency record
				respBytes, _ := json.Marshal(denyResp)
				_, _ = tx.Exec(ctx, `
					INSERT INTO spend_idempotency (organization_id, operation, idempotency_key, payload_hash, response_json, response_status, expires_at)
					VALUES ($1, 'authorize', $2, $3, $4, 200, $5)
					ON CONFLICT (organization_id, operation, idempotency_key) DO NOTHING
				`, orgID, req.IdempotencyKey, payloadHash, respBytes, now.Add(24*time.Hour))
				_ = tx.Commit(ctx)
				return denyResp, nil
			}
		}

		windowsToUpdate = append(windowsToUpdate, windowID)
	}

	// 6. Apply Reservation on all applicable budget windows
	for _, winID := range windowsToUpdate {
		_, err = tx.Exec(ctx, `
			UPDATE budget_windows
			SET reserved_microcents = reserved_microcents + $1,
			    version = version + 1,
			    updated_at = now()
			WHERE window_id = $2
		`, reserveMicrocents, winID)
		if err != nil {
			return nil, fmt.Errorf("failed to update budget window reserve: %w", err)
		}
	}

	// 7. Insert Spend Reservation
	var reservationID string
	expiresAt := now.Add(5 * time.Minute)
	policySnapshotBytes, _ := json.Marshal(activePolicies)

	err = tx.QueryRow(ctx, `
		INSERT INTO spend_reservations (
			organization_id, request_id, gateway_id, project_id, state,
			reserved_microcents, settled_microcents, currency, expires_at,
			policy_snapshot, price_book_version_id, provider, model,
			input_tokens_estimated, max_output_tokens, created_at
		) VALUES ($1, $2, $3, $4, 'AUTHORIZED', $5, 0, 'USD', $6, $7, $8, $9, $10, $11, $12, now())
		RETURNING reservation_id
	`, orgID, req.RequestID, req.GatewayID, req.ProjectID, reserveMicrocents, expiresAt,
		policySnapshotBytes, activePriceBookID, req.Provider, req.Model, req.InputTokenEstimate, req.MaxOutputTokens).
		Scan(&reservationID)
	if err != nil {
		return nil, fmt.Errorf("failed to insert spend reservation: %w", err)
	}

	// 8. Append Immutable Spend Event
	_, err = tx.Exec(ctx, `
		INSERT INTO spend_events (
			organization_id, reservation_id, request_id, event_type,
			amount_microcents, currency, usage_json, actor, reason_code, occurred_at
		) VALUES ($1, $2, $3, 'AUTHORIZED', $4, 'USD', '{}'::jsonb, $5, 'authorized', now())
	`, orgID, reservationID, req.RequestID, reserveMicrocents, req.GatewayID)
	if err != nil {
		return nil, fmt.Errorf("failed to append spend event: %w", err)
	}

	allowResp := &AuthorizeResponse{
		Decision:             "allow",
		ReasonCode:           "authorized",
		ReservationID:        reservationID,
		ReservationExpiresAt: &expiresAt,
		ReservedMicrocents:   reserveMicrocents,
		Currency:             CurrencyUSD,
		PolicyVersions:       policyVersionsPinned,
		PriceBookVersion:     activePriceBookID,
		CorrelationID:        req.RequestID,
	}

	respBytes, _ := json.Marshal(allowResp)
	_, err = tx.Exec(ctx, `
		INSERT INTO spend_idempotency (organization_id, operation, idempotency_key, payload_hash, response_json, response_status, expires_at)
		VALUES ($1, 'authorize', $2, $3, $4, 200, $5)
		ON CONFLICT (organization_id, operation, idempotency_key) DO NOTHING
	`, orgID, req.IdempotencyKey, payloadHash, respBytes, now.Add(24*time.Hour))
	if err != nil {
		return nil, fmt.Errorf("failed to insert idempotency record: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit authorization tx: %w", err)
	}

	return allowResp, nil
}

func (s *Store) Settle(ctx context.Context, orgID, reservationID string, req *SettleRequest) (*SettleResponse, error) {
	const maxRetries = 5
	var backoff = 10 * time.Millisecond
	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err := s.settleTx(ctx, orgID, reservationID, req)
		if err != nil && isSerializationError(err) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
				continue
			}
		}
		return resp, err
	}
	return nil, errors.New("spend settlement failed: maximum serialization retries exceeded")
}

func (s *Store) settleTx(ctx context.Context, orgID, reservationID string, req *SettleRequest) (*SettleResponse, error) {
	if s.pool == nil {
		return nil, errors.New("database pool uninitialized")
	}
	if orgID == "" || reservationID == "" {
		return nil, errors.New("organization_id and reservation_id are required")
	}

	payloadHash := req.RequestHash
	if payloadHash == "" {
		payloadHash = ComputePayloadHash(req)
	}

	// 1. Check idempotency
	var cachedRespJSON []byte
	err := s.pool.QueryRow(ctx, `
		SELECT response_json FROM spend_idempotency
		WHERE organization_id = $1 AND operation = 'settle' AND idempotency_key = $2
	`, orgID, req.IdempotencyKey).Scan(&cachedRespJSON)
	if err == nil {
		var resp SettleResponse
		if err := json.Unmarshal(cachedRespJSON, &resp); err == nil {
			return &resp, nil
		}
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, fmt.Errorf("failed to begin settle tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// 2. Lock and retrieve reservation
	var res SpendReservation
	var policySnapshotBytes []byte
	err = tx.QueryRow(ctx, `
		SELECT reservation_id, organization_id, request_id, gateway_id, project_id, state,
		       reserved_microcents, settled_microcents, price_book_version_id, provider, model, policy_snapshot
		FROM spend_reservations
		WHERE reservation_id = $1 AND organization_id = $2
		FOR UPDATE
	`, reservationID, orgID).Scan(
		&res.ReservationID, &res.OrganizationID, &res.RequestID, &res.GatewayID, &res.ProjectID,
		&res.State, &res.ReservedMicrocents, &res.SettledMicrocents, &res.PriceBookVersionID,
		&res.Provider, &res.Model, &policySnapshotBytes,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New(ErrCodeReservationNotFound)
		}
		return nil, err
	}

	if res.State == StateSettled {
		// Already settled, return idempotent state
		resp := &SettleResponse{
			Status:             "settled",
			ReservationID:      res.ReservationID,
			SettledMicrocents:  res.SettledMicrocents,
			ReleasedMicrocents: res.ReservedMicrocents - res.SettledMicrocents,
			Currency:           CurrencyUSD,
		}
		return resp, nil
	}

	if res.State == StateReleased || res.State == StateExpired || res.State == StateReversed {
		return nil, fmt.Errorf("%s: reservation is in terminal state %s", ErrCodeReservationTerminal, res.State)
	}

	// 3. Compute Actual Cost
	priceItem, err := s.GetPriceBookItem(ctx, res.PriceBookVersionID, res.Provider, res.Model)
	if err != nil || priceItem == nil {
		return nil, fmt.Errorf("%s: pricing unavailable for settled model %s", ErrCodePriceUnknown, res.Model)
	}

	actualCost, err := priceItem.CalculateSettlement(req.InputTokens, req.OutputTokens, req.CachedInputTokens)
	if err != nil {
		return nil, fmt.Errorf("settlement calculation failed: %w", err)
	}

	// 4. Update associated budget windows: decrement reserve, increment settled
	type activePolicy struct {
		PolicyVersionID string
		PeriodType      string
	}
	var policies []activePolicy
	_ = json.Unmarshal(policySnapshotBytes, &policies)

	now := time.Now().UTC()
	for _, pol := range policies {
		wStart, _ := GetWindowBoundsUTC(pol.PeriodType, now)
		_, err = tx.Exec(ctx, `
			UPDATE budget_windows
			SET reserved_microcents = GREATEST(0, reserved_microcents - $1),
			    settled_microcents = settled_microcents + $2,
			    version = version + 1,
			    updated_at = now()
			WHERE organization_id = $3 AND policy_version_id = $4 AND window_start = $5
		`, res.ReservedMicrocents, actualCost, orgID, pol.PolicyVersionID, wStart)
		if err != nil {
			return nil, fmt.Errorf("failed to update budget window settlement: %w", err)
		}
	}

	// 5. Update Reservation
	_, err = tx.Exec(ctx, `
		UPDATE spend_reservations
		SET state = 'SETTLED',
		    settled_microcents = $1,
		    settled_at = now()
		WHERE reservation_id = $2 AND organization_id = $3
	`, actualCost, reservationID, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to update reservation: %w", err)
	}

	// 6. Write Append-Only Event
	usageSource := req.UsageSource
	if usageSource == "" {
		if req.IsEstimated {
			usageSource = UsageSourceCharacterEstimate
		} else {
			usageSource = UsageSourceProviderReported
		}
	}
	usageMap := map[string]interface{}{
		"input_tokens":        req.InputTokens,
		"output_tokens":       req.OutputTokens,
		"cached_input_tokens": req.CachedInputTokens,
		"is_estimated":        req.IsEstimated,
		"usage_source":        usageSource,
		"provider_status":     req.Status,
	}
	usageBytes, _ := json.Marshal(usageMap)

	var provReqID *string
	if req.ProviderRequestID != "" {
		provReqID = &req.ProviderRequestID
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO spend_events (
			organization_id, reservation_id, request_id, event_type,
			amount_microcents, currency, usage_json, provider_request_id,
			actor, reason_code, occurred_at
		) VALUES ($1, $2, $3, 'SETTLED', $4, 'USD', $5, $6, $7, 'settled', now())
	`, orgID, reservationID, res.RequestID, actualCost, usageBytes, provReqID, res.GatewayID)
	if err != nil {
		return nil, fmt.Errorf("failed to append settlement event: %w", err)
	}

	releasedMicrocents := res.ReservedMicrocents - actualCost
	if releasedMicrocents < 0 {
		releasedMicrocents = 0
	}

	resp := &SettleResponse{
		Status:             "settled",
		ReservationID:      reservationID,
		SettledMicrocents:  actualCost,
		ReleasedMicrocents: releasedMicrocents,
		Currency:           CurrencyUSD,
	}

	respBytes, _ := json.Marshal(resp)
	_, _ = tx.Exec(ctx, `
		INSERT INTO spend_idempotency (organization_id, operation, idempotency_key, payload_hash, response_json, response_status, expires_at)
		VALUES ($1, 'settle', $2, $3, $4, 200, $5)
		ON CONFLICT (organization_id, operation, idempotency_key) DO NOTHING
	`, orgID, req.IdempotencyKey, payloadHash, respBytes, now.Add(24*time.Hour))

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit settlement tx: %w", err)
	}

	return resp, nil
}

// ── 3. RELEASE ───────────────────────────────────────────────────────────────

func (s *Store) Release(ctx context.Context, orgID, reservationID string, req *ReleaseRequest) (*ReleaseResponse, error) {
	const maxRetries = 5
	var backoff = 10 * time.Millisecond
	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err := s.releaseTx(ctx, orgID, reservationID, req)
		if err != nil && isSerializationError(err) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
				continue
			}
		}
		return resp, err
	}
	return nil, errors.New("spend release failed: maximum serialization retries exceeded")
}

func (s *Store) releaseTx(ctx context.Context, orgID, reservationID string, req *ReleaseRequest) (*ReleaseResponse, error) {
	if s.pool == nil {
		return nil, errors.New("database pool uninitialized")
	}
	if orgID == "" || reservationID == "" {
		return nil, errors.New("organization_id and reservation_id are required")
	}

	reason := req.Reason
	if reason == "" {
		reason = "client_cancelled"
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, fmt.Errorf("failed to begin release tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var res SpendReservation
	var policySnapshotBytes []byte
	err = tx.QueryRow(ctx, `
		SELECT reservation_id, organization_id, request_id, gateway_id, state,
		       reserved_microcents, policy_snapshot
		FROM spend_reservations
		WHERE reservation_id = $1 AND organization_id = $2
		FOR UPDATE
	`, reservationID, orgID).Scan(
		&res.ReservationID, &res.OrganizationID, &res.RequestID, &res.GatewayID,
		&res.State, &res.ReservedMicrocents, &policySnapshotBytes,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New(ErrCodeReservationNotFound)
		}
		return nil, err
	}

	if res.State == StateReleased {
		return &ReleaseResponse{
			Status:             "released",
			ReservationID:      res.ReservationID,
			ReleasedMicrocents: res.ReservedMicrocents,
		}, nil
	}

	if res.State == StateSettled {
		return nil, fmt.Errorf("%s: cannot release an already settled reservation", ErrCodeReservationTerminal)
	}

	// Decrement reserve from budget windows
	type activePolicy struct {
		PolicyVersionID string
		PeriodType      string
	}
	var policies []activePolicy
	_ = json.Unmarshal(policySnapshotBytes, &policies)

	now := time.Now().UTC()
	for _, pol := range policies {
		wStart, _ := GetWindowBoundsUTC(pol.PeriodType, now)
		_, err = tx.Exec(ctx, `
			UPDATE budget_windows
			SET reserved_microcents = GREATEST(0, reserved_microcents - $1),
			    version = version + 1,
			    updated_at = now()
			WHERE organization_id = $2 AND policy_version_id = $3 AND window_start = $4
		`, res.ReservedMicrocents, orgID, pol.PolicyVersionID, wStart)
		if err != nil {
			return nil, fmt.Errorf("failed to adjust budget window on release: %w", err)
		}
	}

	// Update reservation to RELEASED
	_, err = tx.Exec(ctx, `
		UPDATE spend_reservations
		SET state = 'RELEASED',
		    released_at = now(),
		    release_reason = $1
		WHERE reservation_id = $2 AND organization_id = $3
	`, reason, reservationID, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to update reservation state: %w", err)
	}

	// Append Spend Event
	_, err = tx.Exec(ctx, `
		INSERT INTO spend_events (
			organization_id, reservation_id, request_id, event_type,
			amount_microcents, currency, usage_json, actor, reason_code, occurred_at
		) VALUES ($1, $2, $3, 'RELEASED', $4, 'USD', '{}'::jsonb, $5, $6, now())
	`, orgID, reservationID, res.RequestID, res.ReservedMicrocents, res.GatewayID, reason)
	if err != nil {
		return nil, fmt.Errorf("failed to write release event: %w", err)
	}

	resp := &ReleaseResponse{
		Status:             "released",
		ReservationID:      reservationID,
		ReleasedMicrocents: res.ReservedMicrocents,
	}

	respBytes, _ := json.Marshal(resp)
	_, _ = tx.Exec(ctx, `
		INSERT INTO spend_idempotency (organization_id, operation, idempotency_key, payload_hash, response_json, response_status, expires_at)
		VALUES ($1, 'release', $2, $3, $4, 200, $5)
		ON CONFLICT (organization_id, operation, idempotency_key) DO NOTHING
	`, orgID, req.IdempotencyKey, req.RequestHash, respBytes, now.Add(24*time.Hour))

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit release tx: %w", err)
	}

	return resp, nil
}

// ── 4. SWEEPER ───────────────────────────────────────────────────────────────

func (s *Store) SweepExpiredReservations(ctx context.Context) (int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT reservation_id, organization_id
		FROM spend_reservations
		WHERE state IN ('AUTHORIZED', 'ACTIVE') AND expires_at < now()
		LIMIT 100
	`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type item struct {
		resID string
		orgID string
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.resID, &it.orgID); err == nil {
			items = append(items, it)
		}
	}
	rows.Close()

	count := 0
	for _, it := range items {
		req := &ReleaseRequest{
			IdempotencyKey: fmt.Sprintf("sweep-%s-%d", it.resID, time.Now().Unix()),
			Reason:         ErrCodeReservationExpired,
		}
		if _, err := s.Release(ctx, it.orgID, it.resID, req); err == nil {
			count++
		}
	}
	return count, nil
}

// ── 5. PRICE BOOK & QUERIES ──────────────────────────────────────────────────

// GetActivePriceBookVersionID returns the most recently published active price book version ID.
func (s *Store) GetActivePriceBookVersionID(ctx context.Context) string {
	if s.pool == nil {
		return "price-book-v1"
	}
	var versionID string
	err := s.pool.QueryRow(ctx, `
		SELECT price_book_version_id FROM price_book_versions
		ORDER BY published_at DESC LIMIT 1
	`).Scan(&versionID)
	if err != nil || versionID == "" {
		return "price-book-v1"
	}
	return versionID
}

// GetPriceBookItem queries the exact or wildcard model rate in the specified price book.
// Returns pgx.ErrNoRows if no pricing rule matches. Never returns synthetic fallback rates.
func (s *Store) GetPriceBookItem(ctx context.Context, versionID, provider, model string) (*PriceBookItem, error) {
	if s.pool == nil {
		return nil, errors.New("database pool uninitialized")
	}
	var item PriceBookItem
	err := s.pool.QueryRow(ctx, `
		SELECT item_id, price_book_version_id, provider, model_selector,
		       input_rate_microcents_per_million, output_rate_microcents_per_million, cached_input_rate_microcents_per_million
		FROM price_book_items
		WHERE price_book_version_id = $1 AND LOWER(provider) = LOWER($2) AND (
			model_selector = $3 
			OR model_selector = '*' 
			OR ($3 LIKE REPLACE(model_selector, '*', '%'))
		)
		ORDER BY 
			CASE WHEN model_selector = $3 THEN 1 WHEN model_selector != '*' THEN 2 ELSE 3 END
		LIMIT 1
	`, versionID, provider, model).Scan(
		&item.ItemID, &item.PriceBookVersionID, &item.Provider, &item.ModelSelector,
		&item.InputRateMicrocentsPerMillion, &item.OutputRateMicrocentsPerMillion,
		&item.CachedInputRateMicrocentsPerMillion,
	)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

// ── 6. POLICY MANAGEMENT & EFFECTIVE BUDGETS ─────────────────────────────────

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

func (s *Store) ListEffectiveBudgetWindows(ctx context.Context, orgID string) ([]BudgetWindow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT window_id, organization_id, policy_version_id, scope_type, scope_id,
		       window_start, window_end, limit_microcents, reserved_microcents, settled_microcents, version
		FROM budget_windows
		WHERE organization_id = $1 AND window_end >= now()
		ORDER BY scope_type, scope_id, window_start DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []BudgetWindow
	for rows.Next() {
		var w BudgetWindow
		if err := rows.Scan(
			&w.WindowID, &w.OrganizationID, &w.PolicyVersionID, &w.ScopeType, &w.ScopeID,
			&w.WindowStart, &w.WindowEnd, &w.LimitMicrocents, &w.ReservedMicrocents, &w.SettledMicrocents, &w.Version,
		); err == nil {
			w.AvailableMicrocents = w.LimitMicrocents - w.ReservedMicrocents - w.SettledMicrocents
			res = append(res, w)
		}
	}
	return res, rows.Err()
}

func (s *Store) ListSpendEvents(ctx context.Context, orgID string, limit int) ([]SpendEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT event_id, organization_id, reservation_id, request_id, event_type,
		       amount_microcents, currency, usage_json, provider_request_id, actor, reason_code, occurred_at
		FROM spend_events
		WHERE organization_id = $1
		ORDER BY occurred_at DESC
		LIMIT $2
	`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []SpendEvent
	for rows.Next() {
		var e SpendEvent
		var usageRaw []byte
		if err := rows.Scan(
			&e.EventID, &e.OrganizationID, &e.ReservationID, &e.RequestID, &e.EventType,
			&e.AmountMicrocents, &e.Currency, &usageRaw, &e.ProviderRequestID, &e.Actor, &e.ReasonCode, &e.OccurredAt,
		); err == nil {
			e.UsageJSON = string(usageRaw)
			res = append(res, e)
		}
	}
	return res, rows.Err()
}

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

// ── 5. SPEND ANALYTICS & RUN EXPLORER ─────────────────────────────────────────

// GetSpendAnalytics returns server-aggregated ledger totals, hourly time-series, and top spenders.
func (s *Store) GetSpendAnalytics(ctx context.Context, orgID string, hours int, groupBy string) (*SpendAnalytics, error) {
	if s.pool == nil {
		return &SpendAnalytics{
			Summary:     SpendAnalyticsSummary{},
			TimeSeries:  []SpendTimeSeriesPoint{},
			TopEntities: []SpendTopEntity{},
		}, nil
	}

	if hours <= 0 || hours > 720 {
		hours = 24
	}
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)

	var a SpendAnalytics
	a.TimeSeries = []SpendTimeSeriesPoint{}
	a.TopEntities = []SpendTopEntity{}

	// 1. High-level Summary
	err := s.pool.QueryRow(ctx, `
		SELECT 
			COALESCE(SUM(reserved_microcents), 0),
			COALESCE(SUM(settled_microcents), 0),
			COALESCE(SUM(CASE WHEN state = 'RELEASED' THEN reserved_microcents - settled_microcents ELSE 0 END), 0),
			COUNT(*),
			COUNT(*) FILTER (WHERE state = 'DENIED')
		FROM spend_reservations
		WHERE organization_id = $1 AND created_at >= $2
	`, orgID, since).Scan(
		&a.Summary.TotalReservedMoney,
		&a.Summary.TotalSettledMoney,
		&a.Summary.TotalReleasedMoney,
		&a.Summary.RequestCount,
		&a.Summary.DeniedCount,
	)
	if err != nil {
		return nil, fmt.Errorf("spend analytics summary: %w", err)
	}

	// 2. Hourly Time Series
	tsRows, err := s.pool.Query(ctx, `
		SELECT 
			to_char(date_trunc('hour', created_at), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') as hr,
			COALESCE(SUM(reserved_microcents), 0),
			COALESCE(SUM(settled_microcents), 0),
			COALESCE(SUM(CASE WHEN state = 'RELEASED' THEN reserved_microcents - settled_microcents ELSE 0 END), 0),
			COUNT(*)
		FROM spend_reservations
		WHERE organization_id = $1 AND created_at >= $2
		GROUP BY date_trunc('hour', created_at)
		ORDER BY date_trunc('hour', created_at) ASC
	`, orgID, since)
	if err == nil {
		defer tsRows.Close()
		for tsRows.Next() {
			var pt SpendTimeSeriesPoint
			if err := tsRows.Scan(&pt.Hour, &pt.ReservedMicrocents, &pt.SettledMicrocents, &pt.ReleasedMicrocents, &pt.RequestCount); err == nil {
				a.TimeSeries = append(a.TimeSeries, pt)
			}
		}
	}

	// 3. Top Entities by Dimension
	validGroupBy := map[string]string{
		"device":   "gateway_id",
		"provider": "provider",
		"model":    "model",
		"project":  "project_id",
	}
	col, ok := validGroupBy[groupBy]
	if !ok {
		col = "provider"
	}

	query := fmt.Sprintf(`
		SELECT 
			COALESCE(%s, 'unknown'),
			COALESCE(SUM(settled_microcents), 0),
			COUNT(*)
		FROM spend_reservations
		WHERE organization_id = $1 AND created_at >= $2
		GROUP BY %s
		ORDER BY SUM(settled_microcents) DESC, COUNT(*) DESC
		LIMIT 20
	`, col, col)

	topRows, err := s.pool.Query(ctx, query, orgID, since)
	if err == nil {
		defer topRows.Close()
		for topRows.Next() {
			var ent SpendTopEntity
			if err := topRows.Scan(&ent.EntityID, &ent.SettledMicrocents, &ent.RequestCount); err == nil {
				ent.EntityName = ent.EntityID
				a.TopEntities = append(a.TopEntities, ent)
			}
		}
	}

	return &a, nil
}

// ListRuns returns filtered broker LLM runs for the Run Explorer.
func (s *Store) ListRuns(ctx context.Context, orgID string, q RunQuery) ([]RunSummary, error) {
	if s.pool == nil {
		return []RunSummary{}, nil
	}

	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 50
	}
	if q.Since.IsZero() {
		q.Since = time.Now().UTC().Add(-24 * time.Hour)
	}

	sql := `
		SELECT reservation_id::text, request_id, gateway_id, project_id, provider, model, state,
		       reserved_microcents, settled_microcents, created_at, settled_at,
		       COALESCE(EXTRACT(EPOCH FROM (COALESCE(settled_at, released_at, now()) - created_at)) * 1000, 0)::bigint
		FROM spend_reservations
		WHERE organization_id = $1 AND created_at >= $2`

	args := []interface{}{orgID, q.Since}
	argIdx := 3

	if q.DeviceID != "" {
		sql += fmt.Sprintf(" AND gateway_id = $%d", argIdx)
		args = append(args, q.DeviceID)
		argIdx++
	}
	if q.Provider != "" {
		sql += fmt.Sprintf(" AND LOWER(provider) = LOWER($%d)", argIdx)
		args = append(args, q.Provider)
		argIdx++
	}
	if q.Model != "" {
		sql += fmt.Sprintf(" AND LOWER(model) LIKE LOWER($%d)", argIdx)
		args = append(args, "%"+q.Model+"%")
		argIdx++
	}
	if q.State != "" {
		sql += fmt.Sprintf(" AND UPPER(state) = UPPER($%d)", argIdx)
		args = append(args, q.State)
		argIdx++
	}

	sql += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", argIdx)
	args = append(args, q.Limit)

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("list runs query: %w", err)
	}
	defer rows.Close()

	runs := make([]RunSummary, 0)
	for rows.Next() {
		var r RunSummary
		var settledAt *time.Time
		if err := rows.Scan(
			&r.RunID, &r.RequestID, &r.DeviceID, &r.ProjectID, &r.Provider, &r.Model, &r.State,
			&r.ReservedMicrocents, &r.SettledMicrocents, &r.StartedAt, &settledAt, &r.DurationMs,
		); err != nil {
			continue
		}
		r.SettledAt = settledAt
		runs = append(runs, r)
	}
	return runs, rows.Err()
}

// GetRunDossier retrieves complete identity, policy, economic, and immutable event details for a run.
func (s *Store) GetRunDossier(ctx context.Context, orgID, runID string) (*RunDossier, error) {
	if s.pool == nil {
		return nil, errors.New("database not available")
	}

	var d RunDossier
	var policyRaw []byte
	var settledAt, releasedAt *time.Time
	var releaseReason *string

	err := s.pool.QueryRow(ctx, `
		SELECT reservation_id::text, request_id, gateway_id, project_id, provider, model, state,
		       reserved_microcents, settled_microcents, policy_snapshot::text, price_book_version_id,
		       created_at, settled_at, released_at, release_reason,
		       COALESCE(EXTRACT(EPOCH FROM (COALESCE(settled_at, released_at, now()) - created_at)) * 1000, 0)::bigint
		FROM spend_reservations
		WHERE (reservation_id::text = $1 OR request_id = $1) AND organization_id = $2
	`, runID, orgID).Scan(
		&d.RunID, &d.RequestID, &d.DeviceID, &d.ProjectID, &d.Provider, &d.Model, &d.State,
		&d.ReservedMicrocents, &d.SettledMicrocents, &policyRaw, &d.PriceBookVersionID,
		&d.StartedAt, &settledAt, &releasedAt, &releaseReason, &d.DurationMs,
	)
	if err != nil {
		return nil, err
	}

	d.PolicySnapshot = string(policyRaw)
	d.SettledAt = settledAt
	d.ReleasedAt = releasedAt
	d.ReleaseReason = releaseReason

	if d.State == StateSettled || d.State == StateReleased {
		d.ReleasedMicrocents = d.ReservedMicrocents - d.SettledMicrocents
		if d.ReleasedMicrocents < 0 {
			d.ReleasedMicrocents = 0
		}
	}

	// Fetch Immutable Events
	d.Events = []SpendEvent{}
	evRows, err := s.pool.Query(ctx, `
		SELECT event_id::text, organization_id::text, COALESCE(reservation_id::text, ''), request_id,
		       event_type, amount_microcents, currency, usage_json::text, provider_request_id,
		       actor, reason_code, occurred_at
		FROM spend_events
		WHERE (reservation_id::text = $1 OR request_id = $1) AND organization_id = $2
		ORDER BY occurred_at ASC
	`, d.RunID, orgID)
	if err == nil {
		defer evRows.Close()
		for evRows.Next() {
			var e SpendEvent
			var resID string
			var usageStr string
			if err := evRows.Scan(
				&e.EventID, &e.OrganizationID, &resID, &e.RequestID,
				&e.EventType, &e.AmountMicrocents, &e.Currency, &usageStr, &e.ProviderRequestID,
				&e.Actor, &e.ReasonCode, &e.OccurredAt,
			); err == nil {
				e.ReservationID = resID
				e.UsageJSON = usageStr
				d.Events = append(d.Events, e)
			}
		}
	}

	return &d, nil
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
