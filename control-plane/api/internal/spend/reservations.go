package spend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

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

// ── 2. SETTLE ────────────────────────────────────────────────────────────────

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
	status := req.Status
	if status == 0 {
		status = 200
	}
	_, err = tx.Exec(ctx, `
		UPDATE spend_reservations
		SET state = 'SETTLED',
		    settled_microcents = $1,
		    input_tokens = $2,
		    output_tokens = $3,
		    cached_tokens = $4,
		    status_code = $5,
		    settled_at = now()
		WHERE reservation_id = $6 AND organization_id = $7
	`, actualCost, req.InputTokens, req.OutputTokens, req.CachedInputTokens, status, reservationID, orgID)
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

	statusCode := req.StatusCode
	if statusCode == 0 {
		switch reason {
		case "provider_credential_unavailable":
			statusCode = http.StatusServiceUnavailable
		case "upstream_provider_error", "streaming_interrupted":
			statusCode = http.StatusBadGateway
		case ErrCodeReservationExpired, "timeout":
			statusCode = http.StatusRequestTimeout
		case "spend_budget_exhausted":
			statusCode = http.StatusTooManyRequests
		case "client_cancelled":
			statusCode = 499
		default:
			statusCode = http.StatusBadRequest
		}
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

	// Update reservation to RELEASED with effective status_code
	_, err = tx.Exec(ctx, `
		UPDATE spend_reservations
		SET state = 'RELEASED',
		    status_code = $1,
		    released_at = now(),
		    release_reason = $2
		WHERE reservation_id = $3 AND organization_id = $4
	`, statusCode, reason, reservationID, orgID)
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
			StatusCode:     http.StatusRequestTimeout,
		}
		if _, err := s.Release(ctx, it.orgID, it.resID, req); err == nil {
			count++
		}
	}
	return count, nil
}
