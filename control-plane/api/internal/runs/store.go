package runs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MoneyMicrocents represents money in integer microcents.
type MoneyMicrocents int64

// RunQuery defines filtering criteria for broker LLM runs & request logs.
type RunQuery struct {
	Limit          int
	Offset         int
	Since          time.Time
	Until          time.Time
	DeviceID       string
	Provider       string
	Model          string
	State          string
	RequestID      string
	SessionID      string
	VirtualKeyHash string
	VirtualKeyID   string
	User           string
	Search         string
}

// RunSummary represents a concise view of an LLM reservation run or request log item.
type RunSummary struct {
	RunID              string          `json:"run_id"`
	RequestID          string          `json:"request_id"`
	DeviceID           string          `json:"device_id"`
	DeviceName         string          `json:"device_name,omitempty"`
	ProjectID          string          `json:"project_id"`
	Provider           string          `json:"provider"`
	Model              string          `json:"model"`
	State              string          `json:"state"`
	ReservedMicrocents MoneyMicrocents `json:"reserved_microcents"`
	SettledMicrocents  MoneyMicrocents `json:"settled_microcents"`
	StartedAt          time.Time       `json:"started_at"`
	SettledAt          *time.Time      `json:"settled_at,omitempty"`
	DurationMs         int64           `json:"duration_ms"`
	TTFTMs             int64           `json:"ttft_ms"`
	InputTokens        int64           `json:"input_tokens"`
	OutputTokens       int64           `json:"output_tokens"`
	CachedTokens       int64           `json:"cached_tokens"`
	TotalTokens        int64           `json:"total_tokens"`
	VirtualKeyID       *string         `json:"virtual_key_id,omitempty"`
	VirtualKeyHash     *string         `json:"virtual_key_hash,omitempty"`
	VirtualKeyPrefix   *string         `json:"virtual_key_prefix,omitempty"`
	VirtualKeyAlias    *string         `json:"virtual_key_alias,omitempty"`
	SessionID          *string         `json:"session_id,omitempty"`
	InternalUserID     *string         `json:"internal_user_id,omitempty"`
	EndUserID          *string         `json:"end_user_id,omitempty"`
	Tags               map[string]any  `json:"tags,omitempty"`
	RequestType        string          `json:"request_type"`
	StatusCode         int             `json:"status_code"`
}

// RunEvent represents an event associated with a run.
type RunEvent struct {
	EventID           string          `json:"event_id"`
	OrganizationID    string          `json:"organization_id"`
	ReservationID     string          `json:"reservation_id"`
	RequestID         string          `json:"request_id"`
	EventType         string          `json:"event_type"`
	AmountMicrocents  MoneyMicrocents `json:"amount_microcents"`
	Currency          string          `json:"currency"`
	UsageJSON         string          `json:"usage_json"`
	ProviderRequestID *string         `json:"provider_request_id,omitempty"`
	Actor             string          `json:"actor"`
	ReasonCode        string          `json:"reason_code"`
	OccurredAt        time.Time       `json:"occurred_at"`
}

// RunDossier contains complete forensic identity, policy, economic, and event details.
type RunDossier struct {
	RunSummary
	ReleasedMicrocents MoneyMicrocents `json:"released_microcents"`
	ReleaseReason      *string         `json:"release_reason,omitempty"`
	ReleasedAt         *time.Time      `json:"released_at,omitempty"`
	PolicySnapshot     string          `json:"policy_snapshot"`
	PriceBookVersionID string          `json:"price_book_version_id"`
	Events             []RunEvent      `json:"events"`
}

// Store handles execution run dossiers and request logging.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore initializes a new runs.Store.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// ListRuns returns filtered broker LLM runs & request logs for Observability.
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
		SELECT sr.reservation_id::text, sr.request_id, sr.gateway_id,
		       COALESCE(NULLIF(d.display_name, ''), d.stable_device_id, sr.gateway_id) AS device_name,
		       sr.project_id, sr.provider, sr.model, sr.state,
		       sr.reserved_microcents, sr.settled_microcents, sr.created_at, sr.settled_at,
		       COALESCE(EXTRACT(EPOCH FROM (COALESCE(sr.settled_at, sr.released_at, now()) - sr.created_at)) * 1000, 0)::bigint,
		       COALESCE(sr.ttft_ms, 0),
		       COALESCE(sr.input_tokens, 0),
		       COALESCE(sr.output_tokens, 0),
		       COALESCE(sr.cached_tokens, 0),
		       sr.virtual_key_id::text,
		       sr.virtual_key_hash,
		       sr.virtual_key_prefix,
		       sr.virtual_key_alias,
		       sr.session_id,
		       sr.internal_user_id,
		       sr.end_user_id,
		       COALESCE(sr.tags, '{}'::jsonb),
		       COALESCE(sr.request_type, 'LLM'),
		       COALESCE(sr.status_code, 200)
		FROM spend_reservations sr
		LEFT JOIN devices d ON (
			d.organization_id = sr.organization_id 
			AND (d.id::text = sr.gateway_id OR d.stable_device_id = sr.gateway_id OR d.display_name = sr.gateway_id)
		)
		WHERE sr.organization_id = $1 AND sr.created_at >= $2
	`
	args := []interface{}{orgID, q.Since}
	argIdx := 3

	if !q.Until.IsZero() {
		sql += fmt.Sprintf(" AND sr.created_at <= $%d", argIdx)
		args = append(args, q.Until)
		argIdx++
	}
	if q.DeviceID != "" {
		sql += fmt.Sprintf(" AND (sr.gateway_id = $%d OR d.stable_device_id = $%d OR d.display_name ILIKE $%d)", argIdx, argIdx, argIdx)
		args = append(args, q.DeviceID)
		argIdx++
	}
	if q.Provider != "" {
		sql += fmt.Sprintf(" AND LOWER(sr.provider) = LOWER($%d)", argIdx)
		args = append(args, q.Provider)
		argIdx++
	}
	if q.Model != "" {
		sql += fmt.Sprintf(" AND LOWER(sr.model) = LOWER($%d)", argIdx)
		args = append(args, q.Model)
		argIdx++
	}
	if q.State != "" {
		sql += fmt.Sprintf(" AND sr.state = $%d", argIdx)
		args = append(args, strings.ToUpper(q.State))
		argIdx++
	}
	if q.RequestID != "" {
		sql += fmt.Sprintf(" AND sr.request_id = $%d", argIdx)
		args = append(args, q.RequestID)
		argIdx++
	}
	if q.SessionID != "" {
		sql += fmt.Sprintf(" AND sr.session_id = $%d", argIdx)
		args = append(args, q.SessionID)
		argIdx++
	}
	if q.VirtualKeyID != "" {
		sql += fmt.Sprintf(" AND sr.virtual_key_id = $%d::uuid", argIdx)
		args = append(args, q.VirtualKeyID)
		argIdx++
	}
	if q.VirtualKeyHash != "" {
		sql += fmt.Sprintf(" AND sr.virtual_key_hash = $%d", argIdx)
		args = append(args, q.VirtualKeyHash)
		argIdx++
	}
	if q.User != "" {
		sql += fmt.Sprintf(" AND (sr.internal_user_id = $%d OR sr.end_user_id = $%d)", argIdx, argIdx)
		args = append(args, q.User)
		argIdx++
	}
	if q.Search != "" {
		term := "%" + q.Search + "%"
		sql += fmt.Sprintf(" AND (sr.request_id ILIKE $%d OR sr.model ILIKE $%d OR sr.session_id ILIKE $%d OR sr.virtual_key_alias ILIKE $%d OR d.display_name ILIKE $%d)", argIdx, argIdx, argIdx, argIdx, argIdx)
		args = append(args, term)
		argIdx++
	}

	sql += " ORDER BY sr.created_at DESC"
	sql += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, q.Limit, q.Offset)

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return s.listRunsLegacyFallback(ctx, orgID, q)
	}
	defer rows.Close()

	var runs []RunSummary
	for rows.Next() {
		var r RunSummary
		var tagsJSON []byte
		var settledAt *time.Time
		var vKeyID *string
		if err := rows.Scan(
			&r.RunID, &r.RequestID, &r.DeviceID, &r.DeviceName, &r.ProjectID, &r.Provider, &r.Model, &r.State,
			&r.ReservedMicrocents, &r.SettledMicrocents, &r.StartedAt, &settledAt,
			&r.DurationMs, &r.TTFTMs, &r.InputTokens, &r.OutputTokens, &r.CachedTokens,
			&vKeyID, &r.VirtualKeyHash, &r.VirtualKeyPrefix, &r.VirtualKeyAlias,
			&r.SessionID, &r.InternalUserID, &r.EndUserID, &tagsJSON, &r.RequestType, &r.StatusCode,
		); err == nil {
			r.SettledAt = settledAt
			r.VirtualKeyID = vKeyID
			r.TotalTokens = r.InputTokens + r.OutputTokens
			if len(tagsJSON) > 0 {
				_ = json.Unmarshal(tagsJSON, &r.Tags)
			}
			runs = append(runs, r)
		}
	}

	if len(runs) == 0 {
		return s.listRunsLegacyFallback(ctx, orgID, q)
	}

	return runs, nil
}

func (s *Store) listRunsLegacyFallback(ctx context.Context, orgID string, q RunQuery) ([]RunSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT event_id, event_type, gateway_id, timestamp, payload
		FROM audit_events
		WHERE tenant_id = $1 AND timestamp >= $2
		ORDER BY timestamp DESC
		LIMIT $3 OFFSET $4
	`, orgID, q.Since, q.Limit, q.Offset)
	if err != nil {
		return []RunSummary{}, nil
	}
	defer rows.Close()

	var runs []RunSummary
	for rows.Next() {
		var eventID, eventType, deviceID string
		var ts time.Time
		var payloadJSON []byte
		if err := rows.Scan(&eventID, &eventType, &deviceID, &ts, &payloadJSON); err == nil {
			var p map[string]interface{}
			_ = json.Unmarshal(payloadJSON, &p)

			runs = append(runs, RunSummary{
				RunID:       eventID,
				RequestID:   eventID,
				DeviceID:    deviceID,
				Provider:    "system",
				Model:       eventType,
				State:       "COMPLETED",
				StartedAt:   ts,
				RequestType: "EVENT",
				StatusCode:  200,
			})
		}
	}
	return runs, nil
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
	var rawStatusCode *int

	err := s.pool.QueryRow(ctx, `
		SELECT reservation_id::text, request_id, gateway_id, project_id, provider, model, state,
		       reserved_microcents, settled_microcents, policy_snapshot::text, price_book_version_id,
		       created_at, settled_at, released_at, release_reason,
		       COALESCE(EXTRACT(EPOCH FROM (COALESCE(settled_at, released_at, now()) - created_at)) * 1000, 0)::bigint,
		       COALESCE(ttft_ms, 0),
		       COALESCE(input_tokens, 0),
		       COALESCE(output_tokens, 0),
		       COALESCE(cached_tokens, 0),
		       virtual_key_id::text,
		       virtual_key_hash,
		       virtual_key_prefix,
		       virtual_key_alias,
		       session_id,
		       internal_user_id,
		       end_user_id,
		       COALESCE(tags, '{}'::jsonb),
		       COALESCE(request_type, 'LLM'),
		       status_code
		FROM spend_reservations
		WHERE (reservation_id::text = $1 OR request_id = $1) AND organization_id = $2
	`, runID, orgID).Scan(
		&d.RunID, &d.RequestID, &d.DeviceID, &d.ProjectID, &d.Provider, &d.Model, &d.State,
		&d.ReservedMicrocents, &d.SettledMicrocents, &policyRaw, &d.PriceBookVersionID,
		&d.StartedAt, &settledAt, &releasedAt, &releaseReason, &d.DurationMs,
		&d.TTFTMs, &d.InputTokens, &d.OutputTokens, &d.CachedTokens,
		&d.VirtualKeyID, &d.VirtualKeyHash, &d.VirtualKeyPrefix, &d.VirtualKeyAlias,
		&d.SessionID, &d.InternalUserID, &d.EndUserID, &d.Tags, &d.RequestType,
		&rawStatusCode,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("run dossier not found: %s", runID)
		}
		return nil, err
	}

	d.TotalTokens = d.InputTokens + d.OutputTokens
	d.PolicySnapshot = string(policyRaw)
	d.SettledAt = settledAt
	d.ReleasedAt = releasedAt
	d.ReleaseReason = releaseReason

	if rawStatusCode != nil && *rawStatusCode > 0 {
		d.StatusCode = *rawStatusCode
	} else {
		switch strings.ToUpper(d.State) {
		case "SETTLED":
			d.StatusCode = 200
		case "RELEASED":
			if releaseReason != nil && strings.Contains(strings.ToLower(*releaseReason), "provider_credential_unavailable") {
				d.StatusCode = 503
			} else if releaseReason != nil && (strings.Contains(strings.ToLower(*releaseReason), "timeout") || strings.Contains(strings.ToLower(*releaseReason), "expired")) {
				d.StatusCode = 504
			} else if releaseReason != nil && strings.Contains(strings.ToLower(*releaseReason), "exhausted") {
				d.StatusCode = 429
			} else if releaseReason != nil && strings.Contains(strings.ToLower(*releaseReason), "cancelled") {
				d.StatusCode = 499
			} else if releaseReason != nil && strings.Contains(strings.ToLower(*releaseReason), "upstream") {
				d.StatusCode = 502
			} else {
				d.StatusCode = 400
			}
		case "DENIED", "BLOCKED":
			d.StatusCode = 403
		case "FAILED", "ERROR":
			d.StatusCode = 500
		default:
			d.StatusCode = 0
		}
	}

	if strings.ToUpper(d.State) == "RELEASED" || strings.ToUpper(d.State) == "FAILED" || strings.ToUpper(d.State) == "ERROR" || strings.ToUpper(d.State) == "DENIED" {
		d.ReleasedMicrocents = d.ReservedMicrocents
		d.SettledMicrocents = 0
	} else if strings.ToUpper(d.State) == "SETTLED" {
		d.ReleasedMicrocents = d.ReservedMicrocents - d.SettledMicrocents
		if d.ReleasedMicrocents < 0 {
			d.ReleasedMicrocents = 0
		}
	}

	// Fetch all immutable spend audit trail events for this reservation
	d.Events = []RunEvent{}
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
			var e RunEvent
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
