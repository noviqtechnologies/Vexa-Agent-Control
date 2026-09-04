package spend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/runs"
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

// Pool returns the underlying pgxpool.Pool.
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
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

		CREATE TABLE IF NOT EXISTS price_book_versions (
			price_book_version_id VARCHAR(64) PRIMARY KEY,
			description TEXT NOT NULL DEFAULT '',
			published_by VARCHAR(128) NOT NULL DEFAULT 'system',
			published_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);

		CREATE TABLE IF NOT EXISTS price_book_items (
			item_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			price_book_version_id VARCHAR(64) NOT NULL REFERENCES price_book_versions(price_book_version_id) ON DELETE CASCADE,
			provider VARCHAR(64) NOT NULL,
			model_selector VARCHAR(128) NOT NULL,
			input_rate_microcents_per_million BIGINT NOT NULL,
			output_rate_microcents_per_million BIGINT NOT NULL,
			cached_input_rate_microcents_per_million BIGINT NOT NULL DEFAULT 0,
			effective_from TIMESTAMPTZ NOT NULL DEFAULT now(),
			effective_to TIMESTAMPTZ,
			CONSTRAINT uq_price_book_item UNIQUE (price_book_version_id, provider, model_selector)
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
			CONSTRAINT uq_budget_window UNIQUE (organization_id, policy_version_id, window_start)
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
			input_tokens BIGINT NOT NULL DEFAULT 0,
			output_tokens BIGINT NOT NULL DEFAULT 0,
			cached_tokens BIGINT NOT NULL DEFAULT 0,
			status_code INT NOT NULL DEFAULT 200,
			release_reason VARCHAR(128),
			released_microcents BIGINT NOT NULL DEFAULT 0,
			virtual_key_id UUID,
			virtual_key_hash VARCHAR(64),
			virtual_key_prefix VARCHAR(16),
			virtual_key_alias VARCHAR(64),
			session_id VARCHAR(128),
			internal_user_id VARCHAR(128),
			end_user_id VARCHAR(128),
			tags JSONB NOT NULL DEFAULT '{}'::jsonb,
			request_type VARCHAR(32) NOT NULL DEFAULT 'LLM',
			ttft_ms BIGINT NOT NULL DEFAULT 0,
			settled_at TIMESTAMPTZ,
			released_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT uq_reservation_req UNIQUE (organization_id, request_id)
		);

		CREATE TABLE IF NOT EXISTS spend_events (
			event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL,
			reservation_id UUID NOT NULL REFERENCES spend_reservations(reservation_id) ON DELETE CASCADE,
			request_id VARCHAR(128) NOT NULL,
			project_id VARCHAR(128) NOT NULL DEFAULT 'default',
			provider VARCHAR(64) NOT NULL DEFAULT 'openai',
			model VARCHAR(128) NOT NULL DEFAULT 'unknown',
			event_type VARCHAR(32) NOT NULL,
			amount_microcents BIGINT NOT NULL,
			currency VARCHAR(8) NOT NULL DEFAULT 'USD',
			usage_json JSONB NOT NULL DEFAULT '{}'::jsonb,
			provider_request_id VARCHAR(128),
			actor VARCHAR(128) NOT NULL DEFAULT 'gateway',
			reason_code VARCHAR(64) NOT NULL DEFAULT 'normal',
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
			current_limit_microcents BIGINT NOT NULL,
			reason TEXT NOT NULL DEFAULT '',
			status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
			created_by VARCHAR(128) NOT NULL DEFAULT 'user',
			decided_by VARCHAR(128),
			decision_reason TEXT,
			resulting_policy_version_id UUID,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			decided_at TIMESTAMPTZ
		);

		-- Seed default price book version if not exists
		INSERT INTO price_book_versions (price_book_version_id, description, published_by)
		VALUES ('price-book-v1', 'Default standard model rate card', 'system')
		ON CONFLICT (price_book_version_id) DO NOTHING;

		-- Seed default standard model rates in microcents ($0.01 = 1,000,000 microcents)
		INSERT INTO price_book_items (price_book_version_id, provider, model_selector, input_rate_microcents_per_million, output_rate_microcents_per_million, cached_input_rate_microcents_per_million)
		VALUES 
			-- OpenAI
			('price-book-v1', 'openai', 'gpt-4o', 250000000, 1000000000, 125000000),
			('price-book-v1', 'openai', 'gpt-4o-mini', 15000000, 60000000, 7500000),
			('price-book-v1', 'openai', 'o1', 1500000000, 6000000000, 750000000),
			('price-book-v1', 'openai', 'o3-mini', 110000000, 440000000, 55000000),
			('price-book-v1', 'openai', '*', 250000000, 1000000000, 125000000),
			-- Anthropic
			('price-book-v1', 'anthropic', 'claude-3-5-sonnet-20241022', 300000000, 1500000000, 30000000),
			('price-book-v1', 'anthropic', 'claude-3-5-haiku-20241022', 80000000, 400000000, 8000000),
			('price-book-v1', 'anthropic', 'claude-3-opus-20240229', 1500000000, 7500000000, 150000000),
			('price-book-v1', 'anthropic', '*', 300000000, 1500000000, 30000000),
			-- Google Gemini
			('price-book-v1', 'google', 'gemini-1.5-pro', 125000000, 500000000, 31250000),
			('price-book-v1', 'google', 'gemini-1.5-flash', 7500000, 30000000, 1875000),
			('price-book-v1', 'google', 'gemini-2.0-flash', 10000000, 40000000, 2500000),
			('price-book-v1', 'google', '*', 125000000, 500000000, 31250000),
			-- Groq
			('price-book-v1', 'groq', 'llama-3.3-70b-versatile', 59000000, 79000000, 0),
			('price-book-v1', 'groq', '*', 59000000, 79000000, 0),
			-- Azure
			('price-book-v1', 'azure', '*', 250000000, 1000000000, 125000000),
			-- Bedrock
			('price-book-v1', 'bedrock', '*', 300000000, 1500000000, 30000000)
		ON CONFLICT (price_book_version_id, provider, model_selector) DO NOTHING;

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

// ListRuns delegates to the runs package while preserving backward compatibility for spend.Store callers.
func (s *Store) ListRuns(ctx context.Context, orgID string, q RunQuery) ([]RunSummary, error) {
	rq := runs.RunQuery{
		Limit:          q.Limit,
		Offset:         q.Offset,
		Since:          q.Since,
		Until:          q.Until,
		DeviceID:       q.DeviceID,
		Provider:       q.Provider,
		Model:          q.Model,
		State:          q.State,
		RequestID:      q.RequestID,
		SessionID:      q.SessionID,
		VirtualKeyHash: q.VirtualKeyHash,
		VirtualKeyID:   q.VirtualKeyID,
		User:           q.User,
		Search:         q.Search,
	}
	runsList, err := runs.NewStore(s.pool).ListRuns(ctx, orgID, rq)
	if err != nil {
		return nil, err
	}
	res := make([]RunSummary, len(runsList))
	for i, r := range runsList {
		res[i] = RunSummary{
			RunID:              r.RunID,
			RequestID:          r.RequestID,
			DeviceID:           r.DeviceID,
			ProjectID:          r.ProjectID,
			Provider:           r.Provider,
			Model:              r.Model,
			State:              r.State,
			ReservedMicrocents: MoneyMicrocents(r.ReservedMicrocents),
			SettledMicrocents:  MoneyMicrocents(r.SettledMicrocents),
			StartedAt:          r.StartedAt,
			SettledAt:          r.SettledAt,
			DurationMs:         r.DurationMs,
			TTFTMs:             r.TTFTMs,
			InputTokens:        r.InputTokens,
			OutputTokens:       r.OutputTokens,
			CachedTokens:       r.CachedTokens,
			TotalTokens:        r.TotalTokens,
			VirtualKeyID:       r.VirtualKeyID,
			VirtualKeyHash:     r.VirtualKeyHash,
			VirtualKeyPrefix:   r.VirtualKeyPrefix,
			VirtualKeyAlias:    r.VirtualKeyAlias,
			SessionID:          r.SessionID,
			InternalUserID:     r.InternalUserID,
			EndUserID:          r.EndUserID,
			Tags:               r.Tags,
			RequestType:        r.RequestType,
			StatusCode:         r.StatusCode,
		}
	}
	return res, nil
}

// GetRunDossier delegates to the runs package while preserving backward compatibility for spend.Store callers.
func (s *Store) GetRunDossier(ctx context.Context, orgID, runID string) (*RunDossier, error) {
	d, err := runs.NewStore(s.pool).GetRunDossier(ctx, orgID, runID)
	if err != nil {
		return nil, err
	}
	events := make([]SpendEvent, len(d.Events))
	for i, ev := range d.Events {
		events[i] = SpendEvent{
			EventID:           ev.EventID,
			OrganizationID:    ev.OrganizationID,
			ReservationID:     ev.ReservationID,
			RequestID:         ev.RequestID,
			EventType:         ev.EventType,
			AmountMicrocents:  MoneyMicrocents(ev.AmountMicrocents),
			Currency:          ev.Currency,
			UsageJSON:         ev.UsageJSON,
			ProviderRequestID: ev.ProviderRequestID,
			Actor:             ev.Actor,
			ReasonCode:        ev.ReasonCode,
			OccurredAt:        ev.OccurredAt,
		}
	}
	return &RunDossier{
		RunSummary: RunSummary{
			RunID:              d.RunID,
			RequestID:          d.RequestID,
			DeviceID:           d.DeviceID,
			ProjectID:          d.ProjectID,
			Provider:           d.Provider,
			Model:              d.Model,
			State:              d.State,
			ReservedMicrocents: MoneyMicrocents(d.ReservedMicrocents),
			SettledMicrocents:  MoneyMicrocents(d.SettledMicrocents),
			StartedAt:          d.StartedAt,
			SettledAt:          d.SettledAt,
			DurationMs:         d.DurationMs,
			TTFTMs:             d.TTFTMs,
			InputTokens:        d.InputTokens,
			OutputTokens:       d.OutputTokens,
			CachedTokens:       d.CachedTokens,
			TotalTokens:        d.TotalTokens,
			VirtualKeyID:       d.VirtualKeyID,
			VirtualKeyHash:     d.VirtualKeyHash,
			VirtualKeyPrefix:   d.VirtualKeyPrefix,
			VirtualKeyAlias:    d.VirtualKeyAlias,
			SessionID:          d.SessionID,
			InternalUserID:     d.InternalUserID,
			EndUserID:          d.EndUserID,
			Tags:               d.Tags,
			RequestType:        d.RequestType,
			StatusCode:         d.StatusCode,
		},
		ReleasedMicrocents: MoneyMicrocents(d.ReleasedMicrocents),
		ReleaseReason:      d.ReleaseReason,
		ReleasedAt:         d.ReleasedAt,
		PolicySnapshot:     d.PolicySnapshot,
		PriceBookVersionID: d.PriceBookVersionID,
		Events:             events,
	}, nil
}
