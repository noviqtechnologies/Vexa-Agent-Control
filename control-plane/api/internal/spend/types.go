package spend

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// MoneyMicrocents represents money in integer microcents.
// 1 USD = 100,000,000 microcents ($0.01 = 1,000,000 microcents).
// Floating point calculations are strictly prohibited in ledger calculations.
type MoneyMicrocents int64

// Convert USD dollars (float) to MoneyMicrocents safely
func DollarsToMicrocents(dollars float64) MoneyMicrocents {
	return MoneyMicrocents(dollars * 100_000_000.0)
}

// ParseDecimalToMicrocents parses an exact decimal string (e.g. "100.50") into integer microcents without float drift
func ParseDecimalToMicrocents(s string) (MoneyMicrocents, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty amount string")
	}
	parts := strings.Split(s, ".")
	if len(parts) > 2 {
		return 0, errors.New("invalid decimal amount format")
	}
	whole, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid integer part: %w", err)
	}
	if whole < 0 {
		return 0, errors.New("amount cannot be negative")
	}

	var microcents int64 = whole * 100_000_000
	if len(parts) == 2 {
		fracStr := parts[1]
		if len(fracStr) > 8 {
			fracStr = fracStr[:8] // truncate beyond 8 decimal places
		} else {
			fracStr = fracStr + strings.Repeat("0", 8-len(fracStr))
		}
		frac, err := strconv.ParseInt(fracStr, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid fractional part: %w", err)
		}
		microcents += frac
	}
	return MoneyMicrocents(microcents), nil
}

// Convert MoneyMicrocents to USD dollars (float) for display purposes only
func (m MoneyMicrocents) ToDollars() float64 {
	return float64(m) / 100_000_000.0
}

const (
	CurrencyUSD = "USD"

	ScopeOrganization = "organization"
	ScopeProject      = "project"
	ScopeProvider     = "provider"

	PeriodDaily   = "daily"
	PeriodMonthly = "monthly"

	ActionHardDeny = "hard_deny"
	ActionWarn     = "warn"
	ActionNotify   = "notify"

	StateAuthorized = "AUTHORIZED"
	StateActive     = "ACTIVE"
	StateSettled    = "SETTLED"
	StateReleased   = "RELEASED"
	StateExpired    = "EXPIRED"
	StateReversed   = "REVERSED"

	EventAuthorized = "AUTHORIZED"
	EventSettled    = "SETTLED"
	EventReleased   = "RELEASED"
	EventReversed   = "REVERSED"

	// Standard error codes per 03_Data_Model_and_API.md
	ErrCodeAuthUnavailable      = "authorization_unavailable"
	ErrCodePriceUnknown         = "price_unknown"
	ErrCodeSpendBudgetExhausted = "spend_budget_exhausted"
	ErrCodeReservationExpired   = "reservation_expired"
	ErrCodePolicyVersionStale   = "policy_version_stale"
	ErrCodeAuthorizationRetry  = "authorization_retryable"
	ErrCodeOutputBoundMissing   = "output_bound_missing"
	ErrCodeIdempotencyConflict  = "idempotency_conflict"
	ErrCodeReservationNotFound  = "reservation_not_found"
	ErrCodeReservationTerminal  = "reservation_terminal"
	ErrCodeScopeUnauthorized    = "scope_unauthorized"

	// Token usage provenance sources
	UsageSourceProviderReported   = "provider_reported"
	UsageSourceProviderReconciled = "provider_reconciled"
	UsageSourceVexaTokenizer      = "vexa_tokenizer_estimate"
	UsageSourceCharacterEstimate  = "character_estimate"
)

// SpendPolicy represents a tenant-scoped budget rule.
type SpendPolicy struct {
	PolicyID        string          `json:"policy_id"`
	OrganizationID  string          `json:"organization_id"`
	ScopeType       string          `json:"scope_type"` // organization | project
	ScopeID         string          `json:"scope_id"`   // tenant_id or project_id
	Currency        string          `json:"currency"`   // USD
	PeriodType      string          `json:"period_type"` // daily | monthly
	LimitMicrocents MoneyMicrocents `json:"limit_microcents"`
	Action          string          `json:"action"` // hard_deny | warn | notify
	EffectiveFrom   time.Time       `json:"effective_from"`
	EffectiveTo     *time.Time      `json:"effective_to,omitempty"`
	Status          string          `json:"status"` // DRAFT | PUBLISHED | RETIRED
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// SpendPolicyVersion represents an immutable published policy snapshot.
type SpendPolicyVersion struct {
	PolicyVersionID string    `json:"policy_version_id"`
	PolicyID        string    `json:"policy_id"`
	Version         int       `json:"version"`
	SnapshotJSON    string    `json:"snapshot_json"`
	PublishedBy     string    `json:"published_by"`
	PublishedAt     time.Time `json:"published_at"`
}

// BudgetWindow tracks current reserved & settled microcents within a UTC time window.
type BudgetWindow struct {
	WindowID           string          `json:"window_id"`
	OrganizationID     string          `json:"organization_id"`
	PolicyVersionID    string          `json:"policy_version_id"`
	ScopeType          string          `json:"scope_type"`
	ScopeID            string          `json:"scope_id"`
	WindowStart        time.Time       `json:"window_start"`
	WindowEnd          time.Time       `json:"window_end"`
	LimitMicrocents    MoneyMicrocents `json:"limit_microcents"`
	ReservedMicrocents MoneyMicrocents `json:"reserved_microcents"`
	SettledMicrocents  MoneyMicrocents `json:"settled_microcents"`
	AvailableMicrocents MoneyMicrocents `json:"available_microcents"`
	Version            int64           `json:"version"`
}

// SpendReservation represents an active preflight reservation.
type SpendReservation struct {
	ReservationID        string          `json:"reservation_id"`
	OrganizationID       string          `json:"organization_id"`
	RequestID            string          `json:"request_id"`
	GatewayID            string          `json:"gateway_id"`
	ProjectID            string          `json:"project_id"`
	State                string          `json:"state"`
	ReservedMicrocents   MoneyMicrocents `json:"reserved_microcents"`
	SettledMicrocents    MoneyMicrocents `json:"settled_microcents"`
	Currency             string          `json:"currency"`
	ExpiresAt            time.Time       `json:"expires_at"`
	PolicySnapshot       string          `json:"policy_snapshot"`
	PriceBookVersionID   string          `json:"price_book_version_id"`
	Provider             string          `json:"provider"`
	Model                string          `json:"model"`
	InputTokensEstimated int64           `json:"input_tokens_estimated"`
	MaxOutputTokens      int64           `json:"max_output_tokens"`
	CreatedAt            time.Time       `json:"created_at"`
	SettledAt            *time.Time      `json:"settled_at,omitempty"`
	ReleasedAt           *time.Time      `json:"released_at,omitempty"`
	ReleaseReason        *string         `json:"release_reason,omitempty"`
}

// SpendEvent represents an immutable append-only financial transition log entry.
type SpendEvent struct {
	EventID           string          `json:"event_id"`
	OrganizationID    string          `json:"organization_id"`
	ReservationID     string          `json:"reservation_id"`
	RequestID         string          `json:"request_id"`
	EventType         string          `json:"event_type"` // AUTHORIZED | SETTLED | RELEASED | REVERSED
	AmountMicrocents  MoneyMicrocents `json:"amount_microcents"`
	Currency          string          `json:"currency"`
	UsageJSON         string          `json:"usage_json"`
	ProviderRequestID *string         `json:"provider_request_id,omitempty"`
	Actor             string          `json:"actor"`
	ReasonCode        string          `json:"reason_code"`
	OccurredAt        time.Time       `json:"occurred_at"`
}

// AuthorizeRequest is the payload sent by the gateway before dispatching an LLM call.
type AuthorizeRequest struct {
	GatewayID          string `json:"gateway_id,omitempty"`
	RequestID          string `json:"request_id"`
	IdempotencyKey     string `json:"idempotency_key"`
	ProjectID          string `json:"project_id"`
	Provider           string `json:"provider"`
	Model              string `json:"model"`
	InputTokenEstimate int64  `json:"input_token_estimate"`
	MaxOutputTokens    int64  `json:"max_output_tokens"`
	RequestHash        string `json:"request_hash"`
}

// AuthorizeResponse is returned to the gateway.
type AuthorizeResponse struct {
	Decision             string          `json:"decision"` // allow | deny
	ReasonCode           string          `json:"reason_code"`
	ReservationID        string          `json:"reservation_id,omitempty"`
	ReservationExpiresAt *time.Time      `json:"reservation_expires_at,omitempty"`
	ReservedMicrocents   MoneyMicrocents `json:"reserved_microcents,omitempty"`
	Currency             string          `json:"currency,omitempty"`
	PolicyVersions       []string        `json:"policy_versions,omitempty"`
	PriceBookVersion     string          `json:"price_book_version,omitempty"`
	CorrelationID        string          `json:"correlation_id,omitempty"`
	DisclosureSafeScope  string          `json:"disclosure_safe_scope,omitempty"`
	ResetAt              *time.Time      `json:"reset_at,omitempty"`
}

// SettleRequest is sent by the gateway after receiving provider response usage.
type SettleRequest struct {
	RequestID         string `json:"request_id"`
	IdempotencyKey    string `json:"idempotency_key"`
	ProviderRequestID string `json:"provider_request_id,omitempty"`
	InputTokens       int64  `json:"input_tokens"`
	OutputTokens      int64  `json:"output_tokens"`
	CachedInputTokens int64  `json:"cached_input_tokens"`
	IsEstimated       bool   `json:"is_estimated"`
	UsageSource       string `json:"usage_source,omitempty"`
	Status            int    `json:"status"`
	RequestHash       string `json:"request_hash"`
}

// SettleResponse returns the final settlement summary.
type SettleResponse struct {
	Status             string          `json:"status"`
	ReservationID      string          `json:"reservation_id"`
	SettledMicrocents  MoneyMicrocents `json:"settled_microcents"`
	ReleasedMicrocents MoneyMicrocents `json:"released_microcents"`
	Currency           string          `json:"currency"`
}

// ReleaseRequest cancels an unused reservation.
type ReleaseRequest struct {
	RequestID      string `json:"request_id"`
	IdempotencyKey string `json:"idempotency_key"`
	Reason         string `json:"reason"`
	RequestHash    string `json:"request_hash"`
	StatusCode     int    `json:"status_code,omitempty"`
}

// ReleaseResponse confirms reservation release.
type ReleaseResponse struct {
	Status             string          `json:"status"`
	ReservationID      string          `json:"reservation_id"`
	ReleasedMicrocents MoneyMicrocents `json:"released_microcents"`
}

// IncreaseRequestV2 represents a project budget increase submission.
type IncreaseRequestV2 struct {
	RequestID                string          `json:"request_id"`
	OrganizationID           string          `json:"organization_id"`
	ProjectID                string          `json:"project_id"`
	RequestedLimitMicrocents MoneyMicrocents `json:"requested_limit_microcents"`
	CurrentLimitMicrocents   MoneyMicrocents `json:"current_limit_microcents"`
	Reason                   string          `json:"reason"`
	Status                   string          `json:"status"` // PENDING | APPROVED | REJECTED
	CreatedBy                string          `json:"created_by"`
	DecidedBy                *string         `json:"decided_by,omitempty"`
	DecisionReason           *string         `json:"decision_reason,omitempty"`
	ResultingPolicyVersionID *string         `json:"resulting_policy_version_id,omitempty"`
	CreatedAt                time.Time       `json:"created_at"`
	DecidedAt                *time.Time      `json:"decided_at,omitempty"`
}

// SpendAnalyticsSummary aggregates high-level ledger totals.
type SpendAnalyticsSummary struct {
	TotalReservedMoney MoneyMicrocents `json:"total_reserved_microcents"`
	TotalSettledMoney  MoneyMicrocents `json:"total_settled_microcents"`
	TotalReleasedMoney MoneyMicrocents `json:"total_released_microcents"`
	RequestCount       int64           `json:"request_count"`
	DeniedCount        int64           `json:"denied_count"`
	TotalCachedTokens  int64           `json:"total_cached_tokens"`
	TotalInputTokens   int64           `json:"total_input_tokens"`
	TotalOutputTokens  int64           `json:"total_output_tokens"`
}

// SpendTimeSeriesPoint represents hourly aggregated spend metrics.
type SpendTimeSeriesPoint struct {
	Hour               string          `json:"hour"`
	ReservedMicrocents MoneyMicrocents `json:"reserved_microcents"`
	SettledMicrocents  MoneyMicrocents `json:"settled_microcents"`
	ReleasedMicrocents MoneyMicrocents `json:"released_microcents"`
	RequestCount       int64           `json:"request_count"`
}

// SpendTopEntity aggregates spend by dimensions (device, provider, model, project).
type SpendTopEntity struct {
	EntityID          string          `json:"entity_id"`
	EntityName        string          `json:"entity_name,omitempty"`
	SettledMicrocents MoneyMicrocents `json:"settled_microcents"`
	RequestCount      int64           `json:"request_count"`
}

// SpendAnalytics encapsulates complete server-aggregated spend analytics.
type SpendAnalytics struct {
	Summary     SpendAnalyticsSummary  `json:"summary"`
	TimeSeries  []SpendTimeSeriesPoint `json:"time_series"`
	TopEntities []SpendTopEntity       `json:"top_entities"`
}

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

// RunDossier contains complete forensic identity, policy, economic, and event details.
type RunDossier struct {
	RunSummary
	ReleasedMicrocents MoneyMicrocents `json:"released_microcents"`
	ReleaseReason      *string         `json:"release_reason,omitempty"`
	ReleasedAt         *time.Time      `json:"released_at,omitempty"`
	PolicySnapshot     string          `json:"policy_snapshot"`
	PriceBookVersionID string          `json:"price_book_version_id"`
	Events             []SpendEvent    `json:"events"`
}

