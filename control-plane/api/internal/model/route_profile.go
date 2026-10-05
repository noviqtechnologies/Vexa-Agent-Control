package model

import (
	"fmt"
	"time"
)

// RouteProfile represents an immutable, versioned LLM route profile.
type RouteProfile struct {
	ID               string    `json:"id"`
	OrganizationID   string    `json:"organization_id"`
	Name             string    `json:"name"`
	Version          int       `json:"version"`
	ContentDigest    string    `json:"content_digest"`
	APIFamily        string    `json:"api_family"` // chat_completions | messages | responses
	MatchModel       string    `json:"match_model"` // *, gpt-*, claude-*, or exact model name
	PrimaryProvider  string    `json:"primary_provider"`
	PrimaryModel     string    `json:"primary_model"`
	FallbackProvider string    `json:"fallback_provider,omitempty"`
	FallbackModel    string    `json:"fallback_model,omitempty"`
	MaxAttempts      int       `json:"max_attempts"` // 1 or 2
	DeadlineMs       int       `json:"deadline_ms"`  // e.g. 30000
	RetryClasses     []string  `json:"retry_classes"`
	AllowedRegions   []string  `json:"allowed_regions"`
	IsActive         bool      `json:"is_active"`
	CreatedAt        time.Time `json:"created_at"`
	CreatedBy        string    `json:"created_by"`
}

// RouteProfileActivation logs an immutable deployment/activation or rollback event.
type RouteProfileActivation struct {
	ID                       string    `json:"id"`
	OrganizationID           string    `json:"organization_id"`
	RouteProfileID           string    `json:"route_profile_id"`
	Version                  int       `json:"version"`
	ContentDigest            string    `json:"content_digest"`
	ActivatedAt              time.Time `json:"activated_at"`
	ActivatedBy              string    `json:"activated_by"`
	Reason                   string    `json:"reason"`
	RollbackFromActivationID *string   `json:"rollback_from_activation_id,omitempty"`
}

// BrokerRequest represents a logical LLM request through the central broker.
type BrokerRequest struct {
	RequestID          string     `json:"request_id"`
	OrganizationID     string     `json:"organization_id"`
	IdempotencyKey     string     `json:"idempotency_key,omitempty"`
	TraceID            string     `json:"trace_id,omitempty"`
	PrincipalDeviceID  string     `json:"principal_device_id,omitempty"`
	PrincipalUserID    string     `json:"principal_user_id,omitempty"`
	RouteProfileID     *string    `json:"route_profile_id,omitempty"`
	PolicyVersionID    string     `json:"policy_version_id,omitempty"`
	RequestedProvider  string     `json:"requested_provider"`
	RequestedModel     string     `json:"requested_model"`
	Stream             bool       `json:"stream"`
	Status             string     `json:"status"` // admitted | in_flight | succeeded | failed | denied
	TerminalReasonCode string     `json:"terminal_reason_code,omitempty"`
	SpendReservationID string     `json:"spend_reservation_id,omitempty"`
	SettledMicrocents  int64      `json:"settled_microcents"`
	RequestHash        string     `json:"request_hash,omitempty"`
	CachedResponse     []byte     `json:"cached_response,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	CompletedAt        *time.Time `json:"completed_at,omitempty"`
}

// BrokerAttempt records an individual upstream provider execution attempt.
type BrokerAttempt struct {
	AttemptID            string     `json:"attempt_id"`
	RequestID            string     `json:"request_id"`
	AttemptNumber        int        `json:"attempt_number"` // 1 or 2
	TargetType           string     `json:"target_type"`    // primary | fallback
	Provider             string     `json:"provider"`
	Model                string     `json:"model"`
	StartedAt            time.Time  `json:"started_at"`
	CompletedAt          *time.Time `json:"completed_at,omitempty"`
	LatencyMs            int        `json:"latency_ms"`
	HTTPStatus           int        `json:"http_status"`
	ErrorClass           string     `json:"error_class,omitempty"`
	ErrorMessageRedacted string     `json:"error_message_redacted,omitempty"`
	StreamCommitted      bool       `json:"stream_committed"`
	InputTokens          int64      `json:"input_tokens"`
	OutputTokens         int64      `json:"output_tokens"`
	CachedTokens         int64      `json:"cached_tokens"`
	UsageSource          string     `json:"usage_source"`
}

// ExplainableRouteDecision documents candidate selection & rejection reasons.
type ExplainableRouteDecision struct {
	RouteProfileID   string            `json:"route_profile_id,omitempty"`
	RouteVersion     int               `json:"route_version,omitempty"`
	PolicyVersion    string            `json:"policy_version,omitempty"`
	TenantID         string            `json:"tenant_id"`
	RequestedAPI     string            `json:"requested_api"`
	RequestedModel   string            `json:"requested_model"`
	SelectedPrimary  string            `json:"selected_primary"`
	SelectedFallback string            `json:"selected_fallback,omitempty"`
	CandidateReasons map[string]string `json:"candidate_reasons"` // e.g. "anthropic/claude-3-5-sonnet": "candidate_selected"
}

// AddCandidateOutcome records why a candidate target was selected or rejected.
func (d *ExplainableRouteDecision) AddCandidateOutcome(provider, modelName, reasonCode string) {
	if d == nil {
		return
	}
	if d.CandidateReasons == nil {
		d.CandidateReasons = make(map[string]string)
	}
	key := fmt.Sprintf("%s/%s", provider, modelName)
	d.CandidateReasons[key] = reasonCode
}

// RequestDossier represents a complete operator inspection view of a request.
type RequestDossier struct {
	Request        BrokerRequest             `json:"request"`
	RouteDecision  *ExplainableRouteDecision `json:"route_decision,omitempty"`
	Attempts       []BrokerAttempt           `json:"attempts"`
	TotalLatencyMs int                       `json:"total_latency_ms"`
	AuditLink      string                    `json:"audit_link,omitempty"`
	TraceLink      string                    `json:"trace_link,omitempty"`
}
