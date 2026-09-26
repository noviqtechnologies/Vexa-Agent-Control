package model

// Wire types mirroring dashboard-proto (Rust). The JSON field names match
// the Rust serde output exactly — snake_case enums, camelCase-free.
// AC-23.10: no field here accepts raw secret material.

type RedactedEvent struct {
	EventID           string                    `json:"event_id"`
	TimestampMs       int64                     `json:"timestamp_ms"`
	SessionID         string                    `json:"session_id"`
	AgentID           string                    `json:"agent_id"`
	ToolName          string                    `json:"tool_name"`
	Decision          string                    `json:"decision"`
	DlpFindings       []RedactedDlpFinding      `json:"dlp_findings"`
	InjectionFindings []RedactedInjectionFinding `json:"injection_findings"`
	SemanticFindings  []RedactedSemanticFinding  `json:"semantic_findings"`
}

type RedactedDlpFinding struct {
	Category    string `json:"category"`
	PatternName string `json:"pattern_name"`
	Count       uint32 `json:"count"`
}

type RedactedInjectionFinding struct {
	PatternName string `json:"pattern_name"`
	Count       uint32 `json:"count"`
}

type RedactedSemanticFinding struct {
	AnomalyScore float32 `json:"anomaly_score"`
	FindingType  string  `json:"finding_type"`
}

type RedactedAlert struct {
	AlertID  string        `json:"alert_id"`
	Severity string        `json:"severity"`
	Event    RedactedEvent `json:"event"`
}

type SanitizedCredentialMeta struct {
	CredentialID    string           `json:"credential_id"`
	AgentID         string           `json:"agent_id"`
	Scope           []string         `json:"scope"`
	TTLSeconds      uint64           `json:"ttl_seconds"`
	CreatedAtMs     int64            `json:"created_at_ms"`
	ExpiresAtMs     int64            `json:"expires_at_ms"`
	LastRotatedAtMs *int64           `json:"last_rotated_at_ms"`
	RotationHistory []RotationRecord `json:"rotation_history"`
}

type RotationRecord struct {
	RotatedAtMs int64  `json:"rotated_at_ms"`
	Reason      string `json:"reason"`
}

// Validation helpers.

var validDecisions = map[string]bool{
	"allowed": true,
	"denied":  true,
	"warned":  true,
}

var validSeverities = map[string]bool{
	"info":     true,
	"warning":  true,
	"critical": true,
}

func (e *RedactedEvent) Valid() bool {
	return e.EventID != "" &&
		e.SessionID != "" &&
		e.AgentID != "" &&
		e.ToolName != "" &&
		validDecisions[e.Decision]
}

func (a *RedactedAlert) Valid() bool {
	return a.AlertID != "" &&
		validSeverities[a.Severity] &&
		a.Event.Valid()
}

type SanitizedMcpServerMeta struct {
	IDETarget    string `json:"ide_target"`
	ServerName   string `json:"server_name"`
	Wrapped      bool   `json:"wrapped"`
	PathVerified bool   `json:"path_verified"`
	LastSeenAtMs int64  `json:"last_seen_at_ms,omitempty"`
}

type McpServerSnapshot struct {
	AgentID string                   `json:"agent_id"`
	Servers []SanitizedMcpServerMeta `json:"servers"`
}

type LlmRequestLog struct {
	RequestID        string  `json:"request_id"`
	SessionID        string  `json:"session_id"`
	KeyHash          *string `json:"key_hash,omitempty"`
	Model            string  `json:"model"`
	Provider         string  `json:"provider"`
	IsStreaming      bool    `json:"is_streaming"`
	PromptTokens     int64   `json:"prompt_tokens"`
	CompletionTokens int64   `json:"completion_tokens"`
	TotalTokens      int64   `json:"total_tokens"`
	LatencyMs        float64 `json:"latency_ms"`
	StatusCode       int     `json:"status_code"`
	Verdict          string  `json:"verdict"`
	IdentitySub      *string `json:"identity_sub,omitempty"`
	IdentityEmail    *string `json:"identity_email,omitempty"`
	RequestIP        *string `json:"request_ip,omitempty"`
	TimestampMs      int64   `json:"timestamp_ms"`
	IsEstimated      bool    `json:"is_estimated"`
	Protocol         string  `json:"protocol"`
	DeviceID         *string `json:"device_id,omitempty"`
}

func (l *LlmRequestLog) Valid() bool {
	return l != nil && l.RequestID != ""
}

