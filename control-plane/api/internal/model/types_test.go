package model

import "testing"

func TestRedactedEvent_Valid(t *testing.T) {
	base := RedactedEvent{
		EventID:   "evt-1",
		SessionID: "sess-1",
		AgentID:   "agent-1",
		ToolName:  "bash",
		Decision:  "allowed",
	}

	tests := []struct {
		name   string
		modify func(e *RedactedEvent)
		want   bool
	}{
		{"valid_allowed", func(e *RedactedEvent) {}, true},
		{"valid_denied", func(e *RedactedEvent) { e.Decision = "denied" }, true},
		{"valid_warned", func(e *RedactedEvent) { e.Decision = "warned" }, true},
		{"empty_event_id", func(e *RedactedEvent) { e.EventID = "" }, false},
		{"empty_session_id", func(e *RedactedEvent) { e.SessionID = "" }, false},
		{"empty_agent_id", func(e *RedactedEvent) { e.AgentID = "" }, false},
		{"empty_tool_name", func(e *RedactedEvent) { e.ToolName = "" }, false},
		{"empty_decision", func(e *RedactedEvent) { e.Decision = "" }, false},
		{"invalid_decision", func(e *RedactedEvent) { e.Decision = "blocked" }, false},
		{"case_sensitive_decision", func(e *RedactedEvent) { e.Decision = "Allowed" }, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := base
			tt.modify(&e)
			if got := e.Valid(); got != tt.want {
				t.Errorf("Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRedactedAlert_Valid(t *testing.T) {
	validEvent := RedactedEvent{
		EventID:   "evt-1",
		SessionID: "sess-1",
		AgentID:   "agent-1",
		ToolName:  "bash",
		Decision:  "denied",
	}

	tests := []struct {
		name   string
		alert  RedactedAlert
		want   bool
	}{
		{
			"valid_critical",
			RedactedAlert{AlertID: "alert-1", Severity: "critical", Event: validEvent},
			true,
		},
		{
			"valid_warning",
			RedactedAlert{AlertID: "alert-2", Severity: "warning", Event: validEvent},
			true,
		},
		{
			"valid_info",
			RedactedAlert{AlertID: "alert-3", Severity: "info", Event: validEvent},
			true,
		},
		{
			"empty_alert_id",
			RedactedAlert{AlertID: "", Severity: "critical", Event: validEvent},
			false,
		},
		{
			"invalid_severity",
			RedactedAlert{AlertID: "alert-1", Severity: "high", Event: validEvent},
			false,
		},
		{
			"empty_severity",
			RedactedAlert{AlertID: "alert-1", Severity: "", Event: validEvent},
			false,
		},
		{
			"invalid_inner_event",
			RedactedAlert{AlertID: "alert-1", Severity: "critical", Event: RedactedEvent{}},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.alert.Valid(); got != tt.want {
				t.Errorf("Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}
