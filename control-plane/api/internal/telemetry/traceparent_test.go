package telemetry

import (
	"net/http"
	"testing"
)

func TestExtractOrGenerateTraceContext_ValidW3C(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	validTrace := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	req.Header.Set("traceparent", validTrace)

	tc := ExtractOrGenerateTraceContext(req)
	if tc == nil {
		t.Fatalf("expected non-nil trace context")
	}
	if tc.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("expected traceID = 4bf92f3577b34da6a3ce929d0e0e4736, got %s", tc.TraceID)
	}
	if tc.ParentID != "00f067aa0ba902b7" {
		t.Errorf("expected parentID = 00f067aa0ba902b7, got %s", tc.ParentID)
	}
	if tc.Flags != "01" {
		t.Errorf("expected flags = 01, got %s", tc.Flags)
	}
}

func TestExtractOrGenerateTraceContext_InvalidOrMissingGeneratesCompliant(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("traceparent", "invalid-trace-format")

	tc := ExtractOrGenerateTraceContext(req)
	if tc == nil {
		t.Fatalf("expected newly generated trace context")
	}
	if len(tc.TraceID) != 32 {
		t.Errorf("expected 32-char hex trace ID, got %d chars (%s)", len(tc.TraceID), tc.TraceID)
	}
	if len(tc.ParentID) != 16 {
		t.Errorf("expected 16-char hex parent ID, got %d chars (%s)", len(tc.ParentID), tc.ParentID)
	}

	formatted := tc.FormatTraceparent()
	if !traceparentRegex.MatchString(formatted) {
		t.Errorf("formatted traceparent %s failed regex validation", formatted)
	}
}
