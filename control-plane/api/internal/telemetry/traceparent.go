package telemetry

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// W3C Traceparent Regex: 00-{32 hex trace_id}-{16 hex parent_id}-{02 hex flags}
var traceparentRegex = regexp.MustCompile(`^00-([0-9a-fA-F]{32})-([0-9a-fA-F]{16})-([0-9a-fA-F]{2})$`)

// TraceContext encapsulates W3C distributed tracing identifiers.
type TraceContext struct {
	TraceID  string
	ParentID string
	Flags    string
}

// GenerateRandomHex generates cryptographically random hex bytes.
func GenerateRandomHex(bytesCount int) string {
	b := make([]byte, bytesCount)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ExtractOrGenerateTraceContext validates incoming traceparent or generates a new one.
func ExtractOrGenerateTraceContext(r *http.Request) *TraceContext {
	raw := ""
	if r != nil {
		raw = r.Header.Get("traceparent")
		if raw == "" {
			raw = r.Header.Get("Traceparent")
		}
	}

	raw = strings.TrimSpace(raw)
	if raw != "" {
		matches := traceparentRegex.FindStringSubmatch(raw)
		if len(matches) == 4 {
			traceID := strings.ToLower(matches[1])
			// Disallow all-zeros trace ID per W3C specification
			if traceID != "00000000000000000000000000000000" {
				return &TraceContext{
					TraceID:  traceID,
					ParentID: strings.ToLower(matches[2]),
					Flags:    strings.ToLower(matches[3]),
				}
			}
		}
	}

	// Generate compliant new W3C trace context
	return &TraceContext{
		TraceID:  GenerateRandomHex(16), // 32 hex chars
		ParentID: GenerateRandomHex(8),  // 16 hex chars
		Flags:    "01",                  // Sampled
	}
}

// FormatTraceparent formats the trace context as a W3C traceparent header value.
func (tc *TraceContext) FormatTraceparent() string {
	if tc == nil || tc.TraceID == "" {
		return fmt.Sprintf("00-%s-%s-01", GenerateRandomHex(16), GenerateRandomHex(8))
	}
	return fmt.Sprintf("00-%s-%s-%s", tc.TraceID, tc.ParentID, tc.Flags)
}
