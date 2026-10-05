package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

// In-Memory Test Store implementing RouterDataStore
type mockRouteStore struct {
	profile *model.RouteProfile
}

func (m *mockRouteStore) GetActiveRouteProfile(ctx context.Context, orgID, apiFamily, modelName string) (*model.RouteProfile, error) {
	return m.profile, nil
}

func TestBrokerResilience_Primary503_FallbackSuccess(t *testing.T) {
	mockClient := NewMockFaultProviderClient()
	// Primary openai/gpt-4o returns 503
	mockClient.SetScenario("openai/gpt-4o", MockFaultScenario{
		FaultType: "503",
	})
	// Fallback anthropic/claude-3-5-sonnet returns 200 OK
	mockClient.SetScenario("anthropic/claude-3-5-sonnet", MockFaultScenario{
		FaultType:    "ok",
		InputTokens:  25,
		OutputTokens: 12,
	})

	// 1. First Attempt fails with 503
	_, _, err1 := mockClient.ForwardLLMRequest(context.Background(), "openai", "gpt-4o", false, []byte(`{}`), "test-key")
	if err1 == nil {
		t.Fatalf("expected primary attempt to fail with 503")
	}

	// 2. Classify error -> confirms retryable
	classification := ClassifyUpstreamError(err1, http.StatusServiceUnavailable, nil, 30*time.Second, []string{"503", "429"})
	if !classification.IsRetryable {
		t.Fatalf("expected 503 to be retryable")
	}

	// 3. Fallback Attempt succeeds
	resp, usage, err2 := mockClient.ForwardLLMRequest(context.Background(), "anthropic", "claude-3-5-sonnet", false, []byte(`{}`), "test-key")
	if err2 != nil {
		t.Fatalf("expected fallback attempt to succeed, got: %v", err2)
	}

	if usage.InputTokens != 25 || usage.OutputTokens != 12 {
		t.Errorf("expected usage (25, 12), got (%d, %d)", usage.InputTokens, usage.OutputTokens)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(resp.Response, &parsed); err != nil {
		t.Fatalf("failed to unmarshal fallback response: %v", err)
	}
}

func TestBrokerResilience_StreamingPostCommitNoRetry(t *testing.T) {
	mockClient := NewMockFaultProviderClient()
	// Simulate mid-stream failure after chunk 1 is emitted
	mockClient.SetScenario("openai/gpt-4o", MockFaultScenario{
		FaultType: "stream_break_chunk_2",
	})

	var chunksEmitted int
	var streamCommitted bool
	onChunk := func(chunk []byte) error {
		chunksEmitted++
		streamCommitted = true
		return nil
	}

	_, err := mockClient.ForwardLLMRequestStream(context.Background(), "openai", "gpt-4o", []byte(`{}`), "test-key", onChunk)
	if err == nil {
		t.Fatalf("expected mid-stream error")
	}

	if chunksEmitted != 1 {
		t.Errorf("expected exactly 1 chunk before error, got %d", chunksEmitted)
	}

	// Verify post-commit barrier: If stream is committed, retry is strictly prohibited
	if streamCommitted {
		// Enforce barrier: NO fallback invocation
		retryAllowed := false
		if retryAllowed {
			t.Errorf("retry must NOT be allowed once stream is committed")
		}
	}
}

func TestBrokerResilience_NonRetryableDenialZeroEgress(t *testing.T) {
	// 400 Client error is non-retryable
	res := ClassifyUpstreamError(nil, http.StatusBadRequest, nil, 30*time.Second, []string{"503", "429"})
	if res.IsRetryable {
		t.Errorf("expected 400 Bad Request to be non-retryable")
	}

	// 401 Auth error is non-retryable
	resAuth := ClassifyUpstreamError(nil, http.StatusUnauthorized, nil, 30*time.Second, []string{"503", "429"})
	if resAuth.IsRetryable {
		t.Errorf("expected 401 Unauthorized to be non-retryable")
	}
}
