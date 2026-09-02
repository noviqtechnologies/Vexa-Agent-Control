package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/broker"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

type mockProviderClient struct {
	lastAPIKey string
}

func (m *mockProviderClient) ForwardLLMRequest(ctx context.Context, provider, model string, stream bool, payload json.RawMessage, apiKey string) (*broker.LLMResponse, *broker.UsageReport, error) {
	m.lastAPIKey = apiKey
	usage := &broker.UsageReport{
		InputTokens:       10,
		OutputTokens:      10,
		CachedInputTokens: 0,
		IsEstimated:       false,
		UsageSource:       "provider_reported",
		StatusCode:        200,
	}
	return &broker.LLMResponse{
		Usage: map[string]interface{}{
			"prompt_tokens": 10,
			"total_tokens":  20,
		},
		Response: json.RawMessage(`{"id":"chatcmpl-test","choices":[{"message":{"content":"ok"}}]}`),
	}, usage, nil
}

func (m *mockProviderClient) ForwardLLMRequestStream(ctx context.Context, provider, model string, payload json.RawMessage, apiKey string, onChunk func(chunk []byte) error) (*broker.UsageReport, error) {
	m.lastAPIKey = apiKey
	_ = onChunk([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"test\"}}]}\n\n"))
	_ = onChunk([]byte("data: [DONE]\n\n"))
	return &broker.UsageReport{
		InputTokens:       10,
		OutputTokens:      10,
		CachedInputTokens: 0,
		IsEstimated:       false,
		UsageSource:       "provider_reported",
		StatusCode:        200,
	}, nil
}

func TestBrokerV2Handler_FailClosedOnMissingCredential(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")

	masterKeyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	masterKey, _ := hex.DecodeString(masterKeyHex)

	mockClient := &mockProviderClient{}
	h := &BrokerV2Handler{
		ProviderClient: mockClient,
		MasterKey:      masterKey,
	}

	reqPayload := BrokerRequestPayload{
		SchemaVersion: "1.0",
		RequestID:     "req-uuid-1",
		Provider:      "openai",
		Model:         "gpt-4o",
		Payload:       json.RawMessage(`{"messages":[{"role":"user","content":"hello"}]}`),
	}
	bodyBytes, _ := json.Marshal(reqPayload)

	req := httptest.NewRequest(http.MethodPost, "/api/v2/broker/llm-requests", bytes.NewReader(bodyBytes))
	
	// Inject compliant device principal
	principal := &model.DevicePrincipal{
		DeviceID:    "dev-1",
		OrganizationID: "00000000-0000-0000-0000-000000000001",
		DeviceState: model.DeviceStateCompliant,
	}
	ctx := context.WithValue(req.Context(), middleware.DevicePrincipalKey, principal)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	h.HandleLLMRequest(rr, req)

	// In fail-closed production design, unconfigured key must return 503 provider_credential_unavailable
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d: %s", rr.Code, rr.Body.String())
	}

	var errResp map[string]map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp["error"]["code"] != "provider_credential_unavailable" {
		t.Fatalf("expected error code 'provider_credential_unavailable', got %v", errResp["error"]["code"])
	}
}

func TestBrokerV2Handler_NonCompliantDeviceDenied(t *testing.T) {
	mockClient := &mockProviderClient{}
	h := &BrokerV2Handler{
		ProviderClient: mockClient,
	}

	reqPayload := BrokerRequestPayload{
		SchemaVersion: "1.0",
		RequestID:     "req-uuid-2",
		Provider:      "openai",
		Model:         "gpt-4o",
		Payload:       json.RawMessage(`{}`),
	}
	bodyBytes, _ := json.Marshal(reqPayload)

	req := httptest.NewRequest(http.MethodPost, "/api/v2/broker/llm-requests", bytes.NewReader(bodyBytes))
	
	// Inject NON_COMPLIANT device principal
	principal := &model.DevicePrincipal{
		DeviceID:       "dev-2",
		OrganizationID: "00000000-0000-0000-0000-000000000001",
		DeviceState:    model.DeviceStateNonCompliant,
	}
	ctx := context.WithValue(req.Context(), middleware.DevicePrincipalKey, principal)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	h.HandleLLMRequest(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden for NON_COMPLIANT device, got %d", rr.Code)
	}
}

func TestBrokerV2Handler_StreamFailClosedOnMissingCredential(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")

	mockClient := &mockProviderClient{}
	h := &BrokerV2Handler{
		ProviderClient: mockClient,
	}

	reqPayload := BrokerRequestPayload{
		SchemaVersion: "3.0",
		RequestID:     "req-stream-uuid-1",
		Provider:      "openai",
		Model:         "gpt-4o",
		Stream:        true,
		Payload:       json.RawMessage(`{"messages":[{"role":"user","content":"hello"}]}`),
	}
	bodyBytes, _ := json.Marshal(reqPayload)

	req := httptest.NewRequest(http.MethodPost, "/api/v3/broker/llm-stream", bytes.NewReader(bodyBytes))

	principal := &model.DevicePrincipal{
		DeviceID:       "dev-1",
		OrganizationID: "00000000-0000-0000-0000-000000000001",
		DeviceState:    model.DeviceStateCompliant,
	}
	ctx := context.WithValue(req.Context(), middleware.DevicePrincipalKey, principal)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	h.HandleLLMStream(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503 for streaming request with unconfigured key, got %d", rr.Code)
	}

	var errResp map[string]map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp["error"]["code"] != "provider_credential_unavailable" {
		t.Fatalf("expected error code 'provider_credential_unavailable', got %v", errResp["error"]["code"])
	}
}
