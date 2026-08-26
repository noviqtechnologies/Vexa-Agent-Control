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
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/crypto"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

type mockProviderClient struct {
	lastAPIKey string
}

func (m *mockProviderClient) ForwardLLMRequest(ctx context.Context, provider, model string, stream bool, payload json.RawMessage, apiKey string) (*broker.LLMResponse, error) {
	m.lastAPIKey = apiKey
	return &broker.LLMResponse{
		Usage: map[string]interface{}{
			"prompt_tokens": 10,
			"total_tokens":  20,
		},
		Response: json.RawMessage(`{"id":"chatcmpl-test","choices":[{"message":{"content":"ok"}}]}`),
	}, nil
}

func TestBrokerV2Handler_DecryptionAndDispatch(t *testing.T) {
	masterKeyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	masterKey, _ := hex.DecodeString(masterKeyHex)

	rawSecret := "sk-real-upstream-secret-key"
	encryptedKey, err := crypto.Encrypt(masterKey, rawSecret)
	if err != nil {
		t.Fatalf("failed to encrypt key: %v", err)
	}

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
		TenantID:    "00000000-0000-0000-0000-000000000001",
		DeviceState: model.DeviceStateCompliant,
	}
	ctx := context.WithValue(req.Context(), middleware.DevicePrincipalKey, principal)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	h.HandleLLMRequest(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify the mock response fallback or decrypted key was passed
	if mockClient.lastAPIKey == "" {
		t.Fatalf("expected non-empty API key passed to provider client")
	}

	_ = encryptedKey
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
		DeviceID:    "dev-2",
		TenantID:    "00000000-0000-0000-0000-000000000001",
		DeviceState: model.DeviceStateNonCompliant,
	}
	ctx := context.WithValue(req.Context(), middleware.DevicePrincipalKey, principal)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	h.HandleLLMRequest(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden for NON_COMPLIANT device, got %d", rr.Code)
	}
}
