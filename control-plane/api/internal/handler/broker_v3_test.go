package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

func TestBrokerV3_InvalidOrExpiredKey(t *testing.T) {
	ms := &mockStore{} // returns ErrVirtualKeyNotFound for all lookups

	h := NewBrokerV3Handler(ms, nil, nil, nil)
	h.SetValkeyClient(nil)

	body := `{"provider":"openai","model":"gpt-4o","payload":{}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v3/broker/dispatch", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-vex-invalid-secret-key-123")

	rr := httptest.NewRecorder()
	h.Dispatch(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 Unauthorized, got %d: %s", rr.Code, rr.Body.String())
	}

	var res map[string]map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode error JSON: %v", err)
	}

	if res["error"]["code"] != "invalid_virtual_key" {
		t.Errorf("expected error code 'invalid_virtual_key', got %q", res["error"]["code"])
	}
}

func TestBrokerV3_ModelNotAllowed(t *testing.T) {
	ms := &mockStore{
		getVirtualKeyByHashFunc: func(ctx context.Context, keyHash string) (*store.VirtualKey, error) {
			return &store.VirtualKey{
				ID:            "vk-123",
				TenantID:      "tenant-abc",
				AllowedModels: []string{"claude-3-5-sonnet*"},
				Status:        "active",
			}, nil
		},
	}

	h := NewBrokerV3Handler(ms, nil, nil, nil)
	h.SetValkeyClient(nil)

	body := `{"provider":"openai","model":"gpt-4o","payload":{}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v3/broker/dispatch", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-vex-valid-secret")

	rr := httptest.NewRecorder()
	h.Dispatch(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden, got %d: %s", rr.Code, rr.Body.String())
	}

	var res map[string]map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode error JSON: %v", err)
	}

	if res["error"]["code"] != "model_not_allowed" {
		t.Errorf("expected error code 'model_not_allowed', got %q", res["error"]["code"])
	}
}

func TestBrokerV3_SpendReservation_BudgetExceeded(t *testing.T) {
	ms := &mockStore{
		getVirtualKeyByHashFunc: func(ctx context.Context, keyHash string) (*store.VirtualKey, error) {
			return &store.VirtualKey{
				ID:                      "vk-123",
				TenantID:                "tenant-abc",
				MonthlyBudgetMicrocents: 1000000,
				Status:                  "active",
			}, nil
		},
		incrementVirtualKeySpendFunc: func(ctx context.Context, tenantID, id string, deltaMicrocents int64) (int64, error) {
			return 0, store.ErrVirtualKeyBudgetExceeded
		},
	}

	h := NewBrokerV3Handler(ms, nil, nil, nil)
	h.SetValkeyClient(nil)

	body := `{"provider":"openai","model":"gpt-4o","payload":{}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v3/broker/dispatch", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-vex-valid-secret")

	rr := httptest.NewRecorder()
	h.Dispatch(rr, req)

	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("expected status 402 Payment Required, got %d: %s", rr.Code, rr.Body.String())
	}

	var res map[string]map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode error JSON: %v", err)
	}

	if res["error"]["code"] != "budget_exceeded" {
		t.Errorf("expected error code 'budget_exceeded', got %q", res["error"]["code"])
	}
}

func TestBrokerV3_SpendReservation_FailClosedOnServiceError(t *testing.T) {
	ms := &mockStore{
		getVirtualKeyByHashFunc: func(ctx context.Context, keyHash string) (*store.VirtualKey, error) {
			return &store.VirtualKey{
				ID:                      "vk-123",
				TenantID:                "tenant-abc",
				MonthlyBudgetMicrocents: 5000000,
				Status:                  "active",
			}, nil
		},
		incrementVirtualKeySpendFunc: func(ctx context.Context, tenantID, id string, deltaMicrocents int64) (int64, error) {
			return 0, errStore // database or infrastructure failure
		},
	}

	h := NewBrokerV3Handler(ms, nil, nil, nil)
	h.SetValkeyClient(nil)

	body := `{"provider":"openai","model":"gpt-4o","payload":{}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v3/broker/dispatch", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-vex-valid-secret")

	rr := httptest.NewRecorder()
	h.Dispatch(rr, req)

	// Fail-closed behavior: should return 503 Service Unavailable, NOT forward request to upstream LLM!
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503 Service Unavailable, got %d: %s", rr.Code, rr.Body.String())
	}

	var res map[string]map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode error JSON: %v", err)
	}

	if res["error"]["code"] != "spend_service_unavailable" {
		t.Errorf("expected error code 'spend_service_unavailable', got %q", res["error"]["code"])
	}
}
