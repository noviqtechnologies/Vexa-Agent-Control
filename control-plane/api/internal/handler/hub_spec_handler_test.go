package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/sse"
)

func TestHubSpecHandler_GetBootstrap(t *testing.T) {
	broker := sse.NewBroker()
	h := NewHubSpecHandler(nil, broker)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap?gateway_id=gw-test1", nil)
	rr := httptest.NewRecorder()

	h.GetBootstrap(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp BootstrapResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode json response: %v", err)
	}

	if resp.Config.PolicyCacheTTLSeconds != 3600 {
		t.Errorf("got PolicyCacheTTLSeconds = %d, want 3600", resp.Config.PolicyCacheTTLSeconds)
	}
}

func TestHubSpecHandler_CreatePolicy_ValidYAML(t *testing.T) {
	broker := sse.NewBroker()
	h := NewHubSpecHandler(nil, broker)

	body := map[string]string{
		"name":           "test-policy",
		"yaml_content":   "version: 2\ndefault_action: deny\n",
		"schema_version": "v2",
	}
	jsonBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(jsonBytes))
	rr := httptest.NewRecorder()

	h.CreatePolicy(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusCreated)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp["name"] != "test-policy" {
		t.Errorf("got name = %v, want test-policy", resp["name"])
	}
}

func TestHubSpecHandler_CreatePolicy_InvalidYAML(t *testing.T) {
	broker := sse.NewBroker()
	h := NewHubSpecHandler(nil, broker)

	body := map[string]string{
		"name":           "bad-policy",
		"yaml_content":   ": : invalid yaml :",
		"schema_version": "v2",
	}
	jsonBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(jsonBytes))
	rr := httptest.NewRecorder()

	h.CreatePolicy(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 for invalid YAML", rr.Code)
	}
}

func TestHubSpecHandler_RotateCredential(t *testing.T) {
	broker := sse.NewBroker()
	h := NewHubSpecHandler(nil, broker)

	body := map[string]string{
		"provider": "openai",
		"new_key":  "sk-test-12345",
	}
	jsonBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/rotate", bytes.NewReader(jsonBytes))
	rr := httptest.NewRecorder()

	h.RotateCredential(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp["provider"] != "openai" {
		t.Errorf("got provider = %v, want openai", resp["provider"])
	}
}

func TestHubSpecHandler_ListGateways(t *testing.T) {
	h := NewHubSpecHandler(nil, nil)

	r := chi.NewRouter()
	r.Get("/api/v1/gateways", h.ListGateways)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateways", nil)
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}
