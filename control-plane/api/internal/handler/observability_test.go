package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestObservabilityHandler_ListDeletedKeys(t *testing.T) {
	mock := &mockStore{}
	h := NewObservabilityHandler(nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/deleted-keys", nil)
	w := httptest.NewRecorder()

	h.ListDeletedKeys(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if _, ok := resp["deleted_virtual_keys"]; !ok {
		t.Fatalf("expected deleted_virtual_keys in response")
	}
	_ = mock
}

func TestObservabilityHandler_ListDeletedTeams(t *testing.T) {
	h := NewObservabilityHandler(nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/deleted-teams", nil)
	w := httptest.NewRecorder()

	h.ListDeletedTeams(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if _, ok := resp["deleted_teams"]; !ok {
		t.Fatalf("expected deleted_teams in response")
	}
}
