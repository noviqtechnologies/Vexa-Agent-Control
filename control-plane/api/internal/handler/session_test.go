package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/spend"
)

func TestSessionHandler_GetSessionTrace_MissingID(t *testing.T) {
	spendStore := spend.NewStore(nil)
	ds := &mockStore{}
	h := NewSessionHandler(spendStore, ds)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/", nil)
	rr := httptest.NewRecorder()

	h.GetSessionTrace(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestSessionHandler_GetSessionTrace_Success(t *testing.T) {
	spendStore := spend.NewStore(nil)
	ds := &mockStore{}
	h := NewSessionHandler(spendStore, ds)

	r := chi.NewRouter()
	r.Get("/api/v1/sessions/{session_id}", h.GetSessionTrace)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/sess-trace-test-123", nil)
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp SessionTraceResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.SessionID != "sess-trace-test-123" {
		t.Errorf("session_id = %s, want sess-trace-test-123", resp.SessionID)
	}
	if resp.Timeline == nil {
		t.Errorf("timeline = nil, want empty slice")
	}
}
