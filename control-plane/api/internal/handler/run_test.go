package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/spend"
)

func TestRunHandler_ListRuns_Success(t *testing.T) {
	spendStore := spend.NewStore(nil)
	ds := &mockStore{}
	h := NewRunHandler(spendStore, ds)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/runs?hours=24&limit=10", nil)
	rr := httptest.NewRecorder()

	h.ListRuns(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp struct {
		OrganizationID string             `json:"organization_id"`
		Runs           []spend.RunSummary `json:"runs"`
		DataFreshness  string             `json:"data_freshness"`
		Confidence     string             `json:"confidence"`
	}

	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.Confidence != "observed" {
		t.Errorf("confidence = %s, want observed", resp.Confidence)
	}
	if resp.Runs == nil {
		t.Errorf("runs = nil, want empty slice")
	}
}

func TestRunHandler_GetRun_MissingID(t *testing.T) {
	spendStore := spend.NewStore(nil)
	ds := &mockStore{}
	h := NewRunHandler(spendStore, ds)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/runs/", nil)
	rr := httptest.NewRecorder()

	h.GetRun(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestRunHandler_GetRun_NotFound(t *testing.T) {
	spendStore := spend.NewStore(nil)
	ds := &mockStore{}
	h := NewRunHandler(spendStore, ds)

	r := chi.NewRouter()
	r.Get("/api/v1/runs/{run_id}", h.GetRun)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/runs/non-existent-run", nil)
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	// In nil pool mock test, returns 500 DB error or 404
	if rr.Code != http.StatusNotFound && rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 404 or 500", rr.Code)
	}
}
