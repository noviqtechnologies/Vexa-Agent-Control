package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/spend"
)

func TestEffectivePolicyHandler_GetEffective_Defaults(t *testing.T) {
	spendStore := spend.NewStore(nil)
	ds := &mockStore{}
	h := NewEffectivePolicyHandler(spendStore, ds)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policy/effective-explorer", nil)
	rr := httptest.NewRecorder()

	h.GetEffective(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp struct {
		ProvenanceLadder []PolicyLadderLevel `json:"provenance_ladder"`
		Effective        struct {
			SpendLimitMicrocents int64    `json:"spend_limit_microcents"`
			Action               string   `json:"action"`
			AllowedModels        []string `json:"allowed_models"`
			AllowedRoutes        []string `json:"allowed_routes"`
		} `json:"effective"`
		Confidence string `json:"confidence"`
	}

	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(resp.ProvenanceLadder) != 5 {
		t.Errorf("ladder levels = %d, want 5", len(resp.ProvenanceLadder))
	}
	if resp.Effective.SpendLimitMicrocents != 10000000000 {
		t.Errorf("spend limit = %d, want 10000000000", resp.Effective.SpendLimitMicrocents)
	}
	if resp.Effective.Action != "allow" {
		t.Errorf("action = %s, want allow", resp.Effective.Action)
	}
}

func TestEffectivePolicyHandler_GetEffective_HistoricalTimestamp(t *testing.T) {
	spendStore := spend.NewStore(nil)
	ds := &mockStore{}
	h := NewEffectivePolicyHandler(spendStore, ds)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policy/effective-explorer?at=2026-08-01T12:00:00Z&provider=openai&model=gpt-4o", nil)
	rr := httptest.NewRecorder()

	h.GetEffective(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp struct {
		QueriedAt string `json:"queried_at"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.QueriedAt != "2026-08-01T12:00:00Z" {
		t.Errorf("queried_at = %s, want 2026-08-01T12:00:00Z", resp.QueriedAt)
	}
}
