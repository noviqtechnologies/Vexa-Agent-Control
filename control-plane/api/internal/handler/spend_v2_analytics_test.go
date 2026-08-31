package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/spend"
)

func TestSpendV2Handler_GetAnalytics_Success(t *testing.T) {
	spendStore := spend.NewStore(nil)
	h := NewSpendV2Handler(spendStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v2/spend/analytics?hours=48&group_by=provider", nil)
	rr := httptest.NewRecorder()

	h.GetAnalytics(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp struct {
		OrganizationID string               `json:"organization_id"`
		Analytics      spend.SpendAnalytics `json:"analytics"`
		GeneratedAt    string               `json:"generated_at"`
	}

	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.GeneratedAt == "" {
		t.Errorf("generated_at is empty")
	}
}
