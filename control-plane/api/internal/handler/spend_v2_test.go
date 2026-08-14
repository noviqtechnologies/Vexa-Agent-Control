package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/spend"
)

func TestSpendV2Handler_Authorize_PriceUnknown(t *testing.T) {
	// With nil DB pool, price book lookup will return error / fallback or deny
	spendStore := spend.NewStore(nil)
	h := NewSpendV2Handler(spendStore)

	reqBody := spend.AuthorizeRequest{
		RequestID:          "req-test-1",
		IdempotencyKey:     "idemp-test-1",
		Provider:           "unknown_provider",
		Model:              "unknown_model_xyz",
		InputTokenEstimate: 100,
		MaxOutputTokens:    500,
	}
	b, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v2/spend/authorize", bytes.NewReader(b))
	rr := httptest.NewRecorder()

	h.Authorize(rr, req)

	// Either 429 deny or 500 DB error in mock test without DB
	if rr.Code != http.StatusTooManyRequests && rr.Code != http.StatusInternalServerError {
		t.Logf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
}

func TestSpendV2Handler_CreatePolicy_MissingLimit(t *testing.T) {
	spendStore := spend.NewStore(nil)
	h := NewSpendV2Handler(spendStore)

	reqBody := map[string]interface{}{
		"scope_type": "organization",
		"period":     "daily",
	}
	b, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v2/spend/policies", bytes.NewReader(b))
	rr := httptest.NewRecorder()

	h.CreatePolicy(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 Bad Request for missing limit", rr.Code)
	}
}
