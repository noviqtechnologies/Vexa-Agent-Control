package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/license"
)

func TestRequireFeature_Allowed(t *testing.T) {
	claims := &license.Claims{
		Tier:     "team",
		Features: []string{"siem_aggregation"},
	}

	handler := WithClaims(claims)(RequireFeature("siem_aggregation")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

func TestRequireFeature_Forbidden(t *testing.T) {
	claims := &license.Claims{
		Tier:     "community",
		Features: []string{},
	}

	handler := WithClaims(claims)(RequireFeature("siem_aggregation")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 Forbidden for missing feature", rr.Code)
	}
}

func TestRequireFeature_AliasMatching(t *testing.T) {
	claims := &license.Claims{
		Tier:     "team",
		Features: []string{"spend_v2", "siem_export"},
	}

	// Requesting spend_caps with spend_v2 in license
	handler1 := WithClaims(claims)(RequireFeature("spend_caps")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr1 := httptest.NewRecorder()
	handler1.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Errorf("spend_caps with spend_v2: status = %d, want 200", rr1.Code)
	}

	// Requesting siem_aggregation with siem_export in license
	handler2 := WithClaims(claims)(RequireFeature("siem_aggregation")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr2 := httptest.NewRecorder()
	handler2.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("siem_aggregation with siem_export: status = %d, want 200", rr2.Code)
	}
}
