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
