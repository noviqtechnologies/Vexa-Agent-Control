package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/session"
)

func TestRequireSaaSOperatorMiddleware(t *testing.T) {
	handler := DashboardAuth()(RequireSaaSOperator()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("operator-ok"))
	})))

	// 1. Regular admin user (is_saas_operator = false) -> Expected 403
	regularCookie := session.Create("00000000-0000-0000-0000-000000000001", "admin-user", true, false)
	req1 := httptest.NewRequest("GET", "/api/v1/operator/organizations", nil)
	req1.AddCookie(&http.Cookie{Name: "agentwall_session", Value: regularCookie})
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for non-operator, got %d", rec1.Code)
	}

	// 2. SaaS Operator user (is_saas_operator = true) -> Expected 200
	operatorCookie := session.Create("00000000-0000-0000-0000-000000000001", "operator-user", true, true)
	req2 := httptest.NewRequest("GET", "/api/v1/operator/organizations", nil)
	req2.AddCookie(&http.Cookie{Name: "agentwall_session", Value: operatorCookie})
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Errorf("expected 200 OK for operator, got %d", rec2.Code)
	}
}
