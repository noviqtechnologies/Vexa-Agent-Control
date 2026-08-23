package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/session"
)

func TestRequireSaaSOperatorMiddleware(t *testing.T) {
	handler := DashboardAuth()(RequireSaaSOperator()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("operator-ok"))
	})))

	// 1. Regular admin user (is_saas_operator = false) -> Expected 403
	regularCookie := session.Create("00000000-0000-0000-0000-000000000001", "admin-user", true, false)
	req1 := httptest.NewRequest("GET", "/api/v1/operator/organizations", nil)
	req1.AddCookie(&http.Cookie{Name: "agentcontrol_session", Value: regularCookie})
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for non-operator, got %d", rec1.Code)
	}

	// 2. SaaS Operator user (is_saas_operator = true) -> Expected 200
	operatorCookie := session.Create("00000000-0000-0000-0000-000000000001", "operator-user", true, true)
	req2 := httptest.NewRequest("GET", "/api/v1/operator/organizations", nil)
	req2.AddCookie(&http.Cookie{Name: "agentcontrol_session", Value: operatorCookie})
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Errorf("expected 200 OK for operator, got %d", rec2.Code)
	}
}

func TestSessionAuthOptional(t *testing.T) {
	testOrgID := "11111111-2222-3333-4444-555555555555"
	var extractedTenant string
	handler := SessionAuthOptional()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extractedTenant = ResolveTenantScope(r)
		w.WriteHeader(http.StatusOK)
	}))

	// 1. With valid session cookie for custom tenant
	sessCookie := session.Create(testOrgID, "tenant-admin", true, false)
	req1 := httptest.NewRequest("GET", "/api/v2/spend/policies", nil)
	req1.AddCookie(&http.Cookie{Name: "agentcontrol_session", Value: sessCookie})
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rec1.Code)
	}
	if extractedTenant != testOrgID {
		t.Errorf("expected resolved tenant %s, got %s", testOrgID, extractedTenant)
	}

	// 2. Without session cookie -> should not fail, should resolve to default tenant
	req2 := httptest.NewRequest("GET", "/api/v2/spend/policies", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rec2.Code)
	}
	if extractedTenant != DefaultTenantID {
		t.Errorf("expected resolved tenant %s, got %s", DefaultTenantID, extractedTenant)
	}
}
