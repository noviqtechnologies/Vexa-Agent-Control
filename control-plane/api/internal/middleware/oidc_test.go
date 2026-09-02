package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/session"
)

func TestRequireAdminMiddleware(t *testing.T) {
	handler := DashboardAuth()(RequireAdmin()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("admin-ok"))
	})))

	// 1. Regular non-admin user -> Expected 403
	regularCookie := session.Create("00000000-0000-0000-0000-000000000001", "member-user", false, false)
	req1 := httptest.NewRequest("GET", "/api/v1/users", nil)
	req1.AddCookie(&http.Cookie{Name: "agentcontrol_session", Value: regularCookie})
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for non-admin, got %d", rec1.Code)
	}

	// 2. Admin user -> Expected 200
	adminCookie := session.Create("00000000-0000-0000-0000-000000000001", "admin-user", true, false)
	req2 := httptest.NewRequest("GET", "/api/v1/users", nil)
	req2.AddCookie(&http.Cookie{Name: "agentcontrol_session", Value: adminCookie})
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Errorf("expected 200 OK for admin, got %d", rec2.Code)
	}
}

func TestResolveOrganizationScope(t *testing.T) {
	testOrgID := "11111111-2222-3333-4444-555555555555"
	var extractedOrg string
	handler := SessionAuthOptional()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extractedOrg = ResolveOrganizationScope(r)
		w.WriteHeader(http.StatusOK)
	}))

	// 1. With valid session cookie for custom org
	sessCookie := session.Create(testOrgID, "admin-user", true, false)
	req1 := httptest.NewRequest("GET", "/api/v2/spend/policies", nil)
	req1.AddCookie(&http.Cookie{Name: "agentcontrol_session", Value: sessCookie})
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rec1.Code)
	}
	if extractedOrg != testOrgID {
		t.Errorf("expected resolved org %s, got %s", testOrgID, extractedOrg)
	}

	// 2. Without session cookie -> should resolve to DefaultOrganizationID
	req2 := httptest.NewRequest("GET", "/api/v2/spend/policies", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rec2.Code)
	}
	if extractedOrg != DefaultOrganizationID {
		t.Errorf("expected default org %s, got %s", DefaultOrganizationID, extractedOrg)
	}
}
