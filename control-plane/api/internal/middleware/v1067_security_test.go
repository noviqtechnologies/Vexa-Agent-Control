package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPolicyReadAuth_SingleTenant(t *testing.T) {
	secret := "test-policy-read-secret"
	auth := PolicyReadAuth(secret, LegacyAuthConfig{
		LegacySingleTenantMode: true,
		LegacyTenantID:         DefaultOrganizationID,
	})

	var boundOrg string
	handler := auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := RequestPrincipalFromContext(r.Context())
		if p != nil {
			boundOrg = p.TenantID
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	// 1. Valid bearer token -> 200 OK
	req1 := httptest.NewRequest("GET", "/api/v1/policy/active", nil)
	req1.Header.Set("Authorization", "Bearer "+secret)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec1.Code)
	}
	if boundOrg != DefaultOrganizationID {
		t.Fatalf("expected principal org %s, got %s", DefaultOrganizationID, boundOrg)
	}

	// 2. Invalid bearer token -> 401 Unauthorized
	req2 := httptest.NewRequest("GET", "/api/v1/policy/active", nil)
	req2.Header.Set("Authorization", "Bearer invalid-secret")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for invalid secret, got %d", rec2.Code)
	}
}

func TestGatewayAuth_SingleTenant(t *testing.T) {
	secret := "test-gateway-secret"
	auth := GatewayAuth(secret, nil, LegacyAuthConfig{
		LegacySingleTenantMode: true,
		LegacyTenantID:         DefaultOrganizationID,
	})

	var boundOrg string
	handler := auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := RequestPrincipalFromContext(r.Context())
		if p != nil {
			boundOrg = p.TenantID
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	// 1. Valid gateway token -> 200 OK
	req1 := httptest.NewRequest("POST", "/api/v1/ingest/events", nil)
	req1.Header.Set("Authorization", "Bearer "+secret)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec1.Code)
	}
	if boundOrg != DefaultOrganizationID {
		t.Fatalf("expected principal org %s, got %s", DefaultOrganizationID, boundOrg)
	}

	// 2. Invalid gateway token -> 403 Forbidden
	req2 := httptest.NewRequest("POST", "/api/v1/ingest/events", nil)
	req2.Header.Set("Authorization", "Bearer invalid-token")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for invalid secret, got %d", rec2.Code)
	}
}

func TestRequireTenantPrincipalMiddleware_SingleTenant(t *testing.T) {
	mw := RequireTenantPrincipalMiddleware()
	var executed bool
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		executed = true
		w.WriteHeader(http.StatusOK)
	}))

	// Case 1: Tenant principal in context -> 200 OK
	req1 := httptest.NewRequest("GET", "/api/v1/policies", nil)
	principal := &RequestPrincipal{
		TenantID:  DefaultOrganizationID,
		AuthnType: AuthnTypeMTLS,
	}
	ctx := context.WithValue(req1.Context(), RequestPrincipalKey, principal)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1.WithContext(ctx))

	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with tenant principal, got %d", rec1.Code)
	}
	if !executed {
		t.Fatalf("handler should have executed")
	}
}
