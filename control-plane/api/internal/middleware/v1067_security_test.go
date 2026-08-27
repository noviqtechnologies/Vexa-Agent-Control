package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestV1067_PolicyReadAuthMultiTenantRejection(t *testing.T) {
	secret := "test-shared-policy-read-secret"

	// 1. Multi-tenant mode (LegacySingleTenantMode = false) -> shared secret MUST be rejected
	multiTenantAuth := PolicyReadAuth(secret, LegacyAuthConfig{
		LegacySingleTenantMode: false,
		LegacyTenantID:         "",
	})

	handler1 := multiTenantAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req1 := httptest.NewRequest("GET", "/api/v1/policy/active", nil)
	req1.Header.Set("Authorization", "Bearer "+secret)
	rec1 := httptest.NewRecorder()
	handler1.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for shared secret in multi-tenant mode, got %d", rec1.Code)
	}

	// 2. Legacy single-tenant mode (LegacySingleTenantMode = true) -> shared secret accepted & bound to LegacyTenantID
	legacyTenantID := "tenant-legacy-uuid-1234"
	legacyAuth := PolicyReadAuth(secret, LegacyAuthConfig{
		LegacySingleTenantMode: true,
		LegacyTenantID:         legacyTenantID,
	})

	var boundTenant string
	handler2 := legacyAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := RequestPrincipalFromContext(r.Context())
		if p != nil {
			boundTenant = p.TenantID
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req2 := httptest.NewRequest("GET", "/api/v1/policy/active", nil)
	req2.Header.Set("Authorization", "Bearer "+secret)
	rec2 := httptest.NewRecorder()
	handler2.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK in explicit legacy single tenant mode, got %d", rec2.Code)
	}
	if boundTenant != legacyTenantID {
		t.Fatalf("expected principal tenant %s, got %s", legacyTenantID, boundTenant)
	}
}

func TestV1067_GatewayAuthMultiTenantRejection(t *testing.T) {
	secret := "test-shared-gateway-secret"

	// 1. Multi-tenant mode (LegacySingleTenantMode = false) -> shared secret MUST be rejected
	multiTenantAuth := GatewayAuth(secret, nil, LegacyAuthConfig{
		LegacySingleTenantMode: false,
		LegacyTenantID:         "",
	})

	handler1 := multiTenantAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req1 := httptest.NewRequest("POST", "/api/v1/ingest/events", nil)
	req1.Header.Set("Authorization", "Bearer "+secret)
	rec1 := httptest.NewRecorder()
	handler1.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for shared gateway secret in multi-tenant mode, got %d", rec1.Code)
	}

	// 2. Legacy single-tenant mode (LegacySingleTenantMode = true) -> shared secret accepted & bound to LegacyTenantID
	legacyTenantID := "tenant-legacy-gateway-uuid-5678"
	legacyAuth := GatewayAuth(secret, nil, LegacyAuthConfig{
		LegacySingleTenantMode: true,
		LegacyTenantID:         legacyTenantID,
	})

	var boundTenant string
	handler2 := legacyAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := RequestPrincipalFromContext(r.Context())
		if p != nil {
			boundTenant = p.TenantID
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req2 := httptest.NewRequest("POST", "/api/v1/ingest/events", nil)
	req2.Header.Set("Authorization", "Bearer "+secret)
	rec2 := httptest.NewRecorder()
	handler2.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK in explicit legacy single tenant mode, got %d", rec2.Code)
	}
	if boundTenant != legacyTenantID {
		t.Fatalf("expected principal tenant %s, got %s", legacyTenantID, boundTenant)
	}
}

func TestV1067_RequireTenantPrincipalMiddleware(t *testing.T) {
	mw := RequireTenantPrincipalMiddleware()
	var executed bool
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		executed = true
		w.WriteHeader(http.StatusOK)
	}))

	// Case 1: No tenant in context -> 401 Unauthorized
	req1 := httptest.NewRequest("GET", "/api/v1/policies", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized when tenant principal is missing, got %d", rec1.Code)
	}
	if executed {
		t.Fatalf("handler should not have executed without tenant principal")
	}

	// Case 2: Tenant principal in context -> 200 OK
	req2 := httptest.NewRequest("GET", "/api/v1/policies", nil)
	principal := &RequestPrincipal{
		TenantID:  "tenant-uuid-1234",
		AuthnType: AuthnTypeMTLS,
	}
	ctx := req2.Context()
	ctx = context.WithValue(ctx, RequestPrincipalKey, principal)
	req2 = req2.WithContext(ctx)

	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK when tenant principal is present, got %d", rec2.Code)
	}
	if !executed {
		t.Fatalf("handler should have executed with valid tenant principal")
	}
}
