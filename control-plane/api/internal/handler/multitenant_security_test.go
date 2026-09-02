package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/sse"
)

// Helper to set authenticated user context with specific role and tenant
func withUserContext(r *http.Request, userID, tenantID string, isAdmin, isOperator bool) *http.Request {
	claims := &middleware.UserClaims{
		UserID:         userID,
		TenantID:       tenantID,
		IsAdmin:        isAdmin,
		IsSaaSOperator: isOperator,
	}
	ctx := context.WithValue(r.Context(), middleware.UserClaimsKey, claims)
	return r.WithContext(ctx)
}

func TestMultiTenant_HeaderOverrideProtection(t *testing.T) {
	tenantA := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tenantB := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	// 1. Standard member token with spoofed X-Organization-ID header
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	req.Header.Set("X-Organization-ID", tenantB)
	req = withUserContext(req, "user-member-1", tenantA, false, false)

	resolvedTenant := middleware.ResolveTenantScope(req)
	if resolvedTenant != tenantA {
		t.Fatalf("Header override vulnerability: expected tenant %s, got %s", tenantA, resolvedTenant)
	}
}

func TestMultiTenant_SSEStreamIsolation(t *testing.T) {
	broker := sse.NewBroker()
	tenantA := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tenantB := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	chA, cleanupA := broker.SubscribeTenant(tenantA)
	defer cleanupA()

	chB, cleanupB := broker.SubscribeTenant(tenantB)
	defer cleanupB()

	// Publish alert to Tenant A
	alertA := map[string]string{"alert": "Malicious tool call", "tenant": tenantA}
	broker.PublishTenant(tenantA, alertA)

	// Verify Tenant A receives the alert
	select {
	case msg := <-chA:
		if !bytes.Contains(msg, []byte("Malicious tool call")) {
			t.Fatalf("Tenant A received unexpected message: %s", msg)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Tenant A timed out waiting for its own alert")
	}

	// Verify Tenant B received ZERO messages
	select {
	case msg := <-chB:
		t.Fatalf("Cross-tenant SSE leak! Tenant B received Tenant A's alert: %s", msg)
	default:
		// Passed: channel is empty
	}
}

func TestMultiTenant_PasswordUpdateRBAC(t *testing.T) {
	userH := NewUserHandler(nil)
	tenantA := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

	// 1. Standard member attempting to update another user's password without admin role
	body, _ := json.Marshal(map[string]string{"password": "newSecurePassword123!"})
	r := chi.NewRouter()
	r.Post("/users/{id}/password", userH.UpdatePassword)

	req := httptest.NewRequest(http.MethodPost, "/users/victim-user-id/password", bytes.NewReader(body))
	req = withUserContext(req, "attacker-user-id", tenantA, false, false)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("Privilege escalation: expected 403 Forbidden for non-admin password update, got %d", w.Code)
	}
}

func TestMultiTenant_AdminRouteRoleGating(t *testing.T) {
	// Test that middleware.RequireAdmin denies standard member
	r := chi.NewRouter()
	r.Use(middleware.RequireAdmin())
	r.Post("/admin-only-action", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Non-admin request
	req := httptest.NewRequest(http.MethodPost, "/admin-only-action", nil)
	req = withUserContext(req, "member-1", "tenant-1", false, false)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for non-admin, got %d", w.Code)
	}

	// Admin request
	adminReq := httptest.NewRequest(http.MethodPost, "/admin-only-action", nil)
	adminReq = withUserContext(adminReq, "admin-1", "tenant-1", true, false)

	adminW := httptest.NewRecorder()
	r.ServeHTTP(adminW, adminReq)

	if adminW.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for admin, got %d", adminW.Code)
	}
}
