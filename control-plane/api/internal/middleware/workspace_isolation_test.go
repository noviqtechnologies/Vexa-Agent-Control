package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWorkspaceScope_DerivationFromPrincipal(t *testing.T) {
	// 1. Empty context defaults to "default"
	if ws := WorkspaceIDFromContext(context.Background()); ws != DefaultWorkspaceID {
		t.Fatalf("expected '%s', got '%s'", DefaultWorkspaceID, ws)
	}

	// 2. Context with UserClaims
	claims := &UserClaims{
		OrganizationID: "org-1",
		WorkspaceID:    "ws-backend",
		ProjectID:      "proj-billing",
		UserID:         "user-1",
	}
	ctx := context.WithValue(context.Background(), UserClaimsKey, claims)
	if ws := WorkspaceIDFromContext(ctx); ws != "ws-backend" {
		t.Fatalf("expected 'ws-backend', got '%s'", ws)
	}
	if proj := ProjectIDFromContext(ctx); proj != "proj-billing" {
		t.Fatalf("expected 'proj-billing', got '%s'", proj)
	}

	// 3. Context with RequestPrincipal
	principal := &RequestPrincipal{
		OrganizationID: "org-1",
		WorkspaceID:    "ws-payments",
		ProjectID:      "proj-stripe",
		SubjectID:      "user-2",
		AuthnType:      AuthnTypeSession,
	}
	ctx2 := context.WithValue(context.Background(), RequestPrincipalKey, principal)
	if ws := WorkspaceIDFromContext(ctx2); ws != "ws-payments" {
		t.Fatalf("expected 'ws-payments', got '%s'", ws)
	}
}

func TestWorkspaceScope_AdversarialSubstitutionRejected(t *testing.T) {
	// Authenticated principal belongs to "ws-engineering"
	principal := &RequestPrincipal{
		OrganizationID: "org-1",
		WorkspaceID:    "ws-engineering",
		ProjectID:      "proj-core",
		SubjectID:      "dev-user-42",
		AuthnType:      AuthnTypeSession,
		IsAdmin:        false,
	}
	ctx := context.WithValue(context.Background(), RequestPrincipalKey, principal)

	// Valid access to own workspace
	if err := ValidateWorkspaceScope(ctx, "ws-engineering"); err != nil {
		t.Fatalf("expected own workspace to be permitted, got error: %v", err)
	}

	// Adversarial attempt: Principal from "ws-engineering" requests "ws-finance"
	err := ValidateWorkspaceScope(ctx, "ws-finance")
	if err == nil {
		t.Fatal("expected cross-workspace access to be rejected, got nil")
	}
	if err != ErrCrossWorkspaceAccessDenied {
		t.Fatalf("expected ErrCrossWorkspaceAccessDenied, got: %v", err)
	}
}

func TestWorkspaceScope_OrgAdminBypassPermitted(t *testing.T) {
	// Global Org Admin
	adminPrincipal := &RequestPrincipal{
		OrganizationID: "org-1",
		WorkspaceID:    "ws-admin",
		SubjectID:      "admin-lead",
		AuthnType:      AuthnTypeSession,
		IsAdmin:        true,
		Role:           "org_admin",
	}
	ctx := context.WithValue(context.Background(), RequestPrincipalKey, adminPrincipal)

	// Org admin can inspect or administer other workspaces
	if err := ValidateWorkspaceScope(ctx, "ws-finance"); err != nil {
		t.Fatalf("expected org admin to administer cross-workspace, got: %v", err)
	}
}

func TestRequireWorkspaceScopeMiddleware_Rejection(t *testing.T) {
	principal := &RequestPrincipal{
		OrganizationID: "org-1",
		WorkspaceID:    "ws-marketing",
		SubjectID:      "user-mkt",
		AuthnType:      AuthnTypeSession,
		IsAdmin:        false,
	}

	// Target getter attempts to access "ws-infrastructure"
	middleware := RequireWorkspaceScopeMiddleware(func(r *http.Request) string {
		return "ws-infrastructure"
	})

	handlerExecuted := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerExecuted = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/policies", nil)
	req = req.WithContext(context.WithValue(req.Context(), RequestPrincipalKey, principal))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if handlerExecuted {
		t.Fatal("handler should not have executed on cross-workspace mismatch")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden, got %d", w.Code)
	}
}
