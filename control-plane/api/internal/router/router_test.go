package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestRegisterProtectedRoute_Tracking(t *testing.T) {
	ClearRegistry()

	r := chi.NewRouter()

	testHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}

	spec := RouteSpec{
		Method:      http.MethodPost,
		Path:        "/api/v2/telemetry/ingest",
		Principal:   PrincipalDeviceNode,
		MinRole:     "device",
		OrgScope:    ScopeFromDevice,
		Credential:  CredDeviceToken,
		Description: "Ingest agent telemetry batches",
		Handler:     testHandler,
	}

	RegisterProtectedRoute(r, spec)

	inv := GetRouteInventory()
	if len(inv) != 1 {
		t.Fatalf("expected 1 registered route, got %d", len(inv))
	}

	if inv[0].Path != "/api/v2/telemetry/ingest" {
		t.Errorf("expected path /api/v2/telemetry/ingest, got %s", inv[0].Path)
	}
	if inv[0].Principal != PrincipalDeviceNode {
		t.Errorf("expected principal DeviceNode, got %s", inv[0].Principal)
	}
	if inv[0].Credential != CredDeviceToken {
		t.Errorf("expected credential DeviceToken, got %s", inv[0].Credential)
	}

	// Test request execution
	req := httptest.NewRequest(http.MethodPost, "/api/v2/telemetry/ingest", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestRouteInventory_NoUnclassifiedSensitiveRoutes(t *testing.T) {
	ClearRegistry()

	r := chi.NewRouter()

	dummyHandler := func(w http.ResponseWriter, r *http.Request) {}

	routes := []RouteSpec{
		{
			Method:      http.MethodGet,
			Path:        "/healthz",
			Principal:   PrincipalPublic,
			MinRole:     "",
			OrgScope:    ScopePublic,
			Credential:  CredNone,
			Description: "Health check",
			Handler:     dummyHandler,
		},
		{
			Method:      http.MethodPost,
			Path:        "/api/v2/admin/enrollment-tokens",
			Principal:   PrincipalAdminUser,
			MinRole:     "admin",
			OrgScope:    ScopeFromJWT,
			Credential:  CredBearerJWT,
			Description: "Create device enrollment token",
			Handler:     dummyHandler,
		},
		{
			Method:      http.MethodPost,
			Path:        "/api/v2/device/heartbeats",
			Principal:   PrincipalDeviceNode,
			MinRole:     "device",
			OrgScope:    ScopeFromDevice,
			Credential:  CredDeviceToken,
			Description: "Submit device heartbeat",
			Handler:     dummyHandler,
		},
	}

	for _, spec := range routes {
		RegisterProtectedRoute(r, spec)
	}

	inv := GetRouteInventory()

	for _, rt := range inv {
		// Public route exemption
		if rt.Principal == PrincipalPublic {
			if rt.Credential != CredNone {
				t.Errorf("public route %s must not require credentials", rt.Path)
			}
			continue
		}

		// Sensitive routes must have non-empty credential and org scope
		if rt.Credential == CredNone || rt.Credential == "" {
			t.Errorf("sensitive route %s lacks required credential classification", rt.Path)
		}
		if rt.OrgScope == ScopePublic || rt.OrgScope == "" {
			t.Errorf("sensitive route %s lacks tenant organization scope policy", rt.Path)
		}
	}

	// Verify JSON export
	jsonBytes, err := ExportRouteInventoryJSON()
	if err != nil {
		t.Fatalf("failed to export JSON inventory: %v", err)
	}

	var parsed []RouteSpec
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("exported JSON is invalid: %v", err)
	}
	if len(parsed) != len(routes) {
		t.Errorf("expected %d exported routes, got %d", len(routes), len(parsed))
	}
}
