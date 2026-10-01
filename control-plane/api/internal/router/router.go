package router

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"
)

// PrincipalType defines the allowed principal classes
type PrincipalType string

const (
	PrincipalPublic         PrincipalType = "Public"
	PrincipalAdminUser      PrincipalType = "AdminUser"
	PrincipalMemberUser     PrincipalType = "MemberUser"
	PrincipalDeviceNode     PrincipalType = "DeviceNode"
	PrincipalGatewayProxy   PrincipalType = "GatewayProxy"
	PrincipalVirtualKeyUser PrincipalType = "VirtualKeyUser"
	PrincipalInternalJob    PrincipalType = "InternalJob"
)

// CredentialType defines the authentication mechanism
type CredentialType string

const (
	CredNone          CredentialType = "None"
	CredBearerJWT     CredentialType = "BearerJWT"
	CredDeviceToken   CredentialType = "DeviceToken"
	CredGatewaySecret CredentialType = "GatewaySecret"
	CredVirtualKey    CredentialType = "VirtualKey"
	CredOAuthPKCE     CredentialType = "OAuthPKCE"
	CredAdminToken    CredentialType = "AdminToken"
)

// OrgScopePolicy defines how organization context is resolved
type OrgScopePolicy string

const (
	ScopePublic          OrgScopePolicy = "Public"
	ScopeFromJWT         OrgScopePolicy = "ScopeFromJWT"
	ScopeFromDevice      OrgScopePolicy = "ScopeFromDevice"
	ScopeFromVirtualKey  OrgScopePolicy = "ScopeFromVirtualKey"
	ScopeFromAdminHeader OrgScopePolicy = "ScopeFromAdminHeader"
)

// RouteSpec defines the security specification for an API endpoint
type RouteSpec struct {
	Method      string           `json:"method"`
	Path        string           `json:"path"`
	Principal   PrincipalType    `json:"principal"`
	MinRole     string           `json:"min_role"`
	OrgScope    OrgScopePolicy   `json:"org_scope"`
	Credential  CredentialType   `json:"credential"`
	Description string           `json:"description"`
	Handler     http.HandlerFunc `json:"-"`
}

var (
	registryMu sync.RWMutex
	registry   []RouteSpec
)

// RegisterProtectedRoute registers a route with explicit security metadata and tracking
func RegisterProtectedRoute(r chi.Router, spec RouteSpec) {
	registryMu.Lock()
	registry = append(registry, spec)
	registryMu.Unlock()

	r.Method(spec.Method, spec.Path, spec.Handler)
}

// GetRouteInventory returns a copy of all registered route specifications
func GetRouteInventory() []RouteSpec {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]RouteSpec, len(registry))
	copy(out, registry)
	return out
}

// ExportRouteInventoryJSON returns the route inventory serialized as JSON
func ExportRouteInventoryJSON() ([]byte, error) {
	inv := GetRouteInventory()
	return json.MarshalIndent(inv, "", "  ")
}

// ClearRegistry resets the in-memory registry (useful for unit tests)
func ClearRegistry() {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = nil
}
