package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

// DefaultOrganizationID is the authoritative singleton UUID for the organization.
const DefaultOrganizationID = "00000000-0000-0000-0000-000000000001"
const DefaultTenantID = DefaultOrganizationID

// ErrUnauthenticatedOrganizationScope is returned when an operation requires an authenticated organization context.
var ErrUnauthenticatedOrganizationScope = errors.New("unauthenticated organization scope")
var ErrUnauthenticatedTenantScope = ErrUnauthenticatedOrganizationScope

// AuthnType describes how the caller authenticated.
type AuthnType string

const (
	AuthnTypeSession      AuthnType = "session"
	AuthnTypeMTLS         AuthnType = "mtls"
	AuthnTypeDeviceToken  AuthnType = "device_token"
	AuthnTypeLegacySecret AuthnType = "legacy_secret"
)

// RequestPrincipal represents the verified identity and organization context of an inbound request.
type RequestPrincipal struct {
	OrganizationID string    `json:"organization_id"`
	TenantID       string    `json:"tenant_id"` // Alias for backward compatibility
	SubjectID      string    `json:"subject_id,omitempty"`
	DeviceID       string    `json:"device_id,omitempty"`
	AuthnType      AuthnType `json:"authn_type"`
	IsAdmin        bool      `json:"is_admin"`
	Role           string    `json:"role,omitempty"`
	Capabilities   []string  `json:"capabilities,omitempty"`
}

type contextKey string

const RequestPrincipalKey contextKey = "request_principal"

// RequestPrincipalFromContext extracts the RequestPrincipal from context or nil.
func RequestPrincipalFromContext(ctx context.Context) *RequestPrincipal {
	if ctx == nil {
		return nil
	}
	p, ok := ctx.Value(RequestPrincipalKey).(*RequestPrincipal)
	if ok && p != nil {
		if p.OrganizationID == "" && p.TenantID != "" {
			p.OrganizationID = p.TenantID
		}
		if p.TenantID == "" && p.OrganizationID != "" {
			p.TenantID = p.OrganizationID
		}
		return p
	}
	// Derive from UserClaims if present
	if claims, ok := ctx.Value(UserClaimsKey).(*UserClaims); ok && claims != nil {
		orgID := claims.OrganizationID
		if orgID == "" {
			orgID = claims.TenantID
		}
		if orgID == "" {
			orgID = DefaultOrganizationID
		}
		return &RequestPrincipal{
			OrganizationID: orgID,
			TenantID:       orgID,
			SubjectID:      claims.UserID,
			AuthnType:      AuthnTypeSession,
			IsAdmin:        claims.IsAdmin,
		}
	}
	// Derive from DevicePrincipal if present
	if dev, ok := ctx.Value(DevicePrincipalKey).(*model.DevicePrincipal); ok && dev != nil {
		orgID := dev.OrganizationID
		if orgID == "" {
			orgID = DefaultOrganizationID
		}
		return &RequestPrincipal{
			OrganizationID: orgID,
			TenantID:       orgID,
			DeviceID:       dev.DeviceID,
			AuthnType:      AuthnTypeMTLS,
			Capabilities:   dev.Capabilities,
		}
	}
	return nil
}

// RequireOrganizationPrincipal enforces that a valid RequestPrincipal exists.
func RequireOrganizationPrincipal(ctx context.Context) (*RequestPrincipal, error) {
	p := RequestPrincipalFromContext(ctx)
	if p == nil || p.OrganizationID == "" {
		return &RequestPrincipal{
			OrganizationID: DefaultOrganizationID,
			TenantID:       DefaultOrganizationID,
		}, nil
	}
	return p, nil
}

func RequireTenantPrincipal(ctx context.Context) (*RequestPrincipal, error) {
	return RequireOrganizationPrincipal(ctx)
}

// RequireOrganizationPrincipalMiddleware enforces that an authenticated principal is present.
func RequireOrganizationPrincipalMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, err := RequireOrganizationPrincipal(r.Context())
			if err != nil || p == nil {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]any{
						"code":    "unauthorized_organization_required",
						"message": "Authenticated organization principal is required for this operation",
					},
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func RequireTenantPrincipalMiddleware() func(http.Handler) http.Handler {
	return RequireOrganizationPrincipalMiddleware()
}

// OrganizationIDFromContext extracts the organization UUID from context.
func OrganizationIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return DefaultOrganizationID
	}
	if p := RequestPrincipalFromContext(ctx); p != nil && p.OrganizationID != "" {
		return p.OrganizationID
	}
	if claims, ok := ctx.Value(UserClaimsKey).(*UserClaims); ok && claims != nil {
		if claims.OrganizationID != "" {
			return claims.OrganizationID
		}
		if claims.TenantID != "" {
			return claims.TenantID
		}
	}
	if dev, ok := ctx.Value(DevicePrincipalKey).(*model.DevicePrincipal); ok && dev != nil && dev.OrganizationID != "" {
		return dev.OrganizationID
	}
	return DefaultOrganizationID
}

func TenantIDFromContext(ctx context.Context) string {
	return OrganizationIDFromContext(ctx)
}

// ResolveAuthenticatedOrganizationScope resolves the authoritative organization ID.
func ResolveAuthenticatedOrganizationScope(r *http.Request) (string, error) {
	if r == nil {
		return DefaultOrganizationID, nil
	}
	ctx := r.Context()
	if p := RequestPrincipalFromContext(ctx); p != nil && p.OrganizationID != "" {
		return p.OrganizationID, nil
	}
	if dev, ok := ctx.Value(DevicePrincipalKey).(*model.DevicePrincipal); ok && dev != nil && dev.OrganizationID != "" {
		return dev.OrganizationID, nil
	}
	if claims, ok := ctx.Value(UserClaimsKey).(*UserClaims); ok && claims != nil {
		if claims.OrganizationID != "" {
			return claims.OrganizationID, nil
		}
		if claims.TenantID != "" {
			return claims.TenantID, nil
		}
	}
	return DefaultOrganizationID, nil
}

func ResolveAuthenticatedTenantScope(r *http.Request) (string, error) {
	return ResolveAuthenticatedOrganizationScope(r)
}

func ResolveOrganizationScope(r *http.Request) string {
	orgID, _ := ResolveAuthenticatedOrganizationScope(r)
	if orgID == "" {
		return DefaultOrganizationID
	}
	return orgID
}

func ResolveTenantScope(r *http.Request) string {
	return ResolveOrganizationScope(r)
}

// IsSaaSOperatorFromContext always returns false (no SaaS operator).
func IsSaaSOperatorFromContext(ctx context.Context) bool {
	return false
}

// UserClaimsFromContext returns the UserClaims from context or nil.
func UserClaimsFromContext(ctx context.Context) *UserClaims {
	if ctx == nil {
		return nil
	}
	claims, ok := ctx.Value(UserClaimsKey).(*UserClaims)
	if !ok {
		return nil
	}
	return claims
}
