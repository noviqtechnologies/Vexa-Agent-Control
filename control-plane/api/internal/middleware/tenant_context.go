package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

// DefaultTenantID is the UUID for the default seeded tenant.
const DefaultTenantID = "00000000-0000-0000-0000-000000000001"

// ErrUnauthenticatedTenantScope is returned when an operation requires an authenticated tenant context.
var ErrUnauthenticatedTenantScope = errors.New("unauthenticated tenant scope")

// AuthnType describes how the caller authenticated.
type AuthnType string

const (
	AuthnTypeSession      AuthnType = "session"
	AuthnTypeMTLS         AuthnType = "mtls"
	AuthnTypeDeviceToken  AuthnType = "device_token"
	AuthnTypeLegacySecret AuthnType = "legacy_secret"
)

// RequestPrincipal represents the unified, verified identity and tenancy context of an inbound request.
type RequestPrincipal struct {
	TenantID       string    `json:"tenant_id"`
	SubjectID      string    `json:"subject_id,omitempty"`
	DeviceID       string    `json:"device_id,omitempty"`
	AuthnType      AuthnType `json:"authn_type"`
	IsAdmin        bool      `json:"is_admin"`
	IsSaaSOperator bool      `json:"is_saas_operator"`
	Capabilities   []string  `json:"capabilities,omitempty"`
}

const RequestPrincipalKey contextKey = "request_principal"

// RequestPrincipalFromContext extracts the RequestPrincipal from context or nil.
func RequestPrincipalFromContext(ctx context.Context) *RequestPrincipal {
	if ctx == nil {
		return nil
	}
	p, ok := ctx.Value(RequestPrincipalKey).(*RequestPrincipal)
	if ok && p != nil {
		return p
	}
	// Derive from UserClaims if present
	if claims, ok := ctx.Value(UserClaimsKey).(*UserClaims); ok && claims != nil {
		return &RequestPrincipal{
			TenantID:       claims.TenantID,
			SubjectID:      claims.UserID,
			AuthnType:      AuthnTypeSession,
			IsAdmin:        claims.IsAdmin,
			IsSaaSOperator: claims.IsSaaSOperator,
		}
	}
	// Derive from DevicePrincipal if present
	if dev, ok := ctx.Value(DevicePrincipalKey).(*model.DevicePrincipal); ok && dev != nil {
		return &RequestPrincipal{
			TenantID:     dev.TenantID,
			DeviceID:     dev.DeviceID,
			AuthnType:    AuthnTypeMTLS,
			Capabilities: dev.Capabilities,
		}
	}
	return nil
}

// RequireTenantPrincipal enforces that a valid RequestPrincipal with non-empty TenantID exists in context.
func RequireTenantPrincipal(ctx context.Context) (*RequestPrincipal, error) {
	p := RequestPrincipalFromContext(ctx)
	if p == nil || p.TenantID == "" {
		return nil, ErrUnauthenticatedTenantScope
	}
	return p, nil
}

// TenantIDFromContext extracts the tenant UUID from the RequestPrincipal, UserClaims, or DevicePrincipal in context.
// Returns DefaultTenantID only if no tenant claim is found.
func TenantIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return DefaultTenantID
	}
	if p := RequestPrincipalFromContext(ctx); p != nil && p.TenantID != "" {
		return p.TenantID
	}
	if claims, ok := ctx.Value(UserClaimsKey).(*UserClaims); ok && claims != nil && claims.TenantID != "" {
		return claims.TenantID
	}
	if dev, ok := ctx.Value(DevicePrincipalKey).(*model.DevicePrincipal); ok && dev != nil && dev.TenantID != "" {
		return dev.TenantID
	}
	return DefaultTenantID
}

// ResolveAuthenticatedTenantScope resolves the authoritative tenant ID from verified credentials only.
// Client-supplied headers (X-Organization-ID / X-Tenant-ID) are strictly rejected unless the principal
// holds verified elevated SaaS Operator permissions (claims.IsSaaSOperator == true).
func ResolveAuthenticatedTenantScope(r *http.Request) (string, error) {
	if r == nil {
		return "", ErrUnauthenticatedTenantScope
	}
	ctx := r.Context()

	// 1. Check RequestPrincipal
	if p := RequestPrincipalFromContext(ctx); p != nil && p.TenantID != "" {
		if p.IsSaaSOperator {
			headerOrg := r.Header.Get("X-Organization-ID")
			if headerOrg == "" {
				headerOrg = r.Header.Get("X-Tenant-ID")
			}
			if headerOrg != "" {
				return headerOrg, nil
			}
		}
		return p.TenantID, nil
	}

	// 2. Check Device Principal (mTLS authenticated device)
	if dev, ok := ctx.Value(DevicePrincipalKey).(*model.DevicePrincipal); ok && dev != nil && dev.TenantID != "" {
		return dev.TenantID, nil
	}

	// 3. Check User Claims (Dashboard operator)
	if claims, ok := ctx.Value(UserClaimsKey).(*UserClaims); ok && claims != nil {
		// Elevated SaaS Operators can explicitly specify a target tenant via header
		if claims.IsSaaSOperator {
			headerOrg := r.Header.Get("X-Organization-ID")
			if headerOrg == "" {
				headerOrg = r.Header.Get("X-Tenant-ID")
			}
			if headerOrg != "" {
				return headerOrg, nil
			}
		}
		if claims.TenantID != "" {
			return claims.TenantID, nil
		}
	}

	return "", ErrUnauthenticatedTenantScope
}

// ResolveTenantScope safely resolves the tenant ID, returning DefaultTenantID if unauthenticated,
// without allowing unauthenticated requests to inject arbitrary tenant scopes via headers.
func ResolveTenantScope(r *http.Request) string {
	tid, err := ResolveAuthenticatedTenantScope(r)
	if err == nil && tid != "" {
		return tid
	}
	return DefaultTenantID
}

// IsSaaSOperatorFromContext returns true if the authenticated user is a SaaS operator.
func IsSaaSOperatorFromContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	if p := RequestPrincipalFromContext(ctx); p != nil {
		return p.IsSaaSOperator
	}
	claims, ok := ctx.Value(UserClaimsKey).(*UserClaims)
	if !ok || claims == nil {
		return false
	}
	return claims.IsSaaSOperator
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


