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

// TenantIDFromContext extracts the tenant UUID from the UserClaims or DevicePrincipal in context.
// Returns DefaultTenantID only if no tenant claim is found.
func TenantIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return DefaultTenantID
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

	// 1. Check Device Principal (mTLS authenticated device)
	if dev, ok := ctx.Value(DevicePrincipalKey).(*model.DevicePrincipal); ok && dev != nil && dev.TenantID != "" {
		return dev.TenantID, nil
	}

	// 2. Check User Claims (Dashboard operator)
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

