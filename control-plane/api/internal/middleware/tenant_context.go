package middleware

import (
	"context"
	"net/http"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

// DefaultTenantID is the UUID for the default seeded tenant.
const DefaultTenantID = "00000000-0000-0000-0000-000000000001"

// TenantIDFromContext extracts the tenant UUID from the UserClaims or DevicePrincipal in context.
// Returns DefaultTenantID if no tenant claim is found.
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

// ResolveTenantScope securely resolves the tenant ID for an incoming HTTP request.
// Standard tenant sessions (Admins, Members, Guests) are strictly bound to their claims.TenantID.
// Client-supplied headers (X-Organization-ID / X-Tenant-ID) are only honored if the caller
// explicitly holds verified elevated SaaS Operator permissions (claims.IsSaaSOperator == true).
func ResolveTenantScope(r *http.Request) string {
	if r == nil {
		return DefaultTenantID
	}
	ctx := r.Context()

	// 1. Check Device Principal (mTLS authenticated device)
	if dev, ok := ctx.Value(DevicePrincipalKey).(*model.DevicePrincipal); ok && dev != nil && dev.TenantID != "" {
		return dev.TenantID
	}

	// 2. Check User Claims (Dashboard operator)
	if claims, ok := ctx.Value(UserClaimsKey).(*UserClaims); ok && claims != nil {
		// Only elevated SaaS Operators can override tenant scope via header
		if claims.IsSaaSOperator {
			headerOrg := r.Header.Get("X-Organization-ID")
			if headerOrg == "" {
				headerOrg = r.Header.Get("X-Tenant-ID")
			}
			if headerOrg != "" {
				return headerOrg
			}
		}
		if claims.TenantID != "" {
			return claims.TenantID
		}
	}

	// 3. Fallback for unauthenticated endpoints or background workers
	headerOrg := r.Header.Get("X-Organization-ID")
	if headerOrg == "" {
		headerOrg = r.Header.Get("X-Tenant-ID")
	}
	if headerOrg != "" {
		return headerOrg
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
