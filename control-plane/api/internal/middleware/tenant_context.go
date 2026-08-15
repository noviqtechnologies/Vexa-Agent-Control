package middleware

import (
	"context"
)

// DefaultTenantID is the UUID for the default seeded tenant.
const DefaultTenantID = "00000000-0000-0000-0000-000000000001"

// TenantIDFromContext extracts the tenant UUID from the UserClaims in context.
// Returns DefaultTenantID if no tenant claim is found.
func TenantIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return DefaultTenantID
	}
	claims, ok := ctx.Value(UserClaimsKey).(*UserClaims)
	if !ok || claims == nil || claims.TenantID == "" {
		return DefaultTenantID
	}
	return claims.TenantID
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
