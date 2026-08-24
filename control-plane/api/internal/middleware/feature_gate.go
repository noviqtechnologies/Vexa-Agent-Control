package middleware

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/license"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type featureGateContextKey string

const claimsContextKey featureGateContextKey = "license_claims"

// WithClaims injects license claims into the request context.
func WithClaims(claims *license.Claims) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClaims extracts license claims from the request context.
func GetClaims(r *http.Request) *license.Claims {
	if c, ok := r.Context().Value(claimsContextKey).(*license.Claims); ok {
		return c
	}
	return nil
}

// RequireFeature returns HTTP 403 Forbidden if the active license does not contain the required feature flag.
func RequireFeature(requiredFeature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r)
			if claims == nil || !hasFeature(claims, requiredFeature) {
				respondFeatureForbidden(w, requiredFeature, getTier(claims))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireTenantFeature resolves tenant from context/store and verifies feature flag entitlement.
func RequireTenantFeature(st *store.Store, requiredFeature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Direct claims in context
			if claims := GetClaims(r); claims != nil {
				if hasFeature(claims, requiredFeature) {
					next.ServeHTTP(w, r)
					return
				}
				respondFeatureForbidden(w, requiredFeature, getTier(claims))
				return
			}

			// 2. If user is SaaS operator, permit
			if IsSaaSOperatorFromContext(r.Context()) {
				next.ServeHTTP(w, r)
				return
			}

			// 3. Resolve tenant and check license tier in DB
			if st != nil {
				tenantID := ResolveTenantScope(r)
				org, err := st.GetOrganization(r.Context(), tenantID)
				if err == nil && org != nil {
					tierFeatures := license.TierToFeatures(org.LicenseTier)
					tempClaims := &license.Claims{
						OrgID:    org.Slug,
						Tier:     org.LicenseTier,
						Features: tierFeatures,
					}
					if hasFeature(tempClaims, requiredFeature) {
						ctx := context.WithValue(r.Context(), claimsContextKey, tempClaims)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
					respondFeatureForbidden(w, requiredFeature, org.LicenseTier)
					return
				}
			}

			// Fallback: deny if unentitled
			respondFeatureForbidden(w, requiredFeature, "community")
		})
	}
}

func respondFeatureForbidden(w http.ResponseWriter, requiredFeature, tier string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":            "feature_not_licensed",
		"required_feature": requiredFeature,
		"tier":             tier,
		"message":          "This feature requires an upgraded VexaSec Team or Enterprise license.",
	})
}

func hasFeature(c *license.Claims, feature string) bool {
	if c == nil {
		return false
	}
	for _, f := range c.Features {
		if f == feature || f == "*" || f == "all" {
			return true
		}
		if (feature == "spend_caps" || feature == "spend_v2") && (f == "spend_caps" || f == "spend_v2") {
			return true
		}
		if (feature == "siem_export" || feature == "siem_aggregation") && (f == "siem_export" || f == "siem_aggregation") {
			return true
		}
	}
	return false
}

func getTier(c *license.Claims) string {
	if c != nil && c.Tier != "" {
		return c.Tier
	}
	return "community"
}
