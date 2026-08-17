package middleware

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/license"
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
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":            "feature_not_licensed",
					"required_feature": requiredFeature,
					"tier":             getTier(claims),
					"message":          "This feature requires an upgraded VexaSec Team or Enterprise license.",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func hasFeature(c *license.Claims, feature string) bool {
	if c == nil {
		return false
	}
	for _, f := range c.Features {
		if f == feature || f == "*" || f == "all" {
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
