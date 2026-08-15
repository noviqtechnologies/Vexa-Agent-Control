package middleware

import (
	"log"
	"net/http"
)

// RequireSaaSOperator enforces that the authenticated user has IsSaaSOperator = true.
func RequireSaaSOperator() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, _ := r.Context().Value(UserClaimsKey).(*UserClaims)
			if claims == nil {
				log.Printf("RequireSaaSOperator denied: no claims found")
				http.Error(w, `{"error":"forbidden: saas operator access required"}`, http.StatusForbidden)
				return
			}

			if !claims.IsSaaSOperator {
				log.Printf("RequireSaaSOperator denied: user_id=%s is not a saas operator", claims.UserID)
				http.Error(w, `{"error":"forbidden: saas operator access required"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
