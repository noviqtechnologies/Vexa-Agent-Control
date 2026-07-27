package middleware

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/session"
)

type contextKey string

const UserClaimsKey contextKey = "user_claims"

type UserClaims struct {
	UserID  string `json:"user_id"`
	IsAdmin bool   `json:"is_admin"`
}

// DashboardAuth validates the agentwall_session cookie for dashboard operators.
func DashboardAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("agentwall_session")
			if err != nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			userID, isAdmin, err := session.Validate(cookie.Value)
			if err != nil {
				http.Error(w, `{"error":"invalid session"}`, http.StatusUnauthorized)
				return
			}

			claims := UserClaims{
				UserID:  userID,
				IsAdmin: isAdmin,
			}
			ctx := context.WithValue(r.Context(), UserClaimsKey, &claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
// GatewayAuth validates the shared HMAC secret the gateway uses for
// ingest endpoints. Dashboard operators never use this path.
func GatewayAuth(secret string) func(http.Handler) http.Handler {
	if secret == "" {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, `{"error":"missing gateway token"}`, http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(auth, "Bearer ")

			if subtle.ConstantTimeCompare([]byte(token), []byte(secret)) != 1 {
				http.Error(w, `{"error":"invalid gateway token"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
