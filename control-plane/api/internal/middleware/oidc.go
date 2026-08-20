package middleware

import (
	"context"
	"crypto/subtle"
	"log"
	"net/http"
	"strings"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/session"
)

type contextKey string

const UserClaimsKey contextKey = "user_claims"

type UserClaims struct {
	TenantID       string `json:"tenant_id"`
	UserID         string `json:"user_id"`
	IsAdmin        bool   `json:"is_admin"`
	IsSaaSOperator bool   `json:"is_saas_operator"`
}

// PolicyReadAuth validates either the gateway PolicyReadSecret Bearer token
// or the operator agentcontrol_session cookie. Fails closed if secret is empty.
func PolicyReadAuth(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check Bearer token (gateway read secret)
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				token := strings.TrimPrefix(auth, "Bearer ")
				if secret != "" && subtle.ConstantTimeCompare([]byte(token), []byte(secret)) == 1 {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Fallback to session cookie (dashboard operators)
			cookie, err := r.Cookie("agentcontrol_session")
			if err != nil {
				cookie, err = r.Cookie("agentwall_session")
			}
			if err == nil {
				sess, err := session.Validate(cookie.Value)
				if err == nil {
					claims := UserClaims{
						TenantID:       sess.TenantID,
						UserID:         sess.UserID,
						IsAdmin:        sess.IsAdmin,
						IsSaaSOperator: sess.IsSaaSOperator,
					}
					ctx := context.WithValue(r.Context(), UserClaimsKey, &claims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		})
	}
}

// DashboardAuth validates the agentcontrol_session cookie for dashboard operators.
func DashboardAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("agentcontrol_session")
			if err != nil {
				cookie, err = r.Cookie("agentwall_session")
			}
			if err != nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			sess, err := session.Validate(cookie.Value)
			if err != nil {
				http.Error(w, `{"error":"invalid session"}`, http.StatusUnauthorized)
				return
			}

			claims := UserClaims{
				TenantID:       sess.TenantID,
				UserID:         sess.UserID,
				IsAdmin:        sess.IsAdmin,
				IsSaaSOperator: sess.IsSaaSOperator,
			}
			ctx := context.WithValue(r.Context(), UserClaimsKey, &claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// DeviceValidator is an interface for validating enrolled device IDs/tokens.
type DeviceValidator interface {
	ValidateDeviceToken(ctx context.Context, token string) bool
	ResolveDevicePrincipal(ctx context.Context, token string) (*model.DevicePrincipal, bool)
}

// GatewayAuth validates either:
// 1. The shared HMAC secret the gateway uses (GATEWAY_SECRET)
// 2. An enrolled device token or device ID in the database
func GatewayAuth(secret string, validator ...DeviceValidator) func(http.Handler) http.Handler {
	var v DeviceValidator
	if len(validator) > 0 {
		v = validator[0]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, `{"error":"missing gateway token"}`, http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(auth, "Bearer ")

			if secret != "" && subtle.ConstantTimeCompare([]byte(token), []byte(secret)) == 1 {
				next.ServeHTTP(w, r)
				return
			}

			if v != nil {
				if principal, ok := v.ResolveDevicePrincipal(r.Context(), token); ok && principal != nil {
					ctx := context.WithValue(r.Context(), DevicePrincipalKey, principal)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				if v.ValidateDeviceToken(r.Context(), token) {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, `{"error":"invalid gateway token"}`, http.StatusForbidden)
		})
	}
}

// RequireAdmin enforces that the authenticated user has IsAdmin = true.
// DashboardAuth must have run prior to this middleware.
func RequireAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, _ := r.Context().Value(UserClaimsKey).(*UserClaims)
			if claims == nil {
				log.Printf("RequireAdmin denied: no claims found")
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			if !claims.IsAdmin && !claims.IsSaaSOperator {
				log.Printf("RequireAdmin denied: user_id=%s is_admin=%v", claims.UserID, claims.IsAdmin)
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
