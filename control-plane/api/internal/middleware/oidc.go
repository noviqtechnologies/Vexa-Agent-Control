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

// LegacyAuthConfig configures single-tenant legacy secret compatibility.
type LegacyAuthConfig struct {
	LegacySingleTenantMode bool
	LegacyTenantID         string
}

// PolicyReadAuth validates either the gateway PolicyReadSecret Bearer token
// (when LegacySingleTenantMode is active) or the operator agentcontrol_session cookie.
// Fails closed if secret is empty or if unauthenticated in multi-tenant mode.
func PolicyReadAuth(secret string, legacyAuth ...LegacyAuthConfig) func(http.Handler) http.Handler {
	var cfg LegacyAuthConfig
	if len(legacyAuth) > 0 {
		cfg = legacyAuth[0]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check Bearer token (gateway read secret)
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				token := strings.TrimPrefix(auth, "Bearer ")
				if secret != "" && subtle.ConstantTimeCompare([]byte(token), []byte(secret)) == 1 {
					if cfg.LegacySingleTenantMode && cfg.LegacyTenantID != "" {
						principal := &RequestPrincipal{
							TenantID:  cfg.LegacyTenantID,
							AuthnType: AuthnTypeLegacySecret,
						}
						ctx := context.WithValue(r.Context(), RequestPrincipalKey, principal)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
					// In multi-tenant mode, shared secret without bound tenancy is rejected
					http.Error(w, `{"error":"unauthorized_multi_tenant_secret_disabled"}`, http.StatusUnauthorized)
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
					principal := &RequestPrincipal{
						TenantID:       sess.TenantID,
						SubjectID:      sess.UserID,
						AuthnType:      AuthnTypeSession,
						IsAdmin:        sess.IsAdmin,
						IsSaaSOperator: sess.IsSaaSOperator,
					}
					ctx := context.WithValue(r.Context(), UserClaimsKey, &claims)
					ctx = context.WithValue(ctx, RequestPrincipalKey, principal)
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
			principal := &RequestPrincipal{
				TenantID:       sess.TenantID,
				SubjectID:      sess.UserID,
				AuthnType:      AuthnTypeSession,
				IsAdmin:        sess.IsAdmin,
				IsSaaSOperator: sess.IsSaaSOperator,
			}
			ctx := context.WithValue(r.Context(), UserClaimsKey, &claims)
			ctx = context.WithValue(ctx, RequestPrincipalKey, principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SessionAuthOptional extracts and validates the session cookie if present,
// populating UserClaims in context without failing requests if no session is provided.
func SessionAuthOptional() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("agentcontrol_session")
			if err != nil {
				cookie, err = r.Cookie("agentwall_session")
			}
			if err == nil && cookie != nil && cookie.Value != "" {
				if sess, err := session.Validate(cookie.Value); err == nil && sess != nil {
					claims := UserClaims{
						TenantID:       sess.TenantID,
						UserID:         sess.UserID,
						IsAdmin:        sess.IsAdmin,
						IsSaaSOperator: sess.IsSaaSOperator,
					}
					principal := &RequestPrincipal{
						TenantID:       sess.TenantID,
						SubjectID:      sess.UserID,
						AuthnType:      AuthnTypeSession,
						IsAdmin:        sess.IsAdmin,
						IsSaaSOperator: sess.IsSaaSOperator,
					}
					ctx := context.WithValue(r.Context(), UserClaimsKey, &claims)
					ctx = context.WithValue(ctx, RequestPrincipalKey, principal)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// DeviceValidator is an interface for validating enrolled device IDs/tokens.
type DeviceValidator interface {
	ValidateDeviceToken(ctx context.Context, token string) bool
	ResolveDevicePrincipal(ctx context.Context, token string) (*model.DevicePrincipal, bool)
}

// GatewayAuth validates either:
// 1. An enrolled device token or device ID in the database (resolving authoritative device principal & tenant)
// 2. The shared HMAC secret (GATEWAY_SECRET) ONLY when LegacySingleTenantMode is active with a configured LegacyTenantID
func GatewayAuth(secret string, validator DeviceValidator, legacyAuth ...LegacyAuthConfig) func(http.Handler) http.Handler {
	var cfg LegacyAuthConfig
	if len(legacyAuth) > 0 {
		cfg = legacyAuth[0]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, `{"error":"missing gateway token"}`, http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(auth, "Bearer ")

			// 1. Check enrolled device identity
			if validator != nil {
				if principal, ok := validator.ResolveDevicePrincipal(r.Context(), token); ok && principal != nil {
					reqPrincipal := &RequestPrincipal{
						TenantID:     principal.TenantID,
						DeviceID:     principal.DeviceID,
						AuthnType:    AuthnTypeDeviceToken,
						Capabilities: principal.Capabilities,
					}
					ctx := context.WithValue(r.Context(), DevicePrincipalKey, principal)
					ctx = context.WithValue(ctx, RequestPrincipalKey, reqPrincipal)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// 2. Check legacy shared secret ONLY if legacy single tenant mode is explicitly enabled
			if cfg.LegacySingleTenantMode && cfg.LegacyTenantID != "" {
				if secret != "" && subtle.ConstantTimeCompare([]byte(token), []byte(secret)) == 1 {
					principal := &RequestPrincipal{
						TenantID:  cfg.LegacyTenantID,
						AuthnType: AuthnTypeLegacySecret,
					}
					ctx := context.WithValue(r.Context(), RequestPrincipalKey, principal)
					next.ServeHTTP(w, r.WithContext(ctx))
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
