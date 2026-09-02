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

const UserClaimsKey contextKey = "user_claims"

type UserClaims struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"` // Alias for backward compatibility
	UserID         string `json:"user_id"`
	IsAdmin        bool   `json:"is_admin"`
	IsSaaSOperator bool   `json:"is_saas_operator"`
	Role           string `json:"role,omitempty"`
}

// LegacyAuthConfig configures single-tenant legacy secret compatibility.
type LegacyAuthConfig struct {
	LegacySingleTenantMode bool
	LegacyTenantID         string
}

// PolicyReadAuth validates either the gateway PolicyReadSecret Bearer token or the operator session cookie.
func PolicyReadAuth(secret string, legacyAuth ...LegacyAuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check Bearer token (gateway read secret)
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				token := strings.TrimPrefix(auth, "Bearer ")
				if secret != "" && subtle.ConstantTimeCompare([]byte(token), []byte(secret)) == 1 {
					principal := &RequestPrincipal{
						OrganizationID: DefaultOrganizationID,
						TenantID:       DefaultOrganizationID,
						AuthnType:      AuthnTypeLegacySecret,
					}
					ctx := context.WithValue(r.Context(), RequestPrincipalKey, principal)
					next.ServeHTTP(w, r.WithContext(ctx))
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
					orgID := sess.TenantID
					if orgID == "" {
						orgID = DefaultOrganizationID
					}
					claims := UserClaims{
						OrganizationID: orgID,
						TenantID:       orgID,
						UserID:         sess.UserID,
						IsAdmin:        sess.IsAdmin,
					}
					principal := &RequestPrincipal{
						OrganizationID: orgID,
						TenantID:       orgID,
						SubjectID:      sess.UserID,
						AuthnType:      AuthnTypeSession,
						IsAdmin:        sess.IsAdmin,
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

			orgID := sess.TenantID
			if orgID == "" {
				orgID = DefaultOrganizationID
			}
			claims := UserClaims{
				OrganizationID: orgID,
				TenantID:       orgID,
				UserID:         sess.UserID,
				IsAdmin:        sess.IsAdmin,
			}
			principal := &RequestPrincipal{
				OrganizationID: orgID,
				TenantID:       orgID,
				SubjectID:      sess.UserID,
				AuthnType:      AuthnTypeSession,
				IsAdmin:        sess.IsAdmin,
			}
			ctx := context.WithValue(r.Context(), UserClaimsKey, &claims)
			ctx = context.WithValue(ctx, RequestPrincipalKey, principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SessionAuthOptional extracts and validates the session cookie if present.
func SessionAuthOptional() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("agentcontrol_session")
			if err != nil {
				cookie, err = r.Cookie("agentwall_session")
			}
			if err == nil && cookie != nil && cookie.Value != "" {
				if sess, err := session.Validate(cookie.Value); err == nil && sess != nil {
					orgID := sess.TenantID
					if orgID == "" {
						orgID = DefaultOrganizationID
					}
					claims := UserClaims{
						OrganizationID: orgID,
						TenantID:       orgID,
						UserID:         sess.UserID,
						IsAdmin:        sess.IsAdmin,
					}
					principal := &RequestPrincipal{
						OrganizationID: orgID,
						TenantID:       orgID,
						SubjectID:      sess.UserID,
						AuthnType:      AuthnTypeSession,
						IsAdmin:        sess.IsAdmin,
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

// GatewayAuth validates enrolled device tokens or shared gateway secrets.
func GatewayAuth(secret string, validator DeviceValidator, legacyAuth ...LegacyAuthConfig) func(http.Handler) http.Handler {
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
					orgID := principal.OrganizationID
					if orgID == "" {
						orgID = DefaultOrganizationID
					}
					reqPrincipal := &RequestPrincipal{
						OrganizationID: orgID,
						TenantID:       orgID,
						DeviceID:       principal.DeviceID,
						AuthnType:      AuthnTypeDeviceToken,
						Capabilities:   principal.Capabilities,
					}
					ctx := context.WithValue(r.Context(), DevicePrincipalKey, principal)
					ctx = context.WithValue(ctx, RequestPrincipalKey, reqPrincipal)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// 2. Check gateway shared secret
			if secret != "" && subtle.ConstantTimeCompare([]byte(token), []byte(secret)) == 1 {
				principal := &RequestPrincipal{
					OrganizationID: DefaultOrganizationID,
					TenantID:       DefaultOrganizationID,
					AuthnType:      AuthnTypeLegacySecret,
				}
				ctx := context.WithValue(r.Context(), RequestPrincipalKey, principal)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			http.Error(w, `{"error":"invalid gateway token"}`, http.StatusForbidden)
		})
	}
}

// RequireAdmin enforces that the authenticated user is an administrator.
func RequireAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, _ := r.Context().Value(UserClaimsKey).(*UserClaims)
			if claims == nil {
				log.Printf("RequireAdmin denied: no claims found")
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			if !claims.IsAdmin {
				log.Printf("RequireAdmin denied: user_id=%s is_admin=%v", claims.UserID, claims.IsAdmin)
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
