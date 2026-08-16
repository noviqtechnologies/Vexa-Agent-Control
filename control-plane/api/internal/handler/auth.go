package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/session"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/store"
	"golang.org/x/oauth2"
)

var (
	// BootstrapToken is set dynamically if no auth is configured.
	BootstrapToken string
)

type AuthHandler struct {
	store *store.Store
}

func NewAuthHandler(s *store.Store) *AuthHandler {
	return &AuthHandler{store: s}
}

type LoginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	saasOpEmail := os.Getenv("SAAS_OPERATOR_EMAIL")
	isSaaSOperator := false
	if saasOpEmail != "" && strings.EqualFold(req.Email, saasOpEmail) {
		isSaaSOperator = true
	}

	// 1. Check Per-Tenant Bootstrap Token
	org, err := h.store.ResolveBootstrapToken(r.Context(), req.Password)
	if err == nil && org != nil {
		_ = h.store.ConsumeBootstrapToken(r.Context(), org.ID)
		userID := req.Email
		if userID == "" {
			userID = "admin"
		}
		// Upsert local user profile for this tenant
		_ = h.store.UpsertUser(r.Context(), &model.User{
			TenantID: org.ID,
			Email:    userID,
			IsAdmin:  true,
		})

		h.setSessionCookie(w, r, org.ID, userID, true, isSaaSOperator)
		json.NewEncoder(w).Encode(map[string]any{
			"status":               "ok",
			"user_id":              userID,
			"tenant_id":            org.ID,
			"organization_name":    org.Name,
			"is_admin":             true,
			"is_saas_operator":     isSaaSOperator,
			"needs_password_setup": true,
		})
		return
	}

	// 2. Check Global Bootstrap Token, Secret Manager Session Secret, or SAAS_OPERATOR_PASSWORD
	saasOpPassword := os.Getenv("SAAS_OPERATOR_PASSWORD")
	sessionSecret := os.Getenv("AGENTWALL_SESSION_SECRET")
	isDevMode := os.Getenv("DEV_MODE") == "true"
	
	isSecretMatch := (BootstrapToken != "" && req.Password == BootstrapToken) ||
		(saasOpPassword != "" && req.Password == saasOpPassword) ||
		(sessionSecret != "" && req.Password == sessionSecret)

	isPlatformEmail := req.Email == "admin" || req.Email == "operator" || req.Email == "admin@example.com" || (saasOpEmail != "" && strings.EqualFold(req.Email, saasOpEmail))

	if (isSecretMatch || isDevMode) && isPlatformEmail {
		h.setSessionCookie(w, r, middleware.DefaultTenantID, req.Email, true, true)
		json.NewEncoder(w).Encode(map[string]any{
			"status":               "ok",
			"user_id":              req.Email,
			"tenant_id":            middleware.DefaultTenantID,
			"organization_name":    "Platform Management",
			"is_admin":             true,
			"is_saas_operator":     true,
			"needs_password_setup": false,
		})
		return
	}

	// 3. Check Local User Password Login (Multi-Tenant)
	u, err := h.store.GetUserByEmailOnly(r.Context(), req.Email)
	if err == nil && u != nil && u.PasswordHash != "" {
		ok, err := VerifyPassword(req.Password, u.PasswordHash)
		if err == nil && ok {
			tenantID := u.TenantID
			if tenantID == "" {
				tenantID = middleware.DefaultTenantID
			}
			if u.IsSaaSOperator || isSaaSOperator {
				isSaaSOperator = true
			}

			h.setSessionCookie(w, r, tenantID, u.Email, u.IsAdmin, isSaaSOperator)
			json.NewEncoder(w).Encode(map[string]any{
				"status":               "ok",
				"user_id":              u.Email,
				"tenant_id":            tenantID,
				"is_admin":             u.IsAdmin,
				"is_saas_operator":     isSaaSOperator,
				"needs_password_setup": false,
			})
			return
		}
	}

	http.Error(w, "invalid credentials", http.StatusUnauthorized)
}

func isRequestSecure(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	if strings.HasPrefix(r.Header.Get("Origin"), "https://") || strings.HasPrefix(r.Header.Get("Referer"), "https://") {
		return true
	}
	return false
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	isSecure := isRequestSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     "agentwall_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusOK)
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims := middleware.UserClaimsFromContext(r.Context())
	if claims == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	orgName := "Platform Management"
	if claims.TenantID != "" && claims.TenantID != middleware.DefaultTenantID {
		org, err := h.store.GetOrganization(r.Context(), claims.TenantID)
		if err == nil && org != nil {
			orgName = org.Name
		} else {
			orgName = "Organization Workspace"
		}
	}

	needsPasswordSetup := false
	if claims.TenantID != "" && claims.TenantID != middleware.DefaultTenantID {
		u, err := h.store.GetUserByEmail(r.Context(), claims.TenantID, "", claims.UserID)
		if err == nil {
			if u == nil || u.PasswordHash == "" {
				needsPasswordSetup = true
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"user_id":              claims.UserID,
		"tenant_id":            claims.TenantID,
		"organization_name":    orgName,
		"is_admin":             claims.IsAdmin,
		"is_saas_operator":     claims.IsSaaSOperator,
		"needs_password_setup": needsPasswordSetup,
	})
}

type SetupInitialPasswordReq struct {
	Password string `json:"password"`
}

func (h *AuthHandler) SetupInitialPassword(w http.ResponseWriter, r *http.Request) {
	claims := middleware.UserClaimsFromContext(r.Context())
	if claims == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	var req SetupInitialPasswordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	req.Password = strings.TrimSpace(req.Password)
	if len(req.Password) < 8 {
		http.Error(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	hash, err := hashPassword(req.Password)
	if err != nil {
		http.Error(w, "failed to hash password", http.StatusInternalServerError)
		return
	}

	tenantID := claims.TenantID
	if tenantID == "" {
		tenantID = middleware.DefaultTenantID
	}

	// 1. Ensure a Local Auth Provider exists and is enabled for this tenant
	localProvider, _ := h.store.GetAuthProviderByType(r.Context(), tenantID, "local")
	var authProviderID string
	if localProvider != nil {
		authProviderID = localProvider.ID
		if !localProvider.Enabled {
			localProvider.Enabled = true
			_ = h.store.UpsertAuthProvider(r.Context(), tenantID, localProvider)
		}
	} else {
		newLocal := &model.AuthProvider{
			Type:         "local",
			Name:         "Local Authentication",
			Enabled:      true,
			EmailDomains: []string{"*"},
		}
		if err := h.store.UpsertAuthProvider(r.Context(), tenantID, newLocal); err == nil {
			authProviderID = newLocal.ID
		}
	}

	// 2. Upsert the User record with the password hash and local auth provider
	user := &model.User{
		TenantID:       tenantID,
		AuthProviderID: authProviderID,
		Email:          claims.UserID,
		PasswordHash:   hash,
		IsAdmin:        claims.IsAdmin,
		IsSaaSOperator: claims.IsSaaSOperator,
	}

	if err := h.store.UpsertUser(r.Context(), user); err != nil {
		http.Error(w, fmt.Sprintf("failed to save user password: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":               "ok",
		"user_id":              claims.UserID,
		"tenant_id":            tenantID,
		"needs_password_setup": false,
	})
}

func (h *AuthHandler) setSessionCookie(w http.ResponseWriter, r *http.Request, tenantID, userID string, isAdmin, isSaaSOperator bool) {
	cookieValue := session.Create(tenantID, userID, isAdmin, isSaaSOperator)
	isSecure := isRequestSecure(r)

	http.SetCookie(w, &http.Cookie{
		Name:     "agentwall_session",
		Value:    cookieValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(session.SessionDuration.Seconds()),
	})
}

func GenerateBootstrapToken() string {
	b := make([]byte, 8)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (h *AuthHandler) CheckBootstrap() {
	if opPass := os.Getenv("SAAS_OPERATOR_PASSWORD"); opPass != "" {
		BootstrapToken = opPass
		log.Printf("INFO: SaaS Platform Operator password loaded from SAAS_OPERATOR_PASSWORD.")
		return
	}

	if sessSec := os.Getenv("AGENTWALL_SESSION_SECRET"); sessSec != "" {
		BootstrapToken = sessSec
		log.Printf("INFO: SaaS Platform Super-Admin Master Secret loaded from Secret Manager.")
		return
	}

	// Always ensure a BootstrapToken exists for platform super-admin access
	if BootstrapToken == "" {
		BootstrapToken = GenerateBootstrapToken()
		log.Printf("=========================================================")
		log.Printf("INFO: SaaS Platform Super-Admin Bootstrap Secret: %s", BootstrapToken)
		log.Printf("INFO: Use Email/Username 'admin' and this secret to log in.")
		log.Printf("=========================================================")
	}
}

type PublicProvider struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

func (h *AuthHandler) ListPublicProviders(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	providers, err := h.store.ListAuthProviders(r.Context(), tenantID)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	public := []PublicProvider{}
	for _, p := range providers {
		if p.Enabled {
			public = append(public, PublicProvider{ID: p.ID, Type: p.Type, Name: p.Name})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(public)
}

func getOAuthConfig(p *model.AuthProvider, host string) *oauth2.Config {
	scheme := "http"
	if !strings.HasPrefix(host, "localhost") && !strings.HasPrefix(host, "127.0.0.1") {
		scheme = "https"
	}
	redirectURL := fmt.Sprintf("%s://%s/api/v1/auth/oauth/%s/callback", scheme, host, p.ID)
	
	var endpoint oauth2.Endpoint
	var scopes []string
	if p.Type == "google" {
		endpoint = oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		}
		scopes = []string{"https://www.googleapis.com/auth/userinfo.email"}
	} else if p.Type == "entra" {
		tenant := "common"
		if p.IssuerURL != "" {
			tenant = strings.TrimSpace(p.IssuerURL)
		}
		endpoint = oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", tenant),
			TokenURL: fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant),
		}
		scopes = []string{"openid", "email", "profile", "User.Read"}
	}
	
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     endpoint,
		Scopes:       scopes,
	}
}

func (h *AuthHandler) OAuthLogin(w http.ResponseWriter, r *http.Request) {
	providerID := chi.URLParam(r, "provider_id")
	provider, err := h.store.GetAuthProvider(r.Context(), "", providerID)
	if err != nil || provider == nil || !provider.Enabled {
		http.Error(w, "provider not found", http.StatusNotFound)
		return
	}
	
	conf := getOAuthConfig(provider, r.Host)
	
	stateBytes := make([]byte, 16)
	rand.Read(stateBytes)
	state := base64.URLEncoding.EncodeToString(stateBytes)
	
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   300,
	})
	
	url := conf.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *AuthHandler) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	providerID := chi.URLParam(r, "provider_id")
	provider, err := h.store.GetAuthProvider(r.Context(), "", providerID)
	if err != nil || provider == nil || !provider.Enabled {
		http.Error(w, "provider not found", http.StatusNotFound)
		return
	}
	
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || r.FormValue("state") != stateCookie.Value {
		http.Error(w, "invalid oauth state", http.StatusBadRequest)
		return
	}
	
	conf := getOAuthConfig(provider, r.Host)
	code := r.FormValue("code")
	tok, err := conf.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "oauth exchange failed", http.StatusInternalServerError)
		return
	}
	
	client := conf.Client(r.Context(), tok)
	var email string
	
	if provider.Type == "google" {
		resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
		if err == nil {
			defer resp.Body.Close()
			var user struct{ Email string `json:"email"` }
			json.NewDecoder(resp.Body).Decode(&user)
			email = user.Email
		}
	} else if provider.Type == "entra" {
		resp, err := client.Get("https://graph.microsoft.com/v1.0/me")
		if err == nil {
			defer resp.Body.Close()
			var user struct {
				Mail              string `json:"mail"`
				UserPrincipalName string `json:"userPrincipalName"`
			}
			json.NewDecoder(resp.Body).Decode(&user)
			if user.Mail != "" {
				email = user.Mail
			} else {
				email = user.UserPrincipalName
			}
		}
	}
	
	if email == "" {
		http.Error(w, "could not retrieve email from provider", http.StatusBadRequest)
		return
	}
	
	domainAllowed := false
	for _, d := range provider.EmailDomains {
		if d == "*" || strings.HasSuffix(email, "@"+d) || strings.HasSuffix(email, d) {
			domainAllowed = true
			break
		}
	}
	if !domainAllowed {
		http.Error(w, "domain not allowed", http.StatusForbidden)
		return
	}
	
	tenantID := provider.TenantID
	if tenantID == "" {
		tenantID = middleware.DefaultTenantID
	}

	user, err := h.store.GetUserByEmail(r.Context(), tenantID, providerID, email)
	if err != nil || user == nil {
		user = &model.User{
			TenantID:       tenantID,
			AuthProviderID: providerID,
			Email:          email,
			PasswordHash:   "",
			IsAdmin:        false,
		}
		if err := h.store.UpsertUser(r.Context(), user); err != nil {
			http.Error(w, "failed to auto-provision user", http.StatusInternalServerError)
			return
		}
		user, _ = h.store.GetUserByEmail(r.Context(), tenantID, providerID, email)
	}
	
	saasOpEmail := os.Getenv("SAAS_OPERATOR_EMAIL")
	isSaaSOperator := user.IsSaaSOperator || (saasOpEmail != "" && strings.EqualFold(email, saasOpEmail))

	h.setSessionCookie(w, r, tenantID, user.ID, user.IsAdmin, isSaaSOperator)
	
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
	})
	
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
