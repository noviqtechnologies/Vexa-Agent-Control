package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/config"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/session"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func hashPassword(password string) (string, error) {
	return HashPassword(password)
}

func VerifyPassword(password, hash string) (bool, error) {
	if password == "" || hash == "" {
		return false, nil
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ── Account Linking State Store ──────────────────────────────────────────────

type LinkingChallenge struct {
	Token          string
	UserID         string
	Email          string
	OrganizationID string
	AuthProviderID string
	ProviderSub    string
	ProviderIssuer string
	ExpiresAt      time.Time
	FailedAttempts int
}

type BreakGlassRecord struct {
	Token          string
	OrganizationID string
	UserID         string
	Email          string
	ExpiresAt      time.Time
	Used           bool
}

type AuthHandler struct {
	store           *store.Store
	cfg             *config.Config
	linkingMu       sync.Mutex
	linkingStore    map[string]*LinkingChallenge
	breakGlassMu    sync.Mutex
	breakGlassStore map[string]*BreakGlassRecord
}

var globalBreakGlassStore = make(map[string]*BreakGlassRecord)
var globalBreakGlassMu sync.Mutex

func NewAuthHandler(s *store.Store, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		store:           s,
		cfg:             cfg,
		linkingStore:    make(map[string]*LinkingChallenge),
		breakGlassStore: make(map[string]*BreakGlassRecord),
	}
}

// GenerateBreakGlassToken generates a single-use 15-minute emergency recovery token.
func GenerateBreakGlassToken(orgID, userID, email string) (string, error) {
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	token := "bg_" + base64.RawURLEncoding.EncodeToString(bytes)

	globalBreakGlassMu.Lock()
	defer globalBreakGlassMu.Unlock()

	globalBreakGlassStore[token] = &BreakGlassRecord{
		Token:          token,
		OrganizationID: orgID,
		UserID:         userID,
		Email:          email,
		ExpiresAt:      time.Now().Add(15 * time.Minute),
		Used:           false,
	}

	return token, nil
}

type LoginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginReq
	contentType := r.Header.Get("Content-Type")
	isForm := strings.Contains(contentType, "application/x-www-form-urlencoded") || strings.Contains(contentType, "multipart/form-data")

	if isForm {
		_ = r.ParseForm()
		req.Email = r.FormValue("email")
		req.Password = r.FormValue("password")
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			_ = r.ParseForm()
			req.Email = r.FormValue("email")
			req.Password = r.FormValue("password")
			if req.Email == "" && req.Password == "" {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
		}
	}

	isJSON := !isForm
	req.Email = strings.TrimSpace(req.Email)
	req.Password = strings.TrimSpace(req.Password)

	isDevMode := h.cfg != nil && h.cfg.DevMode
	isDefaultPassword := req.Password == "admin123!" || req.Password == "admin" || req.Password == "admin12345678"
	isDefaultEmail := req.Email == "admin" || strings.EqualFold(req.Email, "admin@agentcontrol.local")

	// 1. Dedicated Control Hub Administrator Login (Single-Tenant)
	targetAdminEmail := ""
	targetAdminPassword := ""
	targetOrgName := "Primary Organization"
	targetOrgID := middleware.DefaultOrganizationID

	if h.cfg != nil {
		if h.cfg.AdminEmail != "" {
			targetAdminEmail = h.cfg.AdminEmail
		} else if h.cfg.TenantAdminEmail != "" {
			targetAdminEmail = h.cfg.TenantAdminEmail
		} else if h.cfg.ControlHubAdminEmail != "" {
			targetAdminEmail = h.cfg.ControlHubAdminEmail
		}

		if h.cfg.AdminPassword != "" {
			targetAdminPassword = h.cfg.AdminPassword
		} else if h.cfg.TenantAdminPassword != "" {
			targetAdminPassword = h.cfg.TenantAdminPassword
		} else if h.cfg.ControlHubAdminPassword != "" {
			targetAdminPassword = h.cfg.ControlHubAdminPassword
		}

		if h.cfg.OrganizationName != "" {
			targetOrgName = h.cfg.OrganizationName
		} else if h.cfg.TenantAdminOrgName != "" {
			targetOrgName = h.cfg.TenantAdminOrgName
		}

		if h.cfg.OrganizationID != "" {
			targetOrgID = h.cfg.OrganizationID
		}
	}

	if isDevMode {
		if targetAdminEmail == "" {
			targetAdminEmail = "admin@agentcontrol.local"
		}
		if targetAdminPassword == "" {
			targetAdminPassword = "admin12345678"
		}
	}

	isAdminLoginAttempt := false
	if targetAdminEmail != "" && strings.EqualFold(req.Email, targetAdminEmail) {
		isAdminLoginAttempt = true
	} else if isDevMode && (req.Email == "admin" || strings.EqualFold(req.Email, "admin@agentcontrol.local")) {
		isAdminLoginAttempt = true
	}

	// In production, block insecure default credentials
	if !isDevMode && (isDefaultPassword || isDefaultEmail) {
		if !isJSON {
			http.Redirect(w, r, "/login?error=insecure_default_credentials_blocked", http.StatusFound)
			return
		}
		http.Error(w, `{"error":"insecure_default_credentials_blocked","message":"Default credentials (admin / admin123!) are blocked in production cloud deployments. Please configure a secure password via ADMIN_PASSWORD or authenticate via your Identity Provider."}`, http.StatusUnauthorized)
		return
	}

	// Password match against configured Administrator password
	passwordMatches := false
	if isAdminLoginAttempt && targetAdminPassword != "" && req.Password == targetAdminPassword {
		passwordMatches = true
	}

	if passwordMatches {
		h.setSessionCookie(w, r, targetOrgID, req.Email, true, false)
		if !isJSON {
			returnTo := r.FormValue("return_to")
			if returnTo == "" {
				returnTo = r.URL.Query().Get("return_to")
			}
			if returnTo != "" && strings.HasPrefix(returnTo, "/") && !strings.HasPrefix(returnTo, "//") && !strings.Contains(returnTo, "\\") {
				http.Redirect(w, r, returnTo, http.StatusFound)
				return
			}
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":               "ok",
			"user_id":              req.Email,
			"organization_id":      targetOrgID,
			"organization_name":    targetOrgName,
			"is_admin":             true,
			"is_saas_operator":     false,
			"role":                 "OWNER",
			"needs_password_setup": false,
		})
		return
	}

	// 2. Database user verification
	if h.store != nil {
		user, err := h.store.GetUserByEmail(r.Context(), middleware.DefaultOrganizationID, "", req.Email)
		if err == nil && user != nil && user.PasswordHash != "" {
			ok, _ := VerifyPassword(req.Password, user.PasswordHash)
			if ok {
				orgName := "Primary Organization"
				org, _ := h.store.GetOrganization(r.Context(), user.OrganizationID)
				if org != nil && org.Name != "" {
					orgName = org.Name
				}
				h.setSessionCookie(w, r, user.OrganizationID, user.Email, user.IsAdmin, false)
				if !isJSON {
					returnTo := r.FormValue("return_to")
					if returnTo == "" {
						returnTo = r.URL.Query().Get("return_to")
					}
					if returnTo != "" && strings.HasPrefix(returnTo, "/") && !strings.HasPrefix(returnTo, "//") && !strings.Contains(returnTo, "\\") {
						http.Redirect(w, r, returnTo, http.StatusFound)
						return
					}
					http.Redirect(w, r, "/", http.StatusFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":               "ok",
					"user_id":              user.Email,
					"organization_id":      user.OrganizationID,
					"organization_name":    orgName,
					"is_admin":             user.IsAdmin,
					"is_saas_operator":     false,
					"role":                 user.Role,
					"needs_password_setup": false,
				})
				return
			}
		}
	}

	if !isJSON {
		returnTo := r.FormValue("return_to")
		if returnTo == "" {
			returnTo = r.URL.Query().Get("return_to")
		}
		failURL := "/login?error=invalid_credentials"
		if returnTo != "" {
			failURL = fmt.Sprintf("/login?error=invalid_credentials&return_to=%s", url.QueryEscape(returnTo))
		}
		http.Redirect(w, r, failURL, http.StatusFound)
		return
	}

	http.Error(w, `{"error":"invalid_credentials","message":"Invalid email or password"}`, http.StatusUnauthorized)
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
	return false
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	isSecure := isRequestSecure(r)
	clearCookie := func(name string) {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
			Secure:   isSecure,
			SameSite: http.SameSiteLaxMode,
		})
	}

	clearCookie("agentcontrol_session")
	clearCookie("oauth_state")
	clearCookie("oauth_nonce")
	clearCookie("auth_return_to")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": "logged out",
	})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims := middleware.UserClaimsFromContext(r.Context())
	if claims == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	orgID := claims.OrganizationID
	if orgID == "" {
		orgID = middleware.DefaultOrganizationID
	}

	orgName := "Primary Organization"
	if h.store != nil {
		org, err := h.store.GetOrganization(r.Context(), orgID)
		if err == nil && org != nil {
			orgName = org.Name
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"user_id":              claims.UserID,
		"organization_id":      orgID,
		"tenant_id":            orgID,
		"organization_name":    orgName,
		"is_admin":             claims.IsAdmin,
		"is_saas_operator":     claims.IsSaaSOperator,
		"role":                 claims.Role,
		"needs_password_setup": false,
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

	orgID := claims.OrganizationID
	if orgID == "" {
		orgID = middleware.DefaultOrganizationID
	}

	if h.store != nil {
		user := &model.User{
			OrganizationID: orgID,
			Email:          claims.UserID,
			PasswordHash:   hash,
			IsAdmin:        claims.IsAdmin,
			Role:           "ADMIN",
		}
		_ = h.store.CreateUser(r.Context(), user)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":               "ok",
		"user_id":              claims.UserID,
		"organization_id":      orgID,
		"needs_password_setup": false,
	})
}

func (h *AuthHandler) setSessionCookie(w http.ResponseWriter, r *http.Request, orgID, userID string, isAdmin, isSaaSOperator bool) {
	cookieValue := session.Create(orgID, userID, isAdmin, isSaaSOperator)
	isSecure := isRequestSecure(r)

	http.SetCookie(w, &http.Cookie{
		Name:     "agentcontrol_session",
		Value:    cookieValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(session.SessionDuration.Seconds()),
	})
}

type PublicProvider struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

func (h *AuthHandler) ListPublicProviders(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.ResolveOrganizationScope(r)
	if h.store == nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]PublicProvider{})
		return
	}
	providers, err := h.store.ListAuthProviders(r.Context(), orgID)
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
	_ = json.NewEncoder(w).Encode(public)
}

// ── Generic OIDC Engine & Discovery ──────────────────────────────────────────

type OIDCDiscoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

func resolveOIDCConfiguration(ctx context.Context, p *model.AuthProvider) (*OIDCDiscoveryDoc, error) {
	if p.Type == "google" {
		return &OIDCDiscoveryDoc{
			Issuer:                "https://accounts.google.com",
			AuthorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
			TokenEndpoint:         "https://oauth2.googleapis.com/token",
			JWKSURI:               "https://www.googleapis.com/oauth2/v3/certs",
			UserinfoEndpoint:      "https://openidconnect.googleapis.com/v1/userinfo",
		}, nil
	} else if p.Type == "entra" {
		tenant := "common"
		if p.IssuerURL != "" {
			tenant = strings.TrimSpace(p.IssuerURL)
			tenant = strings.TrimPrefix(tenant, "https://login.microsoftonline.com/")
			tenant = strings.TrimSuffix(tenant, "/v2.0")
			tenant = strings.Trim(tenant, "/")
			if tenant == "" {
				tenant = "common"
			}
		}
		return &OIDCDiscoveryDoc{
			Issuer:                fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenant),
			AuthorizationEndpoint: fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", tenant),
			TokenEndpoint:         fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant),
			JWKSURI:               fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", tenant),
			UserinfoEndpoint:      "https://graph.microsoft.com/oidc/userinfo",
		}, nil
	}

	// Generic OIDC discovery
	if p.IssuerURL == "" {
		return nil, errors.New("missing issuer_url for OIDC provider")
	}

	discoURL := strings.TrimSuffix(p.IssuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build discovery request: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned HTTP %d", resp.StatusCode)
	}

	var doc OIDCDiscoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to parse OIDC discovery document: %w", err)
	}

	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return nil, errors.New("OIDC discovery document missing required endpoints")
	}

	return &doc, nil
}

func (h *AuthHandler) resolveRedirectBase(r *http.Request) string {
	if h.cfg != nil && h.cfg.AppBaseURL != "" {
		return strings.TrimRight(h.cfg.AppBaseURL, "/")
	}

	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}

	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else if strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.0.0.1") {
			proto = "http"
		} else {
			proto = "https"
		}
	}

	return fmt.Sprintf("%s://%s", proto, host)
}

func (h *AuthHandler) getOAuthConfigWithDiscovery(r *http.Request, p *model.AuthProvider, doc *OIDCDiscoveryDoc) *oauth2.Config {
	baseURL := h.resolveRedirectBase(r)
	redirectURL := fmt.Sprintf("%s/api/v1/auth/oauth/%s/callback", baseURL, p.ID)

	scopes := []string{"openid", "email", "profile"}
	if p.Type == "entra" {
		scopes = append(scopes, "User.Read")
	}

	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		RedirectURL:  redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  doc.AuthorizationEndpoint,
			TokenURL: doc.TokenEndpoint,
		},
		Scopes: scopes,
	}
}

func (h *AuthHandler) OAuthLogin(w http.ResponseWriter, r *http.Request) {
	providerID := chi.URLParam(r, "provider_id")
	provider, err := h.store.GetAuthProvider(r.Context(), "", providerID)
	if err != nil || provider == nil || !provider.Enabled {
		http.Error(w, "provider not found", http.StatusNotFound)
		return
	}

	disco, err := resolveOIDCConfiguration(r.Context(), provider)
	if err != nil {
		http.Error(w, fmt.Sprintf("OIDC provider configuration error: %v", err), http.StatusBadGateway)
		return
	}

	conf := h.getOAuthConfigWithDiscovery(r, provider, disco)

	stateBytes := make([]byte, 16)
	_, _ = rand.Read(stateBytes)
	state := base64.URLEncoding.EncodeToString(stateBytes)

	nonceBytes := make([]byte, 16)
	_, _ = rand.Read(nonceBytes)
	nonce := base64.URLEncoding.EncodeToString(nonceBytes)

	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   300,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_nonce",
		Value:    nonce,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   300,
	})

	returnTo := r.URL.Query().Get("return_to")
	if returnTo != "" && strings.HasPrefix(returnTo, "/") && !strings.HasPrefix(returnTo, "//") && !strings.Contains(returnTo, "\\") {
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_return_to",
			Value:    returnTo,
			Path:     "/",
			HttpOnly: true,
			Secure:   isRequestSecure(r),
			SameSite: http.SameSiteLaxMode,
			MaxAge:   300,
		})
	}

	prompt := r.URL.Query().Get("prompt")
	if prompt == "" {
		prompt = "select_account"
	}

	authOptions := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("prompt", prompt),
	}

	authURL := conf.AuthCodeURL(state, authOptions...)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
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

	disco, err := resolveOIDCConfiguration(r.Context(), provider)
	if err != nil {
		http.Error(w, fmt.Sprintf("OIDC provider configuration error: %v", err), http.StatusBadGateway)
		return
	}

	conf := h.getOAuthConfigWithDiscovery(r, provider, disco)
	code := r.FormValue("code")
	tok, err := conf.Exchange(r.Context(), code)
	if err != nil {
		log.Printf("[OAuth Error] token exchange failed for provider %s (%s): %v", provider.ID, provider.Type, err)
		http.Error(w, fmt.Sprintf("oauth exchange failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Cryptographically verify ID Token against provider JWKS
	var subject, email, issuer string
	idTokenRaw, ok := tok.Extra("id_token").(string)
	if ok && idTokenRaw != "" {
		expectedNonce := ""
		if nonceCookie, err := r.Cookie("oauth_nonce"); err == nil && nonceCookie != nil {
			expectedNonce = nonceCookie.Value
		}

		claims, err := defaultOIDCVerifier.VerifyIDToken(
			r.Context(),
			idTokenRaw,
			disco.JWKSURI,
			disco.Issuer,
			provider.ClientID,
			expectedNonce,
		)
		if err != nil {
			log.Printf("[OAuth Error] ID token cryptographic verification failed for provider %s: %v", provider.ID, err)
			http.Error(w, fmt.Sprintf("invalid_id_token: %v", err), http.StatusUnauthorized)
			return
		}

		if sub, ok := claims["sub"].(string); ok && sub != "" {
			subject = sub
		} else if oid, ok := claims["oid"].(string); ok && oid != "" {
			subject = oid
		}

		if em, ok := claims["email"].(string); ok && em != "" {
			email = em
		} else if pref, ok := claims["preferred_username"].(string); ok && pref != "" {
			email = pref
		} else if upn, ok := claims["upn"].(string); ok && upn != "" {
			email = upn
		} else if un, ok := claims["unique_name"].(string); ok && un != "" {
			email = un
		}

		if iss, ok := claims["iss"].(string); ok {
			issuer = iss
		}
	} else {
		log.Printf("[OAuth Error] missing id_token in token exchange for provider %s", provider.ID)
		http.Error(w, "missing_id_token: provider did not return an id_token", http.StatusBadRequest)
		return
	}

	// Fallback to UserInfo endpoint / Graph API if email or subject was missing
	if email == "" || subject == "" {
		client := conf.Client(r.Context(), tok)
		userinfoURLs := []string{}
		if disco.UserinfoEndpoint != "" {
			userinfoURLs = append(userinfoURLs, disco.UserinfoEndpoint)
		}
		if provider.Type == "google" {
			userinfoURLs = append(userinfoURLs, "https://openidconnect.googleapis.com/v1/userinfo")
		} else if provider.Type == "entra" {
			userinfoURLs = append(userinfoURLs, "https://graph.microsoft.com/oidc/userinfo", "https://graph.microsoft.com/v1.0/me")
		}

		for _, uURL := range userinfoURLs {
			if (email != "" && subject != "") || uURL == "" {
				break
			}
			resp, err := client.Get(uURL)
			if err == nil {
				func() {
					defer resp.Body.Close()
					var uinfo struct {
						Sub               string `json:"sub"`
						Email             string `json:"email"`
						Mail              string `json:"mail"`
						UserPrincipalName string `json:"userPrincipalName"`
						PreferredUsername string `json:"preferred_username"`
						ID                string `json:"id"`
						OID               string `json:"oid"`
					}
					if json.NewDecoder(resp.Body).Decode(&uinfo) == nil {
						if subject == "" {
							if uinfo.Sub != "" {
								subject = uinfo.Sub
							} else if uinfo.ID != "" {
								subject = uinfo.ID
							} else if uinfo.OID != "" {
								subject = uinfo.OID
							}
						}
						if email == "" {
							if uinfo.Email != "" {
								email = uinfo.Email
							} else if uinfo.Mail != "" {
								email = uinfo.Mail
							} else if uinfo.UserPrincipalName != "" {
								email = uinfo.UserPrincipalName
							} else if uinfo.PreferredUsername != "" {
								email = uinfo.PreferredUsername
							}
						}
					}
				}()
			}
		}
	}

	if issuer == "" {
		issuer = disco.Issuer
	}

	if subject == "" || email == "" {
		log.Printf("[OAuth Error] Failed to extract identity. subject=%q, email=%q, idTokenPresent=%v", subject, email, idTokenRaw != "")
		http.Error(w, "could not retrieve verified identity and subject from provider", http.StatusBadRequest)
		return
	}

	// Validate allowed domain whitelist
	domainAllowed := false
	if len(provider.EmailDomains) == 0 {
		domainAllowed = true
	} else {
		for _, d := range provider.EmailDomains {
			domain := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), "@")
			if domain == "*" || strings.HasSuffix(strings.ToLower(email), "@"+domain) {
				domainAllowed = true
				break
			}
		}
	}
	if !domainAllowed {
		http.Error(w, "corporate email domain not authorized for this provider", http.StatusForbidden)
		return
	}

	orgID := provider.OrganizationID
	if orgID == "" {
		orgID = middleware.DefaultOrganizationID
	}

	// ── 1. Step A: Check by durable provider_subject ─────────────────────────
	user, err := h.store.GetUserByProviderSubject(r.Context(), orgID, providerID, subject)
	if err == nil && user != nil {
		isAdmin := user.IsAdmin
		if h.cfg != nil && h.cfg.AdminEmail != "" && strings.EqualFold(user.Email, h.cfg.AdminEmail) {
			isAdmin = true
		}
		h.setSessionCookie(w, r, user.OrganizationID, user.Email, isAdmin, false)
		h.finishAuthRedirect(w, r)
		return
	}

	// ── 2. Step B: Candidate Email Lookup & Ambiguity Guard ───────────────────
	candidates, err := h.store.FindUsersByEmail(r.Context(), email)
	if err != nil {
		http.Error(w, "server error querying accounts", http.StatusInternalServerError)
		return
	}

	// Ambiguity Guard: Halt immediately if multiple candidate accounts match
	if len(candidates) > 1 {
		http.Error(w, "Multiple accounts detected with this email. Please contact your administrator to resolve identity binding.", http.StatusConflict)
		return
	}

	if len(candidates) == 1 {
		cand := candidates[0]

		// Disallow automatic self-service linking for privileged roles
		if cand.Role == "ADMIN" || cand.Role == "OWNER" || cand.IsAdmin {
			http.Error(w, "Administrative accounts cannot be automatically linked via self-service SSO. Please sign in with your administrative credentials or contact an owner.", http.StatusForbidden)
			return
		}

		// Existing SSO member with NULL provider_subject — execute safe backfill
		if cand.PasswordHash == "" {
			_ = h.store.BackfillUserProviderSubject(r.Context(), orgID, providerID, cand.ID, subject, issuer)
			isAdmin := cand.IsAdmin
			if h.cfg != nil && h.cfg.AdminEmail != "" && strings.EqualFold(cand.Email, h.cfg.AdminEmail) {
				isAdmin = true
			}
			h.setSessionCookie(w, r, cand.OrganizationID, cand.Email, isAdmin, false)
			h.finishAuthRedirect(w, r)
			return
		}

		// Local password user attempting to link SSO — require password confirmation
		challengeTokenBytes := make([]byte, 24)
		_, _ = rand.Read(challengeTokenBytes)
		challengeToken := "link_" + base64.RawURLEncoding.EncodeToString(challengeTokenBytes)

		h.linkingMu.Lock()
		h.linkingStore[challengeToken] = &LinkingChallenge{
			Token:          challengeToken,
			UserID:         cand.ID,
			Email:          cand.Email,
			OrganizationID: orgID,
			AuthProviderID: providerID,
			ProviderSub:    subject,
			ProviderIssuer: issuer,
			ExpiresAt:      time.Now().Add(5 * time.Minute),
			FailedAttempts: 0,
		}
		h.linkingMu.Unlock()

		http.Redirect(w, r, fmt.Sprintf("/auth/link/confirm?token=%s", url.QueryEscape(challengeToken)), http.StatusSeeOther)
		return
	}

	// ── 3. Step C: JIT Provisioning for new Member ───────────────────────────
	isAdmin := false
	role := "MEMBER"
	if h.cfg != nil && h.cfg.AdminEmail != "" && strings.EqualFold(email, h.cfg.AdminEmail) {
		isAdmin = true
		role = "ADMIN"
	}

	newUser := &model.User{
		OrganizationID:  orgID,
		AuthProviderID:  &providerID,
		ProviderSubject: &subject,
		ProviderIssuer:  &issuer,
		Email:           email,
		PasswordHash:    "",
		IsAdmin:         isAdmin,
		Role:            role,
	}
	if err := h.store.CreateUser(r.Context(), newUser); err != nil {
		http.Error(w, "failed to provision new user", http.StatusInternalServerError)
		return
	}

	h.setSessionCookie(w, r, orgID, newUser.Email, isAdmin, false)
	h.finishAuthRedirect(w, r)
}

func (h *AuthHandler) finishAuthRedirect(w http.ResponseWriter, r *http.Request) {
	redirectTarget := "/"
	if returnCookie, err := r.Cookie("auth_return_to"); err == nil && returnCookie != nil && returnCookie.Value != "" {
		val := returnCookie.Value
		if strings.HasPrefix(val, "/") && !strings.HasPrefix(val, "//") && !strings.Contains(val, "\\") {
			redirectTarget = val
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_return_to",
			Value:    "",
			Path:     "/",
			Expires:  time.Now().Add(-1 * time.Hour),
			HttpOnly: true,
		})
	}
	http.Redirect(w, r, redirectTarget, http.StatusTemporaryRedirect)
}

// ── Multi-Step Account Linking Verification Handlers ─────────────────────────

type ConfirmLinkReq struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (h *AuthHandler) HandleLinkConfirmView(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	h.linkingMu.Lock()
	challenge, exists := h.linkingStore[token]
	h.linkingMu.Unlock()

	if !exists || time.Now().After(challenge.ExpiresAt) {
		http.Error(w, "Linking challenge expired or invalid. Please start SSO login again.", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Confirm Account Linking — Vexa Agent Control</title>
  <style>
    body { background: #0b1120; color: #f9fafb; font-family: sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 2rem; width: 100%%; max-width: 400px; }
    h2 { font-size: 1.25rem; margin-bottom: 0.5rem; color: #38bdf8; }
    p { font-size: 0.875rem; color: #9ca3af; margin-bottom: 1.5rem; line-height: 1.4; }
    input { width: 100%%; padding: 0.75rem; background: #1e293b; border: 1px solid #334155; border-radius: 6px; color: #fff; margin-bottom: 1rem; box-sizing: border-box; }
    button { width: 100%%; padding: 0.75rem; background: #38bdf8; color: #0b1120; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Link Account to Single Sign-On</h2>
    <p>An existing account was found for <strong>%s</strong>. Enter your local password to authorize linking to your Identity Provider.</p>
    <form method="POST" action="/api/v1/auth/link/confirm">
      <input type="hidden" name="token" value="%s">
      <input type="password" name="password" placeholder="Existing Account Password" required>
      <button type="submit">Confirm & Link Account</button>
    </form>
  </div>
</body>
</html>`, html.EscapeString(challenge.Email), html.EscapeString(token))
}

func (h *AuthHandler) ConfirmAccountLink(w http.ResponseWriter, r *http.Request) {
	var req ConfirmLinkReq
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		_ = json.NewDecoder(r.Body).Decode(&req)
	} else {
		_ = r.ParseForm()
		req.Token = r.FormValue("token")
		req.Password = r.FormValue("password")
	}

	h.linkingMu.Lock()
	challenge, exists := h.linkingStore[req.Token]
	if !exists || time.Now().After(challenge.ExpiresAt) {
		h.linkingMu.Unlock()
		http.Error(w, "Linking challenge expired or invalid", http.StatusBadRequest)
		return
	}

	if challenge.FailedAttempts >= 5 {
		delete(h.linkingStore, req.Token)
		h.linkingMu.Unlock()
		http.Error(w, "Too many failed attempts. Linking challenge cancelled.", http.StatusTooManyRequests)
		return
	}

	if h.store == nil {
		delete(h.linkingStore, req.Token)
		h.linkingMu.Unlock()
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	user, err := h.store.GetUserByID(r.Context(), challenge.UserID)
	if err != nil || user == nil {
		delete(h.linkingStore, req.Token)
		h.linkingMu.Unlock()
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	ok, _ := VerifyPassword(req.Password, user.PasswordHash)
	if !ok {
		challenge.FailedAttempts++
		h.linkingMu.Unlock()
		http.Error(w, "Invalid password confirmation", http.StatusUnauthorized)
		return
	}

	delete(h.linkingStore, req.Token)
	h.linkingMu.Unlock()

	// Bind provider subject to user
	_ = h.store.LinkUserProviderSubject(r.Context(), user.ID, challenge.AuthProviderID, challenge.ProviderSub, challenge.ProviderIssuer)

	h.setSessionCookie(w, r, user.OrganizationID, user.Email, user.IsAdmin, false)
	http.Redirect(w, r, "/", http.StatusFound)
}

// ── Break-Glass Emergency Recovery Handler ───────────────────────────────────

func (h *AuthHandler) HandleBreakGlassView(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Emergency Break-Glass — Vexa Agent Control</title>
  <style>
    body { background: #0b1120; color: #f9fafb; font-family: sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #111827; border: 1px solid #ef4444; border-radius: 10px; padding: 2rem; width: 100%; max-width: 440px; }
    h2 { font-size: 1.25rem; margin-bottom: 0.5rem; color: #ef4444; }
    p { font-size: 0.875rem; color: #9ca3af; margin-bottom: 1.5rem; line-height: 1.4; }
    input { width: 100%; padding: 0.75rem; background: #1e293b; border: 1px solid #334155; border-radius: 6px; color: #fff; margin-bottom: 1rem; box-sizing: border-box; }
    button { width: 100%; padding: 0.75rem; background: #ef4444; color: #fff; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Emergency Break-Glass Recovery</h2>
    <p>Redeem a single-use break-glass token generated on the Control Hub server host to recover administrative access.</p>
    <form method="POST" action="/api/v1/auth/break-glass">
      <input type="text" name="token" placeholder="bg_..." required>
      <button type="submit">Redeem Recovery Token</button>
    </form>
  </div>
</body>
</html>`)
}

type BreakGlassReq struct {
	Token string `json:"token"`
}

func (h *AuthHandler) BreakGlassLogin(w http.ResponseWriter, r *http.Request) {
	var req BreakGlassReq
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		_ = json.NewDecoder(r.Body).Decode(&req)
	} else {
		_ = r.ParseForm()
		req.Token = r.FormValue("token")
	}

	req.Token = strings.TrimSpace(req.Token)
	if req.Token == "" {
		http.Error(w, "missing break-glass token", http.StatusBadRequest)
		return
	}

	globalBreakGlassMu.Lock()
	rec, exists := globalBreakGlassStore[req.Token]
	if !exists || rec.Used || time.Now().After(rec.ExpiresAt) {
		globalBreakGlassMu.Unlock()
		http.Error(w, "break-glass token invalid or expired", http.StatusUnauthorized)
		return
	}
	rec.Used = true
	delete(globalBreakGlassStore, req.Token)
	globalBreakGlassMu.Unlock()

	// Grant emergency Owner/Admin session
	h.setSessionCookie(w, r, rec.OrganizationID, rec.Email, true, false)

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":          "ok",
			"message":         "Emergency break-glass session established.",
			"organization_id": rec.OrganizationID,
			"user_id":         rec.Email,
			"role":            "OWNER",
		})
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// ── OIDC Provider Diagnostic Endpoint ────────────────────────────────────────

func (h *AuthHandler) TestAuthProvider(w http.ResponseWriter, r *http.Request) {
	providerID := chi.URLParam(r, "provider_id")
	provider, err := h.store.GetAuthProvider(r.Context(), "", providerID)
	if err != nil || provider == nil {
		http.Error(w, `{"error":"provider not found"}`, http.StatusNotFound)
		return
	}

	disco, err := resolveOIDCConfiguration(r.Context(), provider)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":   "failed",
			"provider": provider.Name,
			"type":     provider.Type,
			"error":    err.Error(),
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    "healthy",
		"provider":  provider.Name,
		"type":      provider.Type,
		"discovery": disco,
	})
}

func (h *AuthHandler) HandleLoginView(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")

	// Check if already authenticated
	cookie, err := r.Cookie("agentcontrol_session")
	if err != nil {
		cookie, err = r.Cookie("agentwall_session")
	}
	if err == nil && cookie != nil && cookie.Value != "" {
		if sess, err := session.Validate(cookie.Value); err == nil && sess != nil && sess.UserID != "" {
			if returnTo != "" && strings.HasPrefix(returnTo, "/") && !strings.HasPrefix(returnTo, "//") && !strings.Contains(returnTo, "\\") {
				http.Redirect(w, r, returnTo, http.StatusFound)
				return
			}
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	// Fetch enabled OAuth providers
	var ssoSectionHTML string
	if h.store != nil {
		providers, _ := h.store.ListAuthProviders(r.Context(), middleware.DefaultOrganizationID)
		var ssoButtons []string
		for _, p := range providers {
			if p.Enabled && p.Type != "local" {
				oauthURL := fmt.Sprintf("/api/v1/auth/oauth/%s/login", p.ID)
				if returnTo != "" {
					oauthURL = fmt.Sprintf("%s?return_to=%s", oauthURL, url.QueryEscape(returnTo))
				}
				ssoButtons = append(ssoButtons, fmt.Sprintf(`
					<a href="%s" class="btn btn-sso">
						Continue with %s
					</a>`, oauthURL, html.EscapeString(p.Name)))
			}
		}
		if len(ssoButtons) > 0 {
			ssoSectionHTML = fmt.Sprintf(`
				<div class="sso-divider"><span>OR CONTINUE WITH ENTERPRISE SSO</span></div>
				%s`, strings.Join(ssoButtons, "\n"))
		}
	}

	safeReturnTo := html.EscapeString(returnTo)

	errorMsg := ""
	if r.URL.Query().Get("error") == "invalid_credentials" {
		errorMsg = "Invalid corporate email or password."
	} else if r.URL.Query().Get("error") == "insecure_default_credentials_blocked" {
		errorMsg = "Default credentials blocked in production. Configure ADMIN_PASSWORD."
	}

	errorDisplay := "none"
	if errorMsg != "" {
		errorDisplay = "block"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vexa Agent Control — Workstation Authentication</title>
  <style>
    :root {
      --bg: #0b1120;
      --card-bg: #111827;
      --border: #1f2937;
      --text: #f9fafb;
      --text-muted: #9ca3af;
      --primary: #38bdf8;
      --primary-hover: #0284c7;
      --input-bg: #1e293b;
      --input-border: #334155;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
    body { background: var(--bg); color: var(--text); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 1.5rem; }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; width: 100%%; max-width: 440px; padding: 2.25rem; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5); }
    .logo-row { display: flex; align-items: center; gap: 10px; margin-bottom: 1.5rem; }
    .logo-icon { width: 32px; height: 32px; background: rgba(56, 189, 248, 0.15); border: 1px solid rgba(56, 189, 248, 0.4); border-radius: 8px; display: flex; align-items: center; justify-content: center; color: var(--primary); }
    .brand-title { font-size: 1.15rem; font-weight: 700; color: #fff; letter-spacing: -0.02em; }
    .brand-title span { color: var(--primary); }
    h1 { font-size: 1.35rem; font-weight: 600; margin-bottom: 0.5rem; color: #fff; }
    p.subtitle { font-size: 0.875rem; color: var(--text-muted); margin-bottom: 1.75rem; line-height: 1.4; }
    .form-group { margin-bottom: 1.25rem; text-align: left; }
    label { display: block; font-size: 0.8rem; font-weight: 500; color: var(--text-muted); margin-bottom: 0.4rem; text-transform: uppercase; letter-spacing: 0.05em; }
    input[type="text"], input[type="email"], input[type="password"] { width: 100%%; padding: 0.75rem 0.9rem; background: var(--input-bg); border: 1px solid var(--input-border); border-radius: 6px; color: #fff; font-size: 0.95rem; outline: none; transition: border-color 0.15s; }
    input:focus { border-color: var(--primary); box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.2); }
    .btn { width: 100%%; padding: 0.8rem; background: var(--primary); color: #0b1120; border: none; border-radius: 6px; font-size: 0.95rem; font-weight: 600; cursor: pointer; transition: background 0.15s, transform 0.05s; display: flex; align-items: center; justify-content: center; text-decoration: none; }
    .btn:hover { background: var(--primary-hover); color: #fff; }
    .btn:active { transform: scale(0.99); }
    .error-msg { background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.4); color: #fca5a5; padding: 0.65rem 0.85rem; border-radius: 6px; font-size: 0.85rem; margin-bottom: 1.25rem; display: %s; }
    .sso-divider { display: flex; align-items: center; text-align: center; margin: 1.5rem 0; color: #6b7280; font-size: 0.75rem; font-weight: 600; letter-spacing: 0.05em; }
    .sso-divider::before, .sso-divider::after { content: ''; flex: 1; border-bottom: 1px solid var(--border); }
    .sso-divider span { padding: 0 0.75rem; }
    .btn-sso { background: #1e293b; color: #e2e8f0; border: 1px solid #334155; margin-bottom: 0.65rem; }
    .btn-sso:hover { background: #334155; color: #fff; }
    .footer-note { font-size: 0.78rem; color: #6b7280; text-align: center; margin-top: 1.75rem; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo-row">
      <div class="logo-icon">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </div>
      <div class="brand-title"><span>Vexa</span> Agent Control</div>
    </div>
    <h1>Workstation Sign-In</h1>
    <p class="subtitle">Authenticate to enroll this workstation into Primary Organization.</p>

    <div id="error-box" class="error-msg">%s</div>

    <form id="login-form" method="POST" action="/login">
      <input type="hidden" id="return_to" name="return_to" value="%s">
      <div class="form-group">
        <label for="email">Corporate Email</label>
        <input type="text" id="email" name="email" placeholder="admin@agentcontrol.local" required autocomplete="username">
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" placeholder="••••••••" required autocomplete="current-password">
      </div>
      <button type="submit" id="submit-btn" class="btn">Authenticate Workstation</button>
    </form>

    %s

    <p class="footer-note">Enterprise AI Governance & Gateway Platform</p>
  </div>

  <script>
    document.getElementById('login-form').addEventListener('submit', async function(e) {
      e.preventDefault();
      const btn = document.getElementById('submit-btn');
      const errBox = document.getElementById('error-box');
      errBox.style.display = 'none';
      btn.disabled = true;
      btn.innerText = 'Authenticating...';

      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value;
      const returnTo = document.getElementById('return_to').value;

      try {
        const res = await fetch('/api/v1/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: email, password: password })
        });
        if (!res.ok) {
          const data = await res.json().catch(function() { return {}; });
          errBox.innerText = data.message || data.error || 'Invalid corporate email or password';
          errBox.style.display = 'block';
          btn.disabled = false;
          btn.innerText = 'Authenticate Workstation';
          return;
        }
        window.location.href = returnTo || '/';
      } catch (err) {
        errBox.innerText = 'Connection error contacting Control Hub API';
        errBox.style.display = 'block';
        btn.disabled = false;
        btn.innerText = 'Authenticate Workstation';
      }
    });
  </script>
</body>
</html>`, errorDisplay, html.EscapeString(errorMsg), safeReturnTo, ssoSectionHTML)
}
