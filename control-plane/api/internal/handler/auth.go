package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
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

type AuthHandler struct {
	store *store.Store
	cfg   *config.Config
}

func NewAuthHandler(s *store.Store, cfg *config.Config) *AuthHandler {
	return &AuthHandler{store: s, cfg: cfg}
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
	http.SetCookie(w, &http.Cookie{
		Name:     "agentcontrol_session",
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
			var user struct {
				Email string `json:"email"`
			}
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
		domain := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), "@")
		if domain == "*" || strings.HasSuffix(strings.ToLower(email), "@"+domain) {
			domainAllowed = true
			break
		}
	}
	if !domainAllowed {
		http.Error(w, "domain not allowed", http.StatusForbidden)
		return
	}

	orgID := provider.OrganizationID
	if orgID == "" {
		orgID = middleware.DefaultOrganizationID
	}

	user, err := h.store.GetUserByEmail(r.Context(), orgID, providerID, email)
	if err != nil || user == nil {
		user = &model.User{
			OrganizationID: orgID,
			AuthProviderID: &providerID,
			Email:          email,
			PasswordHash:   "",
			IsAdmin:        false,
			Role:           "MEMBER",
		}
		_ = h.store.CreateUser(r.Context(), user)
		user, _ = h.store.GetUserByEmail(r.Context(), orgID, providerID, email)
	}

	h.setSessionCookie(w, r, orgID, user.Email, user.IsAdmin, false)

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
