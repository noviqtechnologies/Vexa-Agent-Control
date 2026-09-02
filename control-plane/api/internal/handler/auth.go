package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	req.Email = strings.TrimSpace(req.Email)
	req.Password = strings.TrimSpace(req.Password)

	// 1. DevMode login bypass
	if h.cfg != nil && h.cfg.DevMode && (req.Email == "admin" || req.Email == "admin@agentcontrol.local") {
		h.setSessionCookie(w, r, middleware.DefaultOrganizationID, req.Email, true)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":               "ok",
			"user_id":              req.Email,
			"organization_id":      middleware.DefaultOrganizationID,
			"organization_name":    "Primary Organization",
			"is_admin":             true,
			"role":                 "OWNER",
			"needs_password_setup": false,
		})
		return
	}

	// 2. Default Admin fallback for fresh installations (admin@agentcontrol.local / admin123! or admin / admin)
	if (req.Email == "admin@agentcontrol.local" || req.Email == "admin") && (req.Password == "admin123!" || req.Password == "admin") {
		h.setSessionCookie(w, r, middleware.DefaultOrganizationID, "admin@agentcontrol.local", true)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":               "ok",
			"user_id":              "admin@agentcontrol.local",
			"organization_id":      middleware.DefaultOrganizationID,
			"organization_name":    "Primary Organization",
			"is_admin":             true,
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
				h.setSessionCookie(w, r, user.OrganizationID, user.Email, user.IsAdmin)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":               "ok",
					"user_id":              user.Email,
					"organization_id":      user.OrganizationID,
					"organization_name":    "Primary Organization",
					"is_admin":             user.IsAdmin,
					"role":                 user.Role,
					"needs_password_setup": false,
				})
				return
			}
		}
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

func (h *AuthHandler) setSessionCookie(w http.ResponseWriter, r *http.Request, orgID, userID string, isAdmin bool) {
	cookieValue := session.Create(orgID, userID, isAdmin, false)
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

	h.setSessionCookie(w, r, orgID, user.Email, user.IsAdmin)
	
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
	})
	
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
