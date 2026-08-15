package handler

import (
	"context"
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

	// 1. Check Bootstrap Token or Dev Mode
	if (BootstrapToken != "" && req.Password == BootstrapToken && (req.Email == "admin" || req.Email == "admin@example.com")) ||
		(os.Getenv("DEV_MODE") == "true" && (req.Email == "admin" || req.Email == "admin@example.com" || strings.Contains(req.Email, "@"))) {
		h.setSessionCookie(w, "admin", true)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}

	// 2. Check Local Auth Provider
	providers, err := h.store.ListAuthProviders(r.Context())
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	var localProviderID string
	for _, p := range providers {
		if p.Type == "local" {
			localProviderID = p.ID
			if p.Enabled {
				break
			}
		}
	}

	if localProviderID == "" {
		http.Error(w, "local auth not enabled", http.StatusUnauthorized)
		return
	}

	u, err := h.store.GetUserByEmail(r.Context(), localProviderID, req.Email)
	if err != nil || u == nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	ok, err := VerifyPassword(req.Password, u.PasswordHash)
	if err != nil || !ok {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	h.setSessionCookie(w, u.ID, u.IsAdmin)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "agentwall_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
	})
	w.WriteHeader(http.StatusOK)
}

func (h *AuthHandler) setSessionCookie(w http.ResponseWriter, userID string, isAdmin bool) {
	cookieValue := session.Create(userID, isAdmin)
	
	http.SetCookie(w, &http.Cookie{
		Name:     "agentwall_session",
		Value:    cookieValue,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})
}

func GenerateBootstrapToken() string {
	b := make([]byte, 8)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (h *AuthHandler) CheckBootstrap() {
	count, err := h.store.CountAuthProviders(context.Background())
	if err != nil {
		log.Printf("ERROR checking auth providers for bootstrap: %v", err)
		return
	}
	if count == 0 {
		BootstrapToken = GenerateBootstrapToken()
		log.Printf("=========================================================")
		log.Printf("INFO: NO AUTH PROVIDERS CONFIGURED.")
		log.Printf("INFO: Bootstrap Token: %s", BootstrapToken)
		log.Printf("INFO: Use Email 'admin' and this token to log in.")
		log.Printf("=========================================================")
	} else {
		log.Printf("INFO: Found %d auth providers, skipping bootstrap.", count)
	}
}

type PublicProvider struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

func (h *AuthHandler) ListPublicProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := h.store.ListAuthProviders(r.Context())
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
	provider, err := h.store.GetAuthProvider(r.Context(), providerID)
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
	provider, err := h.store.GetAuthProvider(r.Context(), providerID)
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
	
	user, err := h.store.GetUserByEmail(r.Context(), providerID, email)
	if err != nil || user == nil {
		user = &model.User{
			AuthProviderID: providerID,
			Email:          email,
			PasswordHash:   "",
			IsAdmin:        false,
		}
		if err := h.store.UpsertUser(r.Context(), user); err != nil {
			http.Error(w, "failed to auto-provision user", http.StatusInternalServerError)
			return
		}
		user, _ = h.store.GetUserByEmail(r.Context(), providerID, email)
	}
	
	h.setSessionCookie(w, user.ID, user.IsAdmin)
	
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
	})
	
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

