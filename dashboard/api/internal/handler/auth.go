package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/session"
	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/store"
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

	// 1. Check Bootstrap Token
	if BootstrapToken != "" && req.Password == BootstrapToken && req.Email == "admin" {
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
