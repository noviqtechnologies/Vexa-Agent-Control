package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type AuthProviderHandler struct {
	store *store.Store
}

func NewAuthProviderHandler(s *store.Store) *AuthProviderHandler {
	return &AuthProviderHandler{store: s}
}

func (h *AuthProviderHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	providers, err := h.store.ListAuthProviders(r.Context(), tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Redact secrets
	for i := range providers {
		providers[i].ClientSecret = ""
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(providers)
}

func (h *AuthProviderHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	id := chi.URLParam(r, "id")
	provider, err := h.store.GetAuthProvider(r.Context(), tenantID, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if provider == nil {
		http.NotFound(w, r)
		return
	}
	
	provider.ClientSecret = "" // Redact
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(provider)
}

func (h *AuthProviderHandler) Upsert(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	var p model.AuthProvider
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	
	if p.Type == "" || p.Name == "" {
		http.Error(w, "type and name are required", http.StatusBadRequest)
		return
	}
	
	if p.ID == "" {
		p.CreatedAt = time.Now()
	}
	p.UpdatedAt = time.Now()
	
	if err := h.store.UpsertAuthProvider(r.Context(), tenantID, &p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	p.ClientSecret = ""
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}
