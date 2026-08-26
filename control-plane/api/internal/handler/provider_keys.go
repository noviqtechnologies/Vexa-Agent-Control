package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/crypto"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type ProviderKeysHandler struct {
	store     DataStore
	masterKey []byte
}

func NewProviderKeysHandler(s DataStore, masterKey []byte) *ProviderKeysHandler {
	return &ProviderKeysHandler{store: s, masterKey: masterKey}
}

// List GET /api/v1/providers/keys
func (h *ProviderKeysHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := middleware.TenantIDFromContext(ctx)
	keys, err := h.store.ListProviderKeys(ctx, tenantID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if keys == nil {
		keys = []store.ProviderKey{}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(keys); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
	}
}

// Save POST /api/v1/providers/keys
func (h *ProviderKeysHandler) Save(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider string `json:"provider"`
		APIKey   string `json:"api_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	if req.Provider == "" || req.APIKey == "" {
		http.Error(w, `{"error":"provider and api_key are required"}`, http.StatusBadRequest)
		return
	}

	// Mask the key for display (e.g., sk-...abcd)
	masked := crypto.MaskAPIKey(req.APIKey)

	// Encrypt the raw API key using AES-256-GCM before persisting to database
	encryptedKey, err := crypto.Encrypt(h.masterKey, req.APIKey)
	if err != nil {
		http.Error(w, `{"error":"encryption failed"}`, http.StatusInternalServerError)
		return
	}

	ctx := r.Context()
	tenantID := middleware.TenantIDFromContext(ctx)

	k := &store.ProviderKey{
		TenantID:        tenantID,
		Provider:        strings.ToLower(req.Provider),
		APIKeyMasked:    masked,
		APIKeyEncrypted: encryptedKey,
	}

	if err := h.store.InsertProviderKey(ctx, tenantID, k); err != nil {
		http.Error(w, `{"error":"failed to save key"}`, http.StatusInternalServerError)
		return
	}

	// Hide the encrypted key from the response
	k.APIKeyEncrypted = ""
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(k)
}

// Delete DELETE /api/v1/providers/keys/{id}
func (h *ProviderKeysHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, `{"error":"missing id"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	tenantID := middleware.TenantIDFromContext(ctx)
	if err := h.store.DeleteProviderKey(ctx, tenantID, id); err != nil {
		http.Error(w, `{"error":"failed to delete key"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
