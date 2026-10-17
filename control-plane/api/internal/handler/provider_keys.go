package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/crypto"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/kms"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type ProviderKeysHandler struct {
	store       DataStore
	masterKey   []byte
	kmsProvider kms.KMSProvider
}

func NewProviderKeysHandler(s DataStore, masterKey []byte, kmsProviders ...kms.KMSProvider) *ProviderKeysHandler {
	var kp kms.KMSProvider
	if len(kmsProviders) > 0 {
		kp = kmsProviders[0]
	}
	return &ProviderKeysHandler{store: s, masterKey: masterKey, kmsProvider: kp}
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

	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	masked := crypto.MaskAPIKey(req.APIKey)

	ctx := r.Context()
	tenantID := middleware.TenantIDFromContext(ctx)

	// If KMS provider is active, persist via the unified KMS Provider Vault
	if h.kmsProvider != nil {
		if err := h.store.InsertEncryptedProviderKey(ctx, tenantID, provider, "default", req.APIKey, h.kmsProvider); err != nil {
			http.Error(w, `{"error":"failed to save key"}`, http.StatusInternalServerError)
			return
		}

		k := &store.ProviderKey{
			TenantID:     tenantID,
			Provider:     provider,
			APIKeyMasked: masked,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(k)
		return
	}

	// Encrypt the raw API key using AES-256-GCM before persisting to database
	encryptedKey, err := crypto.Encrypt(h.masterKey, req.APIKey)
	if err != nil {
		http.Error(w, `{"error":"encryption failed"}`, http.StatusInternalServerError)
		return
	}

	k := &store.ProviderKey{
		TenantID:        tenantID,
		Provider:        provider,
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
