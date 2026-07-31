package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/store"
)

type ProviderKeysHandler struct {
	store DataStore
}

func NewProviderKeysHandler(s DataStore) *ProviderKeysHandler {
	return &ProviderKeysHandler{store: s}
}

// List GET /api/v1/providers/keys
func (h *ProviderKeysHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	keys, err := h.store.ListProviderKeys(ctx)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
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
	masked := req.APIKey
	if len(req.APIKey) > 8 {
		masked = req.APIKey[:4] + "..." + req.APIKey[len(req.APIKey)-4:]
	} else if len(req.APIKey) > 4 {
		masked = req.APIKey[:3] + "..."
	}

	k := &store.ProviderKey{
		Provider:        strings.ToLower(req.Provider),
		APIKeyMasked:    masked,
		APIKeyEncrypted: req.APIKey, // In a real app, encrypt this before saving to DB
	}

	if err := h.store.InsertProviderKey(r.Context(), k); err != nil {
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

	if err := h.store.DeleteProviderKey(r.Context(), id); err != nil {
		http.Error(w, `{"error":"failed to delete key"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
