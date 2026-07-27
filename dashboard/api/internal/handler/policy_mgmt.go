package handler

import (
	"encoding/json"
	"net/http"

	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/model"
	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/store"
)

type PolicyMgmtHandler struct {
	store *store.Store
}

func NewPolicyMgmtHandler(s *store.Store) *PolicyMgmtHandler {
	return &PolicyMgmtHandler{store: s}
}

func (h *PolicyMgmtHandler) GetActive(w http.ResponseWriter, r *http.Request) {
	policy, err := h.store.GetActivePolicy(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if policy == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

func (h *PolicyMgmtHandler) Save(w http.ResponseWriter, r *http.Request) {
	var p model.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	
	if p.Version == "" || p.Content == "" {
		http.Error(w, "version and content are required", http.StatusBadRequest)
		return
	}
	
	p.IsActive = true
	if err := h.store.SavePolicy(r.Context(), &p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}
