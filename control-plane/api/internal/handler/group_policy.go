package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

type PublishGroupPolicyRequest struct {
	GroupID string          `json:"group_id"`
	Claims  json.RawMessage `json:"claims"`
	Tools   json.RawMessage `json:"tools"`
}

type GroupPolicyHandler struct {
	store DataStore
}

func NewHandler(s DataStore) *GroupPolicyHandler {
	return &GroupPolicyHandler{store: s}
}

func (h *GroupPolicyHandler) GetGroupPolicy(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "groupID")
	if groupID == "" {
		http.Error(w, "missing groupID", http.StatusBadRequest)
		return
	}

	policy, err := h.store.GetActiveGroupPolicy(r.Context(), groupID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if policy == nil {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

func (h *GroupPolicyHandler) PublishGroupPolicy(w http.ResponseWriter, r *http.Request) {
	var req PublishGroupPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if req.GroupID == "" {
		http.Error(w, "missing group_id", http.StatusBadRequest)
		return
	}

	createdBy := "system" // Extract from context/auth later

	policy, err := h.store.PublishGroupPolicy(r.Context(), req.GroupID, req.Claims, req.Tools, createdBy)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(policy)
}

func (h *GroupPolicyHandler) ListGroupPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.store.ListGroupPolicies(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"policies": policies,
	})
}
