package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type PublishGroupPolicyRequest struct {
	GroupID string          `json:"group_id"`
	Claims  json.RawMessage `json:"claims"`
	Tools   json.RawMessage `json:"tools"`
}

type GroupPolicyHandler struct {
	store DataStore
}

func NewGroupPolicyHandler(s DataStore) *GroupPolicyHandler {
	return &GroupPolicyHandler{store: s}
}

// Backward compatibility alias
func NewHandler(s DataStore) *GroupPolicyHandler {
	return NewGroupPolicyHandler(s)
}

func (h *GroupPolicyHandler) GetGroupPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	groupID := chi.URLParam(r, "groupID")
	if groupID == "" {
		http.Error(w, "missing groupID", http.StatusBadRequest)
		return
	}

	policy, err := h.store.GetActiveGroupPolicy(r.Context(), tenantID, groupID)
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
	tenantID := middleware.TenantIDFromContext(r.Context())
	var req PublishGroupPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if req.GroupID == "" {
		http.Error(w, "missing group_id", http.StatusBadRequest)
		return
	}

	createdBy := "system"
	if claims := middleware.UserClaimsFromContext(r.Context()); claims != nil && claims.UserID != "" {
		createdBy = claims.UserID
	}

	policy, err := h.store.PublishGroupPolicy(r.Context(), tenantID, req.GroupID, req.Claims, req.Tools, createdBy)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(policy)
}

func (h *GroupPolicyHandler) ListGroupPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	policies, err := h.store.ListGroupPolicies(r.Context(), tenantID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if policies == nil {
		policies = []*store.GroupPolicyVersion{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"policies": policies,
	})
}
