package handler

import (
	"net/http"

	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/middleware"
)

type IdentityHandler struct {
	store DataStore
}

func NewIdentityHandler(s DataStore) *IdentityHandler {
	return &IdentityHandler{store: s}
}

// ListCredentials returns credential metadata for all agents, or filtered
// by agent_id query param. Never returns credential values (AC-23.10).
func (h *IdentityHandler) ListCredentials(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	agentID := r.URL.Query().Get("agent_id")

	creds, err := h.store.ListCredentials(r.Context(), tenantID, agentID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, creds)
}
