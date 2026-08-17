package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
)

type McpServersHandler struct {
	store DataStore
}

func NewMcpServersHandler(s DataStore) *McpServersHandler {
	return &McpServersHandler{store: s}
}

// ListFleetWide GET /api/v1/fleet/mcp-servers
func (h *McpServersHandler) ListFleetWide(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := middleware.TenantIDFromContext(ctx)
	servers, err := h.store.ListMcpServersFleetWide(ctx, tenantID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(servers); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
	}
}

// ListByAgent GET /api/v1/fleet/mcp-servers/{agentID}
func (h *McpServersHandler) ListByAgent(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentID")
	if agentID == "" {
		http.Error(w, `{"error":"missing agent ID"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	tenantID := middleware.TenantIDFromContext(ctx)
	servers, err := h.store.ListMcpServersByAgent(ctx, tenantID, agentID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(servers); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
	}
}
