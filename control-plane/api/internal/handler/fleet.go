package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/store"
)

type FleetHandler struct {
	store DataStore
}

func NewFleetHandler(s DataStore) *FleetHandler {
	return &FleetHandler{store: s}
}

// GetOverview returns fleet-wide stats for the dashboard header.
func (h *FleetHandler) GetOverview(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	stats, err := h.store.GetFleetStats(r.Context(), tenantID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, stats)
}

// ListAgents returns paginated agent summaries.
func (h *FleetHandler) ListAgents(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	limit := queryInt(r, "limit", 50)
	offset := queryInt(r, "offset", 0)

	agents, err := h.store.ListAgents(r.Context(), tenantID, limit, offset)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if agents == nil {
		agents = []store.AgentSummary{}
	}
	writeJSON(w, agents)
}

// GetHeatmap returns hourly decision breakdown for the Fleet Overview heatmap.
func (h *FleetHandler) GetHeatmap(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	hours := queryInt(r, "hours", 24)
	if hours > 168 {
		hours = 168
	}

	data, err := h.store.GetDecisionHeatmap(r.Context(), tenantID, hours)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if data == nil {
		data = []store.DecisionBreakdown{}
	}
	writeJSON(w, data)
}

// ListEvents returns recent events, optionally filtered by agent.
func (h *FleetHandler) ListEvents(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	agentID := chi.URLParam(r, "agentID")
	limit := queryInt(r, "limit", 100)

	events, err := h.store.ListRecentEvents(r.Context(), tenantID, agentID, limit)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, events)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func queryInt(r *http.Request, key string, fallback int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}
