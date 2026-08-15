package handler

import (
	"net/http"

	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/store"
)

type ThreatHandler struct {
	store DataStore
}

func NewThreatHandler(s DataStore) *ThreatHandler {
	return &ThreatHandler{store: s}
}

func (h *ThreatHandler) GetSummary(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	hours := queryInt(r, "hours", 24)
	if hours > 720 {
		hours = 720
	}

	summary, err := h.store.GetThreatSummary(r.Context(), tenantID, hours)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, summary)
}

func (h *ThreatHandler) GetTimeline(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	hours := queryInt(r, "hours", 24)
	if hours > 720 {
		hours = 720
	}

	data, err := h.store.GetThreatTimeline(r.Context(), tenantID, hours)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if data == nil {
		data = []store.ThreatTimelinePoint{}
	}
	writeJSON(w, data)
}

func (h *ThreatHandler) GetTopPatterns(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	hours := queryInt(r, "hours", 24)
	if hours > 720 {
		hours = 720
	}
	limit := queryInt(r, "limit", 20)

	patterns, err := h.store.GetTopThreatPatterns(r.Context(), tenantID, hours, limit)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if patterns == nil {
		patterns = []store.ThreatPattern{}
	}
	writeJSON(w, patterns)
}
