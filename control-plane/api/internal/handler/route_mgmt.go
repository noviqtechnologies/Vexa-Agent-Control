package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/routing"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/sse"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type RouteMgmtHandler struct {
	store  *store.Store
	broker *sse.Broker
}

func NewRouteMgmtHandler(s *store.Store, b *sse.Broker) *RouteMgmtHandler {
	return &RouteMgmtHandler{store: s, broker: b}
}

// List handles GET /api/v1/routes
func (h *RouteMgmtHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	if tenantID == "" {
		writeUnauthorizedTenantError(w)
		return
	}
	profiles, err := h.store.ListRouteProfiles(r.Context(), tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if profiles == nil {
		profiles = []*model.RouteProfile{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"organization_id": tenantID,
		"routes":          profiles,
		"total":           len(profiles),
	})
}

// Create handles POST /api/v1/routes (creates a new candidate version)
func (h *RouteMgmtHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	if tenantID == "" {
		writeUnauthorizedTenantError(w)
		return
	}

	var p model.RouteProfile
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, `{"error":"invalid_json_body"}`, http.StatusBadRequest)
		return
	}
	p.OrganizationID = tenantID

	if err := routing.ValidateProfile(&p); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":   "validation_failed",
			"message": err.Error(),
		})
		return
	}

	if err := h.store.CreateRouteProfile(r.Context(), &p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(p)
}

// GetByID handles GET /api/v1/routes/{id}
func (h *RouteMgmtHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	if tenantID == "" {
		writeUnauthorizedTenantError(w)
		return
	}
	profileID := chi.URLParam(r, "id")
	p, err := h.store.GetRouteProfileByID(r.Context(), tenantID, profileID)
	if err != nil {
		http.Error(w, `{"error":"route_profile_not_found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}

// Simulate handles POST /api/v1/routes/simulate
func (h *RouteMgmtHandler) Simulate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Profile  model.RouteProfile          `json:"profile"`
		Fixtures []routing.SimulationFixture `json:"fixtures,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_json_body"}`, http.StatusBadRequest)
		return
	}

	report, err := routing.Simulate(r.Context(), &req.Profile, req.Fixtures)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":   "simulation_error",
			"message": err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(report)
}

// Activate handles POST /api/v1/routes/{id}/activate
func (h *RouteMgmtHandler) Activate(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	if tenantID == "" {
		writeUnauthorizedTenantError(w)
		return
	}
	profileID := chi.URLParam(r, "id")

	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Reason == "" {
		req.Reason = "admin_activation"
	}

	act, err := h.store.ActivateRouteProfile(r.Context(), tenantID, profileID, "admin", req.Reason, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Broadcast route activation over SSE
	if h.broker != nil {
		eventJSON, _ := json.Marshal(act)
		h.broker.PublishTenant(tenantID, formatSSE("route_activated", string(eventJSON)))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(act)
}

// Rollback handles POST /api/v1/routes/{id}/rollback
func (h *RouteMgmtHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	if tenantID == "" {
		writeUnauthorizedTenantError(w)
		return
	}
	profileID := chi.URLParam(r, "id")

	var req struct {
		Reason                   string  `json:"reason"`
		RollbackFromActivationID *string `json:"rollback_from_activation_id,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Reason == "" {
		req.Reason = "admin_rollback"
	}

	act, err := h.store.ActivateRouteProfile(r.Context(), tenantID, profileID, "admin", req.Reason, req.RollbackFromActivationID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if h.broker != nil {
		eventJSON, _ := json.Marshal(act)
		h.broker.PublishTenant(tenantID, formatSSE("route_rollback", string(eventJSON)))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(act)
}
