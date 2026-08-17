package handler

import (
	"encoding/json"
	"net/http"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/license"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
)

type LicenseHandler struct {
	store  DataStore
	claims *license.Claims
}

func NewLicenseHandler(s DataStore, c *license.Claims) *LicenseHandler {
	if c == nil {
		c = license.CommunityClaims()
	}
	return &LicenseHandler{
		store:  s,
		claims: c,
	}
}

// GET /api/v1/license/status
func (h *LicenseHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	seatsUsed := 0
	if h.store != nil {
		if count, err := h.store.CountDistinctAgents(r.Context(), tenantID); err == nil {
			seatsUsed = count
		}
	}

	seatsRemaining := h.claims.MaxSeats - seatsUsed
	if seatsRemaining < 0 {
		seatsRemaining = 0
	}

	resp := map[string]interface{}{
		"org_id":          h.claims.OrgID,
		"tier":            h.claims.Tier,
		"max_seats":       h.claims.MaxSeats,
		"seats_used":      seatsUsed,
		"seats_remaining": seatsRemaining,
		"features":        h.claims.Features,
		"is_trial":        h.claims.IsTrial,
		"trial_days":      h.claims.TrialDays,
	}
	if h.claims.ExpiresAt != nil {
		resp["expires_at"] = h.claims.ExpiresAt.Time
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
