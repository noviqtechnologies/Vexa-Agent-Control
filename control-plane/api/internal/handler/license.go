package handler

import (
	"encoding/json"
	"net/http"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/license"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type LicenseHandler struct {
	store     *store.Store
	claims    *license.Claims
	validator *license.Validator
}

func NewLicenseHandler(s *store.Store, c *license.Claims) *LicenseHandler {
	if c == nil {
		c = license.DeveloperClaims()
	}
	val, _ := license.NewValidatorFromEnv()
	return &LicenseHandler{
		store:     s,
		claims:    c,
		validator: val,
	}
}

// GET /api/v1/license/status
func (h *LicenseHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.ResolveOrganizationScope(r)
	var org *model.Organization
	if h.store != nil {
		org, _ = h.store.GetOrganization(r.Context(), orgID)
	}

	tier := "developer"
	maxDevices := 1
	enrolledDevices := 0
	features := []string{}

	if org != nil {
		tier = org.LicenseTier
		maxDevices = org.MaxDevices
		enrolledDevices = org.EnrolledDevices
		features = license.TierToFeatures(tier)
	} else if h.claims != nil {
		tier = h.claims.Tier
		maxDevices = h.claims.MaxDevices
		features = h.claims.Features
	}

	devicesRemaining := -1
	if maxDevices > 0 {
		devicesRemaining = maxDevices - enrolledDevices
		if devicesRemaining < 0 {
			devicesRemaining = 0
		}
	}

	resp := map[string]interface{}{
		"org_id":            orgID,
		"tier":              tier,
		"max_devices":       maxDevices,
		"devices_enrolled":  enrolledDevices,
		"devices_remaining": devicesRemaining,
		"features":          features,
		"status":            "active",
	}
	if org != nil && org.LicenseExpiresAt != nil {
		resp["expires_at"] = org.LicenseExpiresAt
	} else if h.claims != nil && h.claims.ExpiresAt != nil {
		resp["expires_at"] = h.claims.ExpiresAt.Time
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// POST /api/v1/license/activate
func (h *LicenseHandler) ActivateLicense(w http.ResponseWriter, r *http.Request) {
	var req model.ActivateLicenseReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.LicenseKeyJWT == "" {
		http.Error(w, `{"error":"license_key_jwt is required"}`, http.StatusBadRequest)
		return
	}

	if h.validator == nil {
		val, err := license.NewValidatorFromEnv()
		if err != nil {
			http.Error(w, `{"error":"license validator uninitialized"}`, http.StatusInternalServerError)
			return
		}
		h.validator = val
	}

	claims, err := h.validator.Validate(req.LicenseKeyJWT)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "invalid_license_key",
			"message": err.Error(),
		})
		return
	}

	orgID := middleware.ResolveOrganizationScope(r)
	var expTime *license.Claims
	_ = expTime
	var expiresAtPtr = claims.ExpiresAt.Time

	if h.store != nil {
		err := h.store.UpdateLicenseKey(r.Context(), orgID, req.LicenseKeyJWT, claims.Tier, claims.MaxDevices, &expiresAtPtr)
		if err != nil {
			http.Error(w, `{"error":"failed to persist license activation"}`, http.StatusInternalServerError)
			return
		}
	}

	h.claims = claims

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"message":     "License activated successfully",
		"tier":        claims.Tier,
		"max_devices": claims.MaxDevices,
		"expires_at":  expiresAtPtr,
		"features":    claims.Features,
	})
}

// GET /api/v1/organization
func (h *LicenseHandler) GetOrganization(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.ResolveOrganizationScope(r)
	if h.store == nil {
		http.Error(w, `{"error":"store unavailable"}`, http.StatusInternalServerError)
		return
	}

	summary, err := h.store.GetOrganizationSummary(r.Context(), orgID)
	if err != nil {
		http.Error(w, `{"error":"failed to get organization summary"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(summary)
}

// PUT /api/v1/organization
func (h *LicenseHandler) UpdateOrganization(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.ResolveOrganizationScope(r)
	var req model.UpdateOrgReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request payload"}`, http.StatusBadRequest)
		return
	}

	if h.store != nil {
		if err := h.store.UpdateOrganization(r.Context(), orgID, req.Name, req.ContactEmail); err != nil {
			http.Error(w, `{"error":"failed to update organization"}`, http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Organization updated successfully",
	})
}
