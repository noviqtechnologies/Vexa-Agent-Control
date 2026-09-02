package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/license"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type SaaSOperatorHandler struct {
	store         *store.Store
	licenseIssuer *license.Issuer
}

func NewSaaSOperatorHandler(s *store.Store, issuer *license.Issuer) *SaaSOperatorHandler {
	return &SaaSOperatorHandler{
		store:         s,
		licenseIssuer: issuer,
	}
}

type CreateOrgResponse struct {
	Organization   *model.Organization `json:"organization"`
	BootstrapToken string              `json:"bootstrap_token"`
	ConsoleURL     string              `json:"console_url"`
}

func (h *SaaSOperatorHandler) CreateOrganization(w http.ResponseWriter, r *http.Request) {
	var req model.CreateOrgReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))
	if req.Slug == "" {
		http.Error(w, "slug is required", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		req.Name = req.Slug
	}
	if req.LicenseTier == "" {
		req.LicenseTier = "developer"
	}
	if req.MaxSeats <= 0 {
		req.MaxSeats = 1
	}

	validDays := req.ValidDays
	if req.IsTrial {
		validDays = 15
	} else if validDays <= 0 {
		validDays = 365
	}

	now := time.Now().UTC()
	var expiresAt time.Time
	hasExpiry := validDays > 0
	if hasExpiry {
		expiresAt = now.AddDate(0, 0, validDays)
	}

	var licenseJWT string
	if h.licenseIssuer != nil {
		features := license.TierToFeatures(req.LicenseTier)
		jwtStr, exp, err := h.licenseIssuer.MintLicense(req.Slug, req.LicenseTier, req.MaxSeats, features, validDays, req.IsTrial)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to mint license: %v", err), http.StatusInternalServerError)
			return
		}
		licenseJWT = jwtStr
		expiresAt = exp
		hasExpiry = true
	}

	org := &model.Organization{
		Name:          req.Name,
		Slug:          req.Slug,
		ContactEmail:  req.ContactEmail,
		LicenseTier:   req.LicenseTier,
		MaxDevices:    req.MaxSeats,
		LicenseKeyJWT: licenseJWT,
	}

	if hasExpiry {
		org.LicenseExpiresAt = &expiresAt
	}

	rawBootstrapToken := "boot_" + req.Slug
	if h.store != nil {
		_ = h.store.UpdateOrganization(r.Context(), org.ID, org.Name, org.ContactEmail)
	}

	resp := CreateOrgResponse{
		Organization:   org,
		BootstrapToken: rawBootstrapToken,
		ConsoleURL:     "http://localhost:8081",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *SaaSOperatorHandler) ListOrganizations(w http.ResponseWriter, r *http.Request) {
	orgID := store.DefaultOrgID
	summary, err := h.store.GetOrganizationSummary(r.Context(), orgID)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get organization summary: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode([]*model.OrganizationSummary{summary})
}

func (h *SaaSOperatorHandler) GetOrganization(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	org, err := h.store.GetOrganization(r.Context(), id)
	if err != nil {
		http.Error(w, fmt.Sprintf("database error: %v", err), http.StatusInternalServerError)
		return
	}
	if org == nil {
		http.Error(w, "organization not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(org)
}

func (h *SaaSOperatorHandler) UpdateOrganization(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req model.UpdateOrgReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.store.UpdateOrganization(r.Context(), id, req.Name, req.ContactEmail); err != nil {
		http.Error(w, fmt.Sprintf("failed to update organization: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (h *SaaSOperatorHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (h *SaaSOperatorHandler) RenewLicense(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req model.RenewLicenseReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	org, err := h.store.GetOrganization(r.Context(), id)
	if err != nil || org == nil {
		http.Error(w, "organization not found", http.StatusNotFound)
		return
	}

	if req.AdditionalDays <= 0 {
		req.AdditionalDays = 30
	}

	var jwtStr string
	now := time.Now().UTC()
	newExpiry := now.AddDate(0, 0, req.AdditionalDays)

	if h.licenseIssuer != nil {
		features := license.TierToFeatures(org.LicenseTier)
		mintedJWT, exp, err := h.licenseIssuer.MintLicense(org.Slug, org.LicenseTier, org.MaxDevices, features, req.AdditionalDays, req.IsTrial)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to mint renewed license: %v", err), http.StatusInternalServerError)
			return
		}
		jwtStr = mintedJWT
		newExpiry = exp
	}

	if err := h.store.UpdateLicenseKey(r.Context(), id, jwtStr, org.LicenseTier, org.MaxDevices, &newExpiry); err != nil {
		http.Error(w, fmt.Sprintf("failed to update license in database: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      "ok",
		"license_jwt": jwtStr,
		"expires_at":  newExpiry,
	})
}

func (h *SaaSOperatorHandler) RegenerateBootstrapToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":          "ok",
		"bootstrap_token": "boot_regenerated",
	})
}

func (h *SaaSOperatorHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
}
