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
		req.LicenseTier = "community"
	}
	if req.MaxSeats <= 0 {
		req.MaxSeats = 10
	}

	// Check if slug already exists
	existing, err := h.store.GetOrganizationBySlug(r.Context(), req.Slug)
	if err != nil {
		http.Error(w, "database query error", http.StatusInternalServerError)
		return
	}
	if existing != nil {
		http.Error(w, fmt.Sprintf("organization with slug %q already exists", req.Slug), http.StatusConflict)
		return
	}

	// Calculate validity days: trial (15 or 30 days) vs custom agreed days (default 365)
	validDays := req.ValidDays
	if req.IsTrial {
		if req.TrialDays == 30 {
			validDays = 30
		} else {
			validDays = 15
			req.TrialDays = 15
		}
	} else if validDays <= 0 {
		validDays = 365
	}

	// Compute expiration timestamp based on validity days
	now := time.Now().UTC()
	var expiresAt time.Time
	hasExpiry := validDays > 0
	if hasExpiry {
		expiresAt = now.AddDate(0, 0, validDays)
	}

	// Auto-mint license JWT if issuer is available
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
		MaxSeats:      req.MaxSeats,
		LicenseKeyJWT: licenseJWT,
		IsTrial:       req.IsTrial,
		TrialDays:     req.TrialDays,
		Status:        model.OrgStatusActive,
	}

	if hasExpiry {
		org.LicenseExpiresAt = &expiresAt
		if req.IsTrial {
			org.TrialEndsAt = &expiresAt
		}
	}

	rawBootstrapToken, err := h.store.CreateOrganization(r.Context(), org)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create organization: %v", err), http.StatusInternalServerError)
		return
	}

	consoleURL := "https://console.vexasec.io"
	if r.Host != "" {
		if strings.HasPrefix(r.Host, "localhost") || strings.HasPrefix(r.Host, "127.0.0.1") {
			consoleURL = fmt.Sprintf("http://localhost:8081?tenant=%s", req.Slug)
		} else if strings.Contains(r.Host, "console.vexasec.io") {
			consoleURL = "https://console.vexasec.io"
		} else {
			consoleURL = fmt.Sprintf("https://%s", r.Host)
		}
	}

	resp := CreateOrgResponse{
		Organization:   org,
		BootstrapToken: rawBootstrapToken,
		ConsoleURL:     consoleURL,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func (h *SaaSOperatorHandler) ListOrganizations(w http.ResponseWriter, r *http.Request) {
	orgs, err := h.store.ListOrganizations(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to list organizations: %v", err), http.StatusInternalServerError)
		return
	}

	if orgs == nil {
		orgs = []model.OrgSummary{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(orgs)
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
	json.NewEncoder(w).Encode(org)
}

func (h *SaaSOperatorHandler) UpdateOrganization(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req model.UpdateOrgReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.store.UpdateOrganization(r.Context(), id, req); err != nil {
		http.Error(w, fmt.Sprintf("failed to update organization: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (h *SaaSOperatorHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	status := model.OrganizationStatus(body.Status)
	if err := h.store.UpdateOrganizationStatus(r.Context(), id, status); err != nil {
		http.Error(w, fmt.Sprintf("failed to update status: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
		mintedJWT, exp, err := h.licenseIssuer.MintLicense(org.Slug, org.LicenseTier, org.MaxSeats, features, req.AdditionalDays, req.IsTrial)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to mint renewed license: %v", err), http.StatusInternalServerError)
			return
		}
		jwtStr = mintedJWT
		newExpiry = exp
	}

	trialDays := 0
	if req.IsTrial {
		trialDays = req.AdditionalDays
	}

	if err := h.store.UpdateLicense(r.Context(), id, jwtStr, newExpiry, req.IsTrial, trialDays); err != nil {
		http.Error(w, fmt.Sprintf("failed to update license in database: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":      "ok",
		"license_jwt": jwtStr,
		"expires_at":  newExpiry,
	})
}

func (h *SaaSOperatorHandler) RegenerateBootstrapToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rawToken, err := h.store.RegenerateBootstrapToken(r.Context(), id)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to regenerate bootstrap token: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":          "ok",
		"bootstrap_token": rawToken,
	})
}

func (h *SaaSOperatorHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.GetOrganizationStats(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get platform stats: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
