package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/spend"
)

type SpendV2Handler struct {
	store *spend.Store
}

func NewSpendV2Handler(s *spend.Store) *SpendV2Handler {
	return &SpendV2Handler{store: s}
}

// resolveContextOrgAndActor safely resolves organization/tenant and actor from authenticated context
func resolveContextOrgAndActor(r *http.Request) (string, string) {
	orgID := middleware.ResolveTenantScope(r)

	// 1. Check Device Principal (mTLS authenticated gateway)
	if dev, ok := r.Context().Value(middleware.DevicePrincipalKey).(*model.DevicePrincipal); ok && dev != nil {
		return orgID, dev.DeviceID
	}

	// 2. Check User Claims (Dashboard operator)
	if user, ok := r.Context().Value(middleware.UserClaimsKey).(*middleware.UserClaims); ok && user != nil {
		return orgID, user.UserID
	}

	return orgID, "gateway-workload"
}

// POST /api/v2/spend/authorize
func (h *SpendV2Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	var req spend.AuthorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request payload"}`, http.StatusBadRequest)
		return
	}

	orgID, actor := resolveContextOrgAndActor(r)
	if req.GatewayID == "" {
		req.GatewayID = actor
	}

	resp, err := h.store.Authorize(r.Context(), orgID, &req)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if resp.Decision == "deny" {
		w.WriteHeader(http.StatusTooManyRequests)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(resp)
}

// POST /api/v2/spend/reservations/{reservation_id}/settle
func (h *SpendV2Handler) Settle(w http.ResponseWriter, r *http.Request) {
	reservationID := chi.URLParam(r, "reservation_id")
	if reservationID == "" {
		http.Error(w, `{"error":"missing reservation_id"}`, http.StatusBadRequest)
		return
	}

	var req spend.SettleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request payload"}`, http.StatusBadRequest)
		return
	}

	orgID, _ := resolveContextOrgAndActor(r)
	resp, err := h.store.Settle(r.Context(), orgID, reservationID, &req)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// POST /api/v2/spend/reservations/{reservation_id}/release
func (h *SpendV2Handler) Release(w http.ResponseWriter, r *http.Request) {
	reservationID := chi.URLParam(r, "reservation_id")
	if reservationID == "" {
		http.Error(w, `{"error":"missing reservation_id"}`, http.StatusBadRequest)
		return
	}

	var req spend.ReleaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request payload"}`, http.StatusBadRequest)
		return
	}

	orgID, _ := resolveContextOrgAndActor(r)
	resp, err := h.store.Release(r.Context(), orgID, reservationID, &req)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// GET /api/v2/spend/effective
func (h *SpendV2Handler) GetEffective(w http.ResponseWriter, r *http.Request) {
	orgID, _ := resolveContextOrgAndActor(r)
	windows, err := h.store.ListEffectiveBudgetWindows(r.Context(), orgID)
	if err != nil {
		http.Error(w, `{"error":"failed to fetch effective budgets"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"organization_id": orgID,
		"windows":         windows,
	})
}

// GET /api/v2/spend/events
func (h *SpendV2Handler) ListEvents(w http.ResponseWriter, r *http.Request) {
	orgID, _ := resolveContextOrgAndActor(r)
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil {
			limit = val
		}
	}

	events, err := h.store.ListSpendEvents(r.Context(), orgID, limit)
	if err != nil {
		http.Error(w, `{"error":"failed to fetch spend events"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"organization_id": orgID,
		"events":          events,
	})
}

// GET /api/v2/spend/policies
func (h *SpendV2Handler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	orgID, _ := resolveContextOrgAndActor(r)
	policies, err := h.store.ListPolicies(r.Context(), orgID)
	if err != nil {
		http.Error(w, `{"error":"failed to fetch policies"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"policies": policies,
	})
}

// POST /api/v2/spend/policies
func (h *SpendV2Handler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScopeType       string  `json:"scope_type"`
		ScopeID         string  `json:"scope_id"`
		PeriodType      string  `json:"period_type"`
		LimitMicrocents *int64  `json:"limit_microcents"`
		LimitUSD        *float64 `json:"limit_usd"`
		Action          string  `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request payload"}`, http.StatusBadRequest)
		return
	}

	orgID, _ := resolveContextOrgAndActor(r)
	var limit spend.MoneyMicrocents
	if req.LimitMicrocents != nil {
		limit = spend.MoneyMicrocents(*req.LimitMicrocents)
	} else if req.LimitUSD != nil {
		limit = spend.DollarsToMicrocents(*req.LimitUSD)
	} else {
		http.Error(w, `{"error":"limit_microcents or limit_usd required"}`, http.StatusBadRequest)
		return
	}

	action := req.Action
	if action == "" {
		action = spend.ActionHardDeny
	}
	period := req.PeriodType
	if period == "" {
		period = spend.PeriodDaily
	}
	scopeType := req.ScopeType
	if scopeType == "" {
		scopeType = spend.ScopeOrganization
	}
	scopeID := req.ScopeID
	if scopeType == spend.ScopeOrganization {
		scopeID = orgID
	} else if scopeType == spend.ScopeProvider {
		scopeID = strings.ToLower(strings.TrimSpace(scopeID))
		if scopeID == "" {
			scopeID = "openai"
		}
	} else if scopeID == "" {
		scopeID = "default"
	}

	p := spend.SpendPolicy{
		OrganizationID:  orgID,
		ScopeType:       scopeType,
		ScopeID:         scopeID,
		Currency:        spend.CurrencyUSD,
		PeriodType:      period,
		LimitMicrocents: limit,
		Action:          action,
	}

	if err := h.store.CreatePolicy(r.Context(), &p); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// Auto-publish to ensure active version exists
	pv, err := h.store.PublishPolicy(r.Context(), orgID, p.PolicyID, "admin")
	if err != nil {
		http.Error(w, `{"error":"failed to publish policy: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "created_and_published",
		"policy":         p,
		"policy_version": pv,
	})
}

// POST /api/v2/spend/policies/{id}/publish
func (h *SpendV2Handler) PublishPolicy(w http.ResponseWriter, r *http.Request) {
	policyID := chi.URLParam(r, "id")
	if policyID == "" {
		http.Error(w, `{"error":"missing policy id"}`, http.StatusBadRequest)
		return
	}

	orgID, actor := resolveContextOrgAndActor(r)
	pv, err := h.store.PublishPolicy(r.Context(), orgID, policyID, actor)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pv)
}

// GET /api/v2/spend/increase-requests
func (h *SpendV2Handler) ListIncreaseRequests(w http.ResponseWriter, r *http.Request) {
	orgID, _ := resolveContextOrgAndActor(r)
	reqs, err := h.store.ListIncreaseRequests(r.Context(), orgID)
	if err != nil {
		http.Error(w, `{"error":"failed to fetch increase requests"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"requests": reqs,
	})
}

// POST /api/v2/spend/increase-requests
func (h *SpendV2Handler) CreateIncreaseRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProjectID                string  `json:"project_id"`
		RequestedLimitMicrocents *int64  `json:"requested_limit_microcents"`
		RequestedLimitUSD        *float64 `json:"requested_limit_usd"`
		CurrentLimitMicrocents   int64   `json:"current_limit_microcents"`
		Reason                   string  `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request payload"}`, http.StatusBadRequest)
		return
	}

	orgID, actor := resolveContextOrgAndActor(r)
	var requestedLimit spend.MoneyMicrocents
	if req.RequestedLimitMicrocents != nil {
		requestedLimit = spend.MoneyMicrocents(*req.RequestedLimitMicrocents)
	} else if req.RequestedLimitUSD != nil {
		requestedLimit = spend.DollarsToMicrocents(*req.RequestedLimitUSD)
	} else {
		http.Error(w, `{"error":"requested limit required"}`, http.StatusBadRequest)
		return
	}

	projID := req.ProjectID
	if projID == "" {
		projID = "default"
	}

	rV2 := spend.IncreaseRequestV2{
		OrganizationID:           orgID,
		ProjectID:                projID,
		RequestedLimitMicrocents: requestedLimit,
		CurrentLimitMicrocents:   spend.MoneyMicrocents(req.CurrentLimitMicrocents),
		Reason:                   req.Reason,
		CreatedBy:                actor,
	}

	if err := h.store.CreateIncreaseRequest(r.Context(), &rV2); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(rV2)
}

// POST /api/v2/spend/increase-requests/{id}/decide
func (h *SpendV2Handler) DecideIncreaseRequest(w http.ResponseWriter, r *http.Request) {
	reqID := chi.URLParam(r, "id")
	if reqID == "" {
		http.Error(w, `{"error":"missing request id"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Decision string `json:"decision"` // APPROVED | REJECTED
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request payload"}`, http.StatusBadRequest)
		return
	}

	orgID, actor := resolveContextOrgAndActor(r)
	status := "APPROVED"
	if req.Decision == "REJECTED" || req.Decision == "deny" || req.Decision == "rejected" {
		status = "REJECTED"
	}

	if err := h.store.ResolveIncreaseRequest(r.Context(), orgID, reqID, status, actor, req.Reason); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "resolved",
		"decision": status,
	})
}
