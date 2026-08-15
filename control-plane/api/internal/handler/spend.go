package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/store"
)

type SpendHandler struct {
	store DataStore
}

func NewSpendHandler(s DataStore) *SpendHandler {
	return &SpendHandler{store: s}
}

// GET /api/v1/spend/budgets
func (h *SpendHandler) ListBudgets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := middleware.TenantIDFromContext(ctx)
	budgets, err := h.store.ListSpendBudgets(ctx, tenantID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if budgets == nil {
		budgets = []store.SpendBudget{}
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(budgets)
}

// POST /api/v1/spend/budgets
func (h *SpendHandler) CreateBudget(w http.ResponseWriter, r *http.Request) {
	var req store.SpendBudget
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	
	ctx := r.Context()
	tenantID := middleware.TenantIDFromContext(ctx)
	if err := h.store.UpsertSpendBudget(ctx, tenantID, &req); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// GET /api/v1/spend/snapshots
func (h *SpendHandler) ListSnapshots(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := middleware.TenantIDFromContext(ctx)
	snapshots, err := h.store.ListSpendSnapshots(ctx, tenantID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if snapshots == nil {
		snapshots = []store.SpendSnapshot{}
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snapshots)
}

// POST /api/v1/spend/snapshots
func (h *SpendHandler) SyncSnapshot(w http.ResponseWriter, r *http.Request) {
	var req store.SpendSnapshot
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	
	ctx := r.Context()
	tenantID := middleware.TenantIDFromContext(ctx)
	if err := h.store.UpsertSpendSnapshot(ctx, tenantID, &req); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusCreated)
}

// GET /api/v1/spend/requests
func (h *SpendHandler) ListIncreaseRequests(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := middleware.TenantIDFromContext(ctx)
	reqs, err := h.store.ListIncreaseRequests(ctx, tenantID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if reqs == nil {
		reqs = []store.IncreaseRequest{}
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reqs)
}

// POST /api/v1/spend/requests
func (h *SpendHandler) SubmitIncreaseRequest(w http.ResponseWriter, r *http.Request) {
	var req store.IncreaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	req.Status = "pending"
	
	ctx := r.Context()
	tenantID := middleware.TenantIDFromContext(ctx)
	if err := h.store.InsertIncreaseRequest(ctx, tenantID, &req); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusCreated)
}

// POST /api/v1/spend/requests/{id}/resolve
func (h *SpendHandler) ResolveIncreaseRequest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		id = r.PathValue("id")
	}
	if id == "" {
		http.Error(w, `{"error":"missing request id"}`, http.StatusBadRequest)
		return
	}
	
	var req struct {
		Status     string  `json:"status"`
		ResolvedBy string  `json:"resolved_by"`
		NewCap     *int64  `json:"new_cap"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	
	ctx := r.Context()
	tenantID := middleware.TenantIDFromContext(ctx)
	if err := h.store.ResolveIncreaseRequest(ctx, tenantID, id, req.Status, req.ResolvedBy, req.NewCap); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusOK)
}
