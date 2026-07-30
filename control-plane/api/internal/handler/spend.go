package handler

import (
	"encoding/json"
	"net/http"

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
	budgets, err := h.store.ListSpendBudgets(ctx)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
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
	if err := h.store.UpsertSpendBudget(ctx, &req); err != nil {
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
	snapshots, err := h.store.ListSpendSnapshots(ctx)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snapshots)
}

// POST /api/v1/spend/snapshots
// Used by the local agentwall gateway to sync snapshots to the dashboard DB
func (h *SpendHandler) SyncSnapshot(w http.ResponseWriter, r *http.Request) {
	var req store.SpendSnapshot
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	
	ctx := r.Context()
	if err := h.store.UpsertSpendSnapshot(ctx, &req); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusCreated)
}

// GET /api/v1/spend/requests
func (h *SpendHandler) ListIncreaseRequests(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reqs, err := h.store.ListIncreaseRequests(ctx)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
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
	if err := h.store.InsertIncreaseRequest(ctx, &req); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusCreated)
}

// POST /api/v1/spend/requests/{id}/resolve
func (h *SpendHandler) ResolveIncreaseRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
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
	if err := h.store.ResolveIncreaseRequest(ctx, id, req.Status, req.ResolvedBy, req.NewCap); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusOK)
}
