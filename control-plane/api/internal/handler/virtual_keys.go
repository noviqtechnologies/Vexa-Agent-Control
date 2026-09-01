package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type VirtualKeyHandler struct {
	store       DataStore
	broadcaster *InvalidationBroadcaster
}

func NewVirtualKeyHandler(store DataStore, broadcaster *InvalidationBroadcaster) *VirtualKeyHandler {
	return &VirtualKeyHandler{
		store:       store,
		broadcaster: broadcaster,
	}
}

type CreateVirtualKeyRequest struct {
	Name                    string            `json:"name"`
	TeamID                  string            `json:"team_id,omitempty"`
	ExpiresAt               *time.Time        `json:"expires_at,omitempty"`
	AllowedIPs              []string          `json:"allowed_ips,omitempty"`
	MaxRPM                  int               `json:"max_rpm,omitempty"`
	MaxTPM                  int               `json:"max_tpm,omitempty"`
	MaxConcurrentRequests   int               `json:"max_concurrent_requests,omitempty"`
	MonthlyBudgetMicrocents int64             `json:"monthly_budget_microcents,omitempty"`
	AllowedModels           []string          `json:"allowed_models,omitempty"`
	AllowedRoutes           []string          `json:"allowed_routes,omitempty"`
	Tags                    map[string]string `json:"tags,omitempty"`
	OwnerType               string            `json:"owner_type,omitempty"`
	BudgetPeriod            string            `json:"budget_period,omitempty"`
}

type CreateVirtualKeyResponse struct {
	Key      store.VirtualKey `json:"virtual_key"`
	RawSecret string          `json:"raw_secret"` // Returned ONLY upon creation
}

func generateVirtualKeySecret(prefix string) (rawSecret, keyHash, keyPrefix string, err error) {
	randomBytes := make([]byte, 24)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", "", fmt.Errorf("generate random bytes: %w", err)
	}
	randomHex := hex.EncodeToString(randomBytes)
	rawSecret = fmt.Sprintf("sk-vex-%s", randomHex)

	hasher := sha256.New()
	hasher.Write([]byte(rawSecret))
	keyHash = hex.EncodeToString(hasher.Sum(nil))

	keyPrefix = fmt.Sprintf("sk-vex-%s...", randomHex[:6])
	return rawSecret, keyHash, keyPrefix, nil
}

func (h *VirtualKeyHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := getTenantID(r)
	if tenantID == "" {
		http.Error(w, `{"error":"unauthorized","message":"missing tenant context"}`, http.StatusUnauthorized)
		return
	}

	var req CreateVirtualKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad_request","message":"invalid json payload"}`, http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		http.Error(w, `{"error":"bad_request","message":"name is required"}`, http.StatusBadRequest)
		return
	}

	rawSecret, keyHash, keyPrefix, err := generateVirtualKeySecret(req.Name)
	if err != nil {
		http.Error(w, `{"error":"internal","message":"failed to generate key"}`, http.StatusInternalServerError)
		return
	}

	ownerType := req.OwnerType
	if ownerType == "" {
		ownerType = "user"
	}
	budgetPeriod := req.BudgetPeriod
	if budgetPeriod == "" {
		budgetPeriod = "monthly"
	}

	vk := store.VirtualKey{
		TenantID:                tenantID,
		KeyHash:                 keyHash,
		KeyPrefix:               keyPrefix,
		Name:                    req.Name,
		TeamID:                  req.TeamID,
		CreatedBy:               "admin",
		CreatedAt:               time.Now().UTC(),
		ExpiresAt:               req.ExpiresAt,
		AllowedIPs:              req.AllowedIPs,
		MaxRPM:                  req.MaxRPM,
		MaxTPM:                  req.MaxTPM,
		MaxConcurrentRequests:   req.MaxConcurrentRequests,
		MonthlyBudgetMicrocents: req.MonthlyBudgetMicrocents,
		SpentMicrocents:         0,
		AllowedModels:           req.AllowedModels,
		AllowedRoutes:           req.AllowedRoutes,
		Status:                  "active",
		Tags:                    req.Tags,
		OwnerType:               ownerType,
		BudgetPeriod:            budgetPeriod,
	}

	if err := h.store.CreateVirtualKey(r.Context(), tenantID, &vk); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"internal","message":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(CreateVirtualKeyResponse{
		Key:       vk,
		RawSecret: rawSecret,
	})
}

func (h *VirtualKeyHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := getTenantID(r)
	if tenantID == "" {
		http.Error(w, `{"error":"unauthorized","message":"missing tenant context"}`, http.StatusUnauthorized)
		return
	}

	keys, err := h.store.ListVirtualKeys(r.Context(), tenantID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"internal","message":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"virtual_keys": keys,
	})
}

func (h *VirtualKeyHandler) ListDeleted(w http.ResponseWriter, r *http.Request) {
	tenantID := getTenantID(r)
	limit := queryInt(r, "limit", 50)
	offset := queryInt(r, "offset", 0)

	keys, err := h.store.ListDeletedVirtualKeys(r.Context(), tenantID, limit, offset)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"internal","message":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	if keys == nil {
		keys = []store.VirtualKey{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"deleted_virtual_keys": keys,
		"total":                len(keys),
	})
}

func (h *VirtualKeyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := getTenantID(r)
	id := chi.URLParam(r, "id")

	actor := r.Header.Get("X-User-Subject")
	if actor == "" {
		actor = r.Header.Get("X-User-Email")
	}
	if actor == "" {
		actor = "admin"
	}
	reason := r.URL.Query().Get("reason")
	if reason == "" {
		reason = "user_revoked"
	}

	key, err := h.store.GetVirtualKeyByID(r.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, store.ErrVirtualKeyNotFound) {
			http.Error(w, `{"error":"not_found","message":"virtual key not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf(`{"error":"internal","message":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	if err := h.store.DeleteVirtualKeyWithActor(r.Context(), tenantID, id, actor, reason); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"internal","message":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Broadcast eviction event to all connected edge proxies
	if h.broadcaster != nil {
		h.broadcaster.Broadcast(InvalidationEvent{
			Action:   "evict_key",
			KeyHash:  key.KeyHash,
			TenantID: tenantID,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "revoked",
		"id":     id,
	})
}


type RotateRequest struct {
	GracePeriodSeconds int `json:"grace_period_seconds"`
}

func (h *VirtualKeyHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	tenantID := getTenantID(r)
	id := chi.URLParam(r, "id")

	var req RotateRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	gracePeriod := 3600 * time.Second
	if req.GracePeriodSeconds > 0 {
		gracePeriod = time.Duration(req.GracePeriodSeconds) * time.Second
	}

	rawSecret, newKeyHash, newKeyPrefix, err := generateVirtualKeySecret(id)
	if err != nil {
		http.Error(w, `{"error":"internal","message":"failed to generate key"}`, http.StatusInternalServerError)
		return
	}

	rotated, err := h.store.RotateVirtualKey(r.Context(), tenantID, id, newKeyHash, newKeyPrefix, gracePeriod)
	if err != nil {
		if errors.Is(err, store.ErrVirtualKeyNotFound) {
			http.Error(w, `{"error":"not_found","message":"virtual key not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf(`{"error":"internal","message":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Broadcast eviction event for old key
	if h.broadcaster != nil && rotated.PreviousKeyHash != nil {
		h.broadcaster.Broadcast(InvalidationEvent{
			Action:   "evict_key",
			KeyHash:  *rotated.PreviousKeyHash,
			TenantID: tenantID,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(CreateVirtualKeyResponse{
		Key:       *rotated,
		RawSecret: rawSecret,
	})
}

func (h *VirtualKeyHandler) Reset(w http.ResponseWriter, r *http.Request) {
	tenantID := getTenantID(r)
	id := chi.URLParam(r, "id")

	if err := h.store.ResetVirtualKeySpend(r.Context(), tenantID, id); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"internal","message":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "reset",
		"id":     id,
	})
}

// Resolve is the internal endpoint called by Rust edge proxy to resolve metadata by key hash.
func (h *VirtualKeyHandler) Resolve(w http.ResponseWriter, r *http.Request) {
	keyHash := r.URL.Query().Get("hash")
	if keyHash == "" {
		http.Error(w, `{"error":"bad_request","message":"hash query parameter required"}`, http.StatusBadRequest)
		return
	}

	key, err := h.store.GetVirtualKeyByHash(r.Context(), keyHash)
	if err != nil {
		if errors.Is(err, store.ErrVirtualKeyNotFound) {
			http.Error(w, `{"error":"not_found","message":"virtual key not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf(`{"error":"internal","message":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(key)
}
