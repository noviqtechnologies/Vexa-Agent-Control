package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/store"
)

type AdminV2Handler struct {
	Store *store.Store
}

func NewAdminV2Handler(st *store.Store) *AdminV2Handler {
	return &AdminV2Handler{Store: st}
}

type CreateTokenRequestV2 struct {
	SchemaVersion    string `json:"schema_version"`
	ExpiresInMinutes int    `json:"expires_in_minutes"`
	DeviceLabel      string `json:"device_label"`
	TargetOwnerSub   string `json:"target_owner_subject"`
	Reason           string `json:"reason"`
}

type CreateTokenResponseV2 struct {
	ID        string `json:"id"`
	Token     string `json:"token"`
	TokenHint string `json:"token_hint"`
	ExpiresAt string `json:"expires_at"`
	MaxUses   int    `json:"max_uses"`
	Status    string `json:"status"`
}

// POST /api/v2/admin/enrollment-tokens
func (h *AdminV2Handler) CreateEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var req CreateTokenRequestV2
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":{"code":"invalid_schema"}}`, http.StatusBadRequest)
		return
	}

	if req.ExpiresInMinutes <= 0 {
		req.ExpiresInMinutes = 480
	}

	// Generate CSPRNG Token
	rawBytes := make([]byte, 24)
	_, _ = rand.Read(rawBytes)
	rawToken := fmt.Sprintf("OTET-%s", hex.EncodeToString(rawBytes))
	tokenHint := fmt.Sprintf("OTET-...%s", rawToken[len(rawToken)-4:])

	tenantID := "00000000-0000-0000-0000-000000000001"

	rec, err := h.Store.CreateEnrollmentTokenV2(
		r.Context(),
		tenantID,
		rawToken,
		tokenHint,
		req.DeviceLabel,
		req.TargetOwnerSub,
		req.Reason,
		"admin_operator",
		req.ExpiresInMinutes,
	)

	if err != nil {
		http.Error(w, `{"error":{"code":"internal_error"}}`, http.StatusInternalServerError)
		return
	}

	resp := CreateTokenResponseV2{
		ID:        rec.ID,
		Token:     rawToken,
		TokenHint: rec.TokenHint,
		ExpiresAt: rec.ExpiresAt.Format("2006-01-02T15:04:05.000Z"),
		MaxUses:   rec.MaxUses,
		Status:    string(rec.Status),
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

type RevokeDeviceRequestV2 struct {
	Reason            string `json:"reason"`
	IncidentReference string `json:"incident_reference,omitempty"`
}

// POST /api/v2/admin/devices/{device_id}/revoke
func (h *AdminV2Handler) RevokeDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		deviceID = chi.URLParam(r, "id")
	}
	if deviceID == "" {
		http.Error(w, `{"error":{"code":"invalid_device_id"}}`, http.StatusBadRequest)
		return
	}

	var req RevokeDeviceRequestV2
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":{"code":"invalid_schema"}}`, http.StatusBadRequest)
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = r.Header.Get("X-Organization-ID")
	}
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	err := h.Store.RevokeDeviceV2(r.Context(), tenantID, deviceID, req.Reason, "admin_operator")
	if err != nil {
		log.Printf("RevokeDevice error for device %s: %v", deviceID, err)
		http.Error(w, `{"error":{"code":"device_not_found","message":"Device not found or already revoked"}}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"device_id": deviceID,
		"state":     "REVOKED",
		"message":   "Device has been revoked and all active credentials invalidated",
	})
}
