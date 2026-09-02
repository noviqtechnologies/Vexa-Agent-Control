package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
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
	HubURL    string `json:"hub_url,omitempty"`
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

	tenantID := middleware.ResolveTenantScope(r)

	actor := "admin_operator"
	if claims := middleware.UserClaimsFromContext(r.Context()); claims != nil && claims.UserID != "" {
		actor = claims.UserID
	}

	rec, err := h.Store.CreateEnrollmentTokenV2(
		r.Context(),
		tenantID,
		rawToken,
		tokenHint,
		req.DeviceLabel,
		req.TargetOwnerSub,
		req.Reason,
		actor,
		req.ExpiresInMinutes,
	)

	if err != nil {
		log.Printf("[AdminV2Handler.CreateEnrollmentToken] Error inserting enrollment token for tenant %s: %v", tenantID, err)
		http.Error(w, fmt.Sprintf(`{"error":{"code":"internal_error","message":%q}}`, err.Error()), http.StatusInternalServerError)
		return
	}

	hubURL := os.Getenv("AGENTCONTROL_HUB_URL")
	if hubURL == "" {
		hubURL = os.Getenv("PUBLIC_API_URL")
	}
	if hubURL == "" {
		hubURL = os.Getenv("HUB_URL")
	}

	resp := CreateTokenResponseV2{
		ID:        rec.ID,
		Token:     rawToken,
		TokenHint: rec.TokenHint,
		ExpiresAt: rec.ExpiresAt.Format("2006-01-02T15:04:05.000Z"),
		MaxUses:   rec.MaxUses,
		Status:    string(rec.Status),
		HubURL:    hubURL,
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

	tenantID := middleware.ResolveTenantScope(r)

	err := h.Store.RevokeDevice(r.Context(), tenantID, deviceID)
	if err != nil {
		log.Printf("RevokeDevice error for device %s: %v", deviceID, err)
		if errors.Is(err, store.ErrDeviceNotFound) {
			http.Error(w, `{"error":{"code":"device_not_found","message":"Device not found or already revoked"}}`, http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf(`{"error":{"code":"internal_error","message":"%s"}}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"device_id": deviceID,
		"state":     "REVOKED",
		"message":   "Device has been revoked and all active credentials invalidated",
	})
}
