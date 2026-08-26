package handler

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type DeviceV2Handler struct {
	Store *store.Store
}

func NewDeviceV2Handler(st *store.Store) *DeviceV2Handler {
	return &DeviceV2Handler{Store: st}
}

// BootstrapResponseV2 represents the signed policy and settings for an enrolled device.
type BootstrapResponseV2 struct {
	DeviceID    string               `json:"device_id"`
	DeviceState model.DeviceState    `json:"device_state"`
	Mode        string               `json:"mode"`
	Policy      model.PolicyEnvelope `json:"policy"`
	Heartbeat   struct {
		IntervalSeconds int `json:"interval_seconds"`
		JitterSeconds   int `json:"jitter_seconds"`
	} `json:"heartbeat"`
	Remediation []struct {
		Code   string `json:"code"`
		Action string `json:"action"`
	} `json:"remediation"`
	EventStream string `json:"event_stream"`
}

// GET /api/v2/device/bootstrap
func (h *DeviceV2Handler) GetBootstrap(w http.ResponseWriter, r *http.Request) {
	principal, ok := middleware.GetDevicePrincipal(r.Context())
	if !ok {
		http.Error(w, `{"error":{"code":"device_auth_required"}}`, http.StatusUnauthorized)
		return
	}

	var resp BootstrapResponseV2
	resp.DeviceID = principal.DeviceID
	resp.DeviceState = principal.DeviceState
	resp.Mode = "TEAM_ENFORCE"
	resp.Heartbeat.IntervalSeconds = 600
	resp.Heartbeat.JitterSeconds = 60
	resp.EventStream = "/api/v2/device/events/stream"

	// Construct signed policy envelope with authentic SHA256 & Ed25519 signature
	resp.Policy.ID = "pol_0198d5b4-default"
	resp.Policy.Version = 1
	resp.Policy.Mode = "TEAM_ENFORCE"
	resp.Policy.Content = "version: 2\ndefault_action: deny\nenforce_safe_mode: true\n"
	
	contentBytes := []byte(resp.Policy.Content)
	hasher := sha256.New()
	hasher.Write(contentBytes)
	contentHash := hex.EncodeToString(hasher.Sum(nil))
	resp.Policy.SHA256 = contentHash

	seed := sha256.Sum256([]byte("vexa-hub-policy-signing-seed-2026"))
	privKey := ed25519.NewKeyFromSeed(seed[:])
	sig := ed25519.Sign(privKey, []byte(contentHash))

	resp.Policy.Signature.Algorithm = "Ed25519"
	resp.Policy.Signature.KeyID = "vexa-policy-signer-2026-01"
	resp.Policy.Signature.Value = base64.StdEncoding.EncodeToString(sig)
	resp.Policy.IssuedAt = time.Now().UTC()
	resp.Policy.ExpiresAt = time.Now().UTC().Add(24 * time.Hour)

	if principal.DeviceState == model.DeviceStatePending {
		resp.Remediation = append(resp.Remediation, struct {
			Code   string `json:"code"`
			Action string `json:"action"`
		}{Code: "WRAPPER_INVENTORY_REQUIRED", Action: "run_status"})
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

// POST /api/v2/device/heartbeats
func (h *DeviceV2Handler) SubmitHeartbeat(w http.ResponseWriter, r *http.Request) {
	principal, ok := middleware.GetDevicePrincipal(r.Context())
	if !ok {
		http.Error(w, `{"error":{"code":"device_auth_required"}}`, http.StatusUnauthorized)
		return
	}

	var req model.HeartbeatPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":{"code":"invalid_schema"}}`, http.StatusBadRequest)
		return
	}

	// Evaluate device state based on self-report
	targetState := model.DeviceStateCompliant
	if req.Coverage.WrappedTargets == 0 && req.Coverage.SupportedTargets > 0 {
		targetState = model.DeviceStateNonCompliant
	}

	if principal.DeviceState != targetState {
		if err := h.Store.TransitionDeviceState(
			r.Context(),
			principal.TenantID,
			principal.DeviceID,
			targetState,
			"HEARTBEAT_EVALUATION",
			"SYSTEM",
			"heartbeat_worker",
			principal.RequestID,
		); err != nil {
			log.Printf("state transition error: %v", err)
			http.Error(w, `{"error":{"code":"internal_error"}}`, http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"device_state":                 targetState,
		"next_heartbeat_after_seconds": 600,
		"remediation":                  []string{},
		"policy_refresh_required":      false,
	})
}

// GET /api/v2/device/status
func (h *DeviceV2Handler) GetDeviceStatus(w http.ResponseWriter, r *http.Request) {
	principal, ok := middleware.GetDevicePrincipal(r.Context())
	if !ok {
		http.Error(w, `{"error":{"code":"device_auth_required"}}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"device_id":          principal.DeviceID,
		"device_state":       principal.DeviceState,
		"credential_status":  principal.CredentialStatus,
		"certificate_serial": principal.CertificateSerial,
		"capabilities":       principal.Capabilities,
		"timestamp":          time.Now().UTC(),
	})
}
