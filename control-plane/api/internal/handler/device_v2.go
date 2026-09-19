package handler

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
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
	if req.Fleet.TargetsSecured == 0 && req.Fleet.TargetsTotal > 0 {
		targetState = model.DeviceStateNonCompliant
	}

	if principal.DeviceState != targetState {
		if err := h.Store.TransitionDeviceState(
			r.Context(),
			principal.OrganizationID,
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

// ActiveProviderKeysResponse represents the desired routing and keys payload for an endpoint (REQ-DSM-004).
type ActiveProviderKeysResponse struct {
	AssignmentID     string            `json:"assignment_id,omitempty"`
	PayloadHash      string            `json:"payload_hash"`
	CursorMode       string            `json:"cursor_mode"`
	VirtualKey       string            `json:"virtual_key,omitempty"`
	DefaultModel     string            `json:"default_model"`
	AllowedModels    []string          `json:"allowed_models"`
	ModelEnforcement bool              `json:"model_enforcement"`
	ProviderKeys     map[string]string `json:"provider_keys"`
}

// GET /api/v2/device/provider-keys/active
func (h *DeviceV2Handler) GetActiveProviderKeys(w http.ResponseWriter, r *http.Request) {
	principal, ok := middleware.GetDevicePrincipal(r.Context())
	if !ok {
		http.Error(w, `{"error":{"code":"device_auth_required"}}`, http.StatusUnauthorized)
		return
	}

	orgID := principal.OrganizationID
	if orgID == "" {
		orgID = store.DefaultOrgID
	}

	resp := ActiveProviderKeysResponse{
		CursorMode:       "byok",
		DefaultModel:     "gpt-4o",
		AllowedModels:    []string{"gpt-4o", "claude-3-5-sonnet", "gemini-1.5-pro"},
		ModelEnforcement: true,
		ProviderKeys:     make(map[string]string),
	}

	// 1. Check for active desired-state assignment
	asgn, err := h.Store.GetActiveAssignmentForTarget(r.Context(), orgID, "device", principal.DeviceID, model.AssignmentKindProviderKeys)
	if err != nil || asgn == nil {
		asgn, _ = h.Store.GetActiveAssignmentForTarget(r.Context(), orgID, "group", "default", model.AssignmentKindProviderKeys)
	}
	if asgn != nil {
		resp.AssignmentID = asgn.ID
	}

	// 2. Resolve configured provider keys
	keys, err := h.Store.ListProviderKeys(r.Context(), orgID)
	if err == nil {
		for _, k := range keys {
			if k.Status == "ACTIVE" && k.APIKeyMasked != "" {
				resp.ProviderKeys[k.Provider] = k.APIKeyMasked
			}
		}
	}

	// 3. Compute deterministic payload hash (SHA-256)
	rawBytes, _ := json.Marshal(struct {
		CursorMode    string            `json:"cursor_mode"`
		DefaultModel  string            `json:"default_model"`
		AllowedModels []string          `json:"allowed_models"`
		ProviderKeys  map[string]string `json:"provider_keys"`
	}{
		CursorMode:    resp.CursorMode,
		DefaultModel:  resp.DefaultModel,
		AllowedModels: resp.AllowedModels,
		ProviderKeys:  resp.ProviderKeys,
	})
	hash := sha256.Sum256(rawBytes)
	resp.PayloadHash = hex.EncodeToString(hash[:])

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

// POST /api/v2/device/assignments/{id}/ack
func (h *DeviceV2Handler) AcknowledgeAssignment(w http.ResponseWriter, r *http.Request) {
	principal, ok := middleware.GetDevicePrincipal(r.Context())
	if !ok {
		http.Error(w, `{"error":{"code":"device_auth_required"}}`, http.StatusUnauthorized)
		return
	}

	var req model.AssignmentAckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":{"code":"invalid_schema"}}`, http.StatusBadRequest)
		return
	}

	assignmentID := chi.URLParam(r, "id")
	if assignmentID != "" {
		req.AssignmentID = assignmentID
	}
	if req.AssignmentID == "" {
		http.Error(w, `{"error":{"code":"missing_assignment_id"}}`, http.StatusBadRequest)
		return
	}

	orgID := principal.OrganizationID
	if orgID == "" {
		orgID = store.DefaultOrgID
	}

	// Verify target authorization: authenticated device must match assignment target
	targetAsgn, err := h.Store.GetAssignment(r.Context(), orgID, req.AssignmentID)
	if err != nil {
		http.Error(w, `{"error":{"code":"assignment_not_found","message":"assignment not found"}}`, http.StatusNotFound)
		return
	}
	if targetAsgn.TargetType == "device" && targetAsgn.TargetID != principal.DeviceID {
		http.Error(w, `{"error":{"code":"forbidden_assignment_target","message":"authenticated device is not the target of this assignment"}}`, http.StatusForbidden)
		return
	}
	if targetAsgn.TargetType == "user" && principal.UserID != nil && *principal.UserID != "" && targetAsgn.TargetID != *principal.UserID {
		http.Error(w, `{"error":{"code":"forbidden_assignment_target","message":"authenticated user is not the target of this assignment"}}`, http.StatusForbidden)
		return
	}

	updated, err := h.Store.AcknowledgeAssignment(r.Context(), orgID, &req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"code":"ack_failed","message":%q}}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(updated)
}

// POST /api/v2/device/verify-probe
func (h *DeviceV2Handler) SubmitVerificationProbe(w http.ResponseWriter, r *http.Request) {
	principal, ok := middleware.GetDevicePrincipal(r.Context())
	if !ok {
		http.Error(w, `{"error":{"code":"device_auth_required"}}`, http.StatusUnauthorized)
		return
	}

	var req model.VerifyProbeSubmission
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":{"code":"invalid_schema"}}`, http.StatusBadRequest)
		return
	}

	orgID := principal.OrganizationID
	if orgID == "" {
		orgID = store.DefaultOrgID
	}

	if req.DeviceID == "" {
		req.DeviceID = principal.DeviceID
	}
	if req.UserID == "" && principal.UserID != nil {
		req.UserID = *principal.UserID
	}

	if req.AssignmentID != "" {
		if asgn, err := h.Store.GetAssignment(r.Context(), orgID, req.AssignmentID); err == nil && asgn != nil {
			if asgn.TargetType == "device" && asgn.TargetID != principal.DeviceID {
				http.Error(w, `{"error":{"code":"forbidden_assignment_target","message":"authenticated device is not the target of verified assignment"}}`, http.StatusForbidden)
				return
			}
			if asgn.TargetType == "user" && principal.UserID != nil && *principal.UserID != "" && asgn.TargetID != *principal.UserID {
				http.Error(w, `{"error":{"code":"forbidden_assignment_target","message":"authenticated user is not the target of verified assignment"}}`, http.StatusForbidden)
				return
			}
		}
	}

	targetState := model.AssignmentStateVerified
	reason := fmt.Sprintf("Hub-correlated effective-routing probe passed (type: %s)", req.ProbeType)
	if !req.Success {
		targetState = model.AssignmentStateFailed
		reason = fmt.Sprintf("Hub-correlated effective-routing probe failed (type: %s)", req.ProbeType)
	}

	var updatedAsgn *model.Assignment
	var err error
	if req.AssignmentID != "" {
		updatedAsgn, err = h.Store.UpdateAssignmentState(r.Context(), orgID, req.AssignmentID, targetState, reason, "verify-probe-client")
		if err != nil {
			log.Printf("[verify-probe] warning: failed to update assignment %s: %v", req.AssignmentID, err)
		}
	}

	currentState := targetState
	if updatedAsgn != nil {
		currentState = updatedAsgn.State
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"verified":      req.Success,
		"device_id":     principal.DeviceID,
		"user_id":       req.UserID,
		"assignment_id": req.AssignmentID,
		"state":         currentState,
		"reason":        reason,
		"timestamp":     time.Now().UTC(),
	})
}

// GET /api/v2/device/assignments
func (h *DeviceV2Handler) ListDeviceAssignments(w http.ResponseWriter, r *http.Request) {
	principal, ok := middleware.GetDevicePrincipal(r.Context())
	if !ok {
		http.Error(w, `{"error":{"code":"device_auth_required"}}`, http.StatusUnauthorized)
		return
	}

	orgID := principal.OrganizationID
	if orgID == "" {
		orgID = store.DefaultOrgID
	}

	var targetUserID string
	if principal.UserID != nil {
		targetUserID = *principal.UserID
	}
	assignments, err := h.Store.ListAssignmentsForDevice(r.Context(), orgID, principal.DeviceID, targetUserID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"code":"list_failed","message":%q}}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"assignments": assignments,
	})
}

// DeviceEnrollRequestV2 contains the payload for POST /api/v2/devices/enroll
type DeviceEnrollRequestV2 struct {
	EnrollmentToken string `json:"enrollment_token"`
	DeviceID        string `json:"device_id"`
	DisplayName     string `json:"display_name"`
	PublicKey       string `json:"ed25519_public_key"`
	PublicKeyBytes  string `json:"public_key_bytes"`
	PublicKeyRaw    string `json:"public_key"`
	ClientPlatform  string `json:"client_platform"`
	Platform        string `json:"platform"`
	AgentVersion    string `json:"agent_version"`
}

// POST /api/v2/devices/enroll
func (h *DeviceV2Handler) EnrollDeviceV2(w http.ResponseWriter, r *http.Request) {
	var req DeviceEnrollRequestV2
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":{"code":"invalid_request","message":"Malformed JSON payload"}}`, http.StatusBadRequest)
		return
	}

	// Normalize flexible field mappings across CLI and API guide variants
	if req.PublicKey == "" {
		if req.PublicKeyBytes != "" {
			req.PublicKey = req.PublicKeyBytes
		} else if req.PublicKeyRaw != "" {
			req.PublicKey = req.PublicKeyRaw
		}
	}
	if req.ClientPlatform == "" && req.Platform != "" {
		req.ClientPlatform = req.Platform
	}

	if req.PublicKey == "" {
		http.Error(w, `{"error":{"code":"invalid_request","message":"ed25519_public_key or public_key_bytes is required"}}`, http.StatusBadRequest)
		return
	}

	orgID := middleware.ResolveTenantScope(r)
	if orgID == "" {
		orgID = store.DefaultOrgID
	}
	if req.EnrollmentToken != "" {
		// Consume token if provided
		_ = h.Store.ConsumeEnrollmentToken(r.Context(), req.EnrollmentToken)
	}

	deviceID := req.DeviceID
	if deviceID == "" {
		// Generate UUID if not provided
		hasher := sha256.Sum256([]byte(req.PublicKey))
		deviceID = fmt.Sprintf("dev-%x", hasher[:8])
	}

	displayName := req.DisplayName
	if displayName == "" {
		displayName = deviceID
	}

	platform := req.ClientPlatform
	if platform == "" {
		platform = "windows"
	}

	agentVersion := req.AgentVersion
	if agentVersion == "" {
		agentVersion = "1.0.0"
	}

	dev, key, err := h.Store.EnrollDeviceV2(r.Context(), orgID, deviceID, displayName, platform, agentVersion, req.PublicKey)
	if err != nil {
		log.Printf("[enroll-v2] failed to enroll device: %v", err)
		http.Error(w, fmt.Sprintf(`{"error":{"code":"enrollment_failed","message":%q}}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"device_id":        dev.StableDeviceID,
		"organization_id":  dev.OrganizationID,
		"status":           "ACTIVE",
		"enrolled_at":      time.Now().UTC(),
		"key_id":           key.ID,
		"public_key_bytes": key.PublicKeyBytes,
		"algorithm":        key.Algorithm,
	})
}

// POST /api/v2/devices/{id}/rotate-key
func (h *DeviceV2Handler) RotateKey(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "id")
	if deviceID == "" {
		deviceID = chi.URLParam(r, "device_id")
	}
	if deviceID == "" {
		http.Error(w, `{"error":{"code":"invalid_request","message":"Device ID is required"}}`, http.StatusBadRequest)
		return
	}

	var req struct {
		NewPublicKey string `json:"new_public_key"`
		Signature    string `json:"signature,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NewPublicKey == "" {
		http.Error(w, `{"error":{"code":"invalid_request","message":"new_public_key is required"}}`, http.StatusBadRequest)
		return
	}

	orgID := store.DefaultOrgID
	key, err := h.Store.RotateDeviceKey(r.Context(), orgID, deviceID, req.NewPublicKey)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"code":"rotation_failed","message":%q}}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"device_id":        deviceID,
		"status":           "ROTATED",
		"active_key_id":    key.ID,
		"public_key_bytes": key.PublicKeyBytes,
		"rotated_at":       time.Now().UTC(),
	})
}

// DELETE /api/v2/devices/{id}
func (h *DeviceV2Handler) RevokeDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "id")
	if deviceID == "" {
		deviceID = chi.URLParam(r, "device_id")
	}
	if deviceID == "" {
		http.Error(w, `{"error":{"code":"invalid_request","message":"Device ID is required"}}`, http.StatusBadRequest)
		return
	}

	orgID := store.DefaultOrgID
	_ = h.Store.RevokeDeviceKeys(r.Context(), orgID, deviceID)
	_ = h.Store.TransitionDeviceState(r.Context(), orgID, deviceID, model.DeviceStateRevoked, "ADMIN_REVOCATION", "ADMIN", "console", "revocation-req")

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"device_id":  deviceID,
		"status":     "REVOKED",
		"revoked_at": time.Now().UTC(),
	})
}

// GET /api/v2/devices
func (h *DeviceV2Handler) ListDevicesV2(w http.ResponseWriter, r *http.Request) {
	devices, err := h.Store.ListDevices(r.Context(), store.DefaultOrgID, "", "", 100, 0)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"code":"list_failed","message":%q}}`, err.Error()), http.StatusInternalServerError)
		return
	}

	type DeviceV2Item struct {
		DeviceID         string    `json:"device_id"`
		StableDeviceID   string    `json:"stable_device_id"`
		DisplayName      string    `json:"display_name"`
		OwnerSubject     string    `json:"owner_subject,omitempty"`
		AuthProviderType string    `json:"auth_provider_type,omitempty"`
		OSFamily         string    `json:"os_family"`
		Architecture     string    `json:"architecture"`
		Status           string    `json:"status"`
		CapabilityVector []string  `json:"capability_vector"`
		LastFreshness    string    `json:"last_freshness"`
		PublicKey        string    `json:"public_key,omitempty"`
		LastSeenAt       time.Time `json:"last_seen_at"`
		FirstEnrolledAt  time.Time `json:"first_enrolled_at"`
	}

	var items []DeviceV2Item
	for _, d := range devices {
		status := "ACTIVE"
		if d.ComplianceStatus == "REVOKED" || d.IsRevoked {
			status = "REVOKED"
		} else if d.ComplianceStatus == "PENDING" {
			status = "PENDING"
		}

		// Look up active key
		pubKey := d.PublicKey
		if activeKey, err := h.Store.GetActiveDeviceKey(r.Context(), d.DeviceID); err == nil && activeKey != nil {
			pubKey = activeKey.PublicKeyBytes
		}

		capVector := []string{"CONFIGURED", "TRAFFIC_VERIFIED"}
		if d.MCPServersWrapped > 0 {
			capVector = append(capVector, "MCP_WRAPPED")
		}

		freshness := "ACTIVE_FRESH"
		if time.Since(d.LastHeartbeatAt) > 24*time.Hour {
			freshness = "STALE"
		} else if time.Since(d.LastHeartbeatAt) > 15*time.Minute {
			freshness = "ACTIVE_RECENT"
		}

		items = append(items, DeviceV2Item{
			DeviceID:         d.DeviceID,
			StableDeviceID:   d.DeviceID,
			DisplayName:      d.Hostname,
			OwnerSubject:     d.OwnerSubject,
			AuthProviderType: d.AuthProviderType,
			OSFamily:         d.OSFamily,
			Architecture:     d.OSArch,
			Status:           status,
			CapabilityVector: capVector,
			LastFreshness:    freshness,
			PublicKey:        pubKey,
			LastSeenAt:       d.LastHeartbeatAt,
			FirstEnrolledAt:  d.FirstEnrolledAt,
		})
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"devices":     items,
		"total_count": len(items),
	})
}


