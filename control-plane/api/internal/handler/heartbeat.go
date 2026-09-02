package handler

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type HeartbeatHandler struct {
	store *store.Store
}

func NewHeartbeatHandler(s *store.Store) *HeartbeatHandler {
	return &HeartbeatHandler{store: s}
}

type HeartbeatRequest struct {
	DeviceID          string                 `json:"device_id"`
	Hostname          string                 `json:"hostname"`
	OSArch            string                 `json:"os_arch"`
	AgentControlVersion  string                 `json:"agentcontrol_version"`
	DaemonStatus      string                 `json:"daemon_status"`
	IDEChecksums       map[string]interface{} `json:"ide_checksums"`
	MCPServersTotal   int                    `json:"mcp_servers_total"`
	MCPServersWrapped int                    `json:"mcp_servers_wrapped"`
	UptimeSeconds     int64                  `json:"uptime_seconds"`
}

type HeartbeatResponse struct {
	Status             string `json:"status"`
	ComplianceStatus   string `json:"compliance_status"`
	PolicySyncRequired bool   `json:"policy_sync_required"`
}

// POST /api/v1/ingest/heartbeat
func (h *HeartbeatHandler) PostHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":{"code":"INVALID_JSON","message":"invalid json payload"}}`, http.StatusBadRequest)
		return
	}

	if req.DeviceID == "" {
		http.Error(w, `{"error":{"code":"INVALID_REQUEST","message":"device_id is required"}}`, http.StatusUnprocessableEntity)
		return
	}

	ctx := r.Context()
	tenantID := middleware.ResolveTenantScope(r)
	err := h.store.UpdateDeviceHeartbeat(ctx, store.DeviceHeartbeatParams{
		OrganizationID:      tenantID,
		DeviceID:            req.DeviceID,
		Hostname:            req.Hostname,
		OSArch:              req.OSArch,
		AgentControlVersion: req.AgentControlVersion,
		MCPServersTotal:     req.MCPServersTotal,
		MCPServersWrapped:   req.MCPServersWrapped,
		IDEChecksums:        req.IDEChecksums,
	})
	if err != nil {
		if errors.Is(err, store.ErrDeviceRevoked) {
			log.Printf("heartbeat rejected for revoked device %s", req.DeviceID)
			http.Error(w, `{"error":{"code":"DEVICE_REVOKED","message":"device is revoked"}}`, http.StatusUnauthorized)
			return
		} else if errors.Is(err, store.ErrDeviceNotFound) {
			log.Printf("heartbeat device not found %s", req.DeviceID)
			http.Error(w, `{"error":{"code":"DEVICE_NOT_FOUND","message":"device not registered"}}`, http.StatusNotFound)
			return
		}
		log.Printf("update heartbeat failed: %v", err)
		http.Error(w, `{"error":{"code":"INTERNAL_ERROR","message":"failed to update heartbeat"}}`, http.StatusInternalServerError)
		return
	}

	compStatus := "COMPLIANT"
	if req.MCPServersWrapped < req.MCPServersTotal {
		compStatus = "NON_COMPLIANT"
	}

	resp := HeartbeatResponse{
		Status:             "ok",
		ComplianceStatus:   compStatus,
		PolicySyncRequired: false,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
