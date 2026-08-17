package handler

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type DeviceAdminHandler struct {
	store *store.Store
}

func NewDeviceAdminHandler(s *store.Store) *DeviceAdminHandler {
	return &DeviceAdminHandler{store: s}
}

// GET /api/v1/admin/devices
func (h *DeviceAdminHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	osFamily := r.URL.Query().Get("os_family")
	statusFilter := r.URL.Query().Get("status")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	devices, err := h.store.ListDevices(r.Context(), osFamily, statusFilter, limit, offset)
	if err != nil {
		log.Printf("list devices failed: %v", err)
		http.Error(w, `{"error":{"code":"INTERNAL_ERROR","message":"failed to list devices"}}`, http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"devices": devices,
		"total":   len(devices),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// POST /api/v1/admin/devices/{id}/revoke
func (h *DeviceAdminHandler) RevokeDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "id")
	if deviceID == "" {
		http.Error(w, `{"error":{"code":"INVALID_REQUEST","message":"device id is required"}}`, http.StatusBadRequest)
		return
	}

	err := h.store.RevokeDevice(r.Context(), deviceID)
	if err != nil {
		if errors.Is(err, store.ErrDeviceNotFound) {
			http.Error(w, `{"error":{"code":"NOT_FOUND","message":"device not found"}}`, http.StatusNotFound)
			return
		}
		log.Printf("revoke device failed: %v", err)
		http.Error(w, `{"error":{"code":"INTERNAL_ERROR","message":"failed to revoke device"}}`, http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"device_id": deviceID,
		"status":    "revoked",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

type TamperLogRequest struct {
	DeviceID     string `json:"device_id"`
	TargetIDE    string `json:"target_ide"`
	DetectedDiff string `json:"detected_diff"`
	ActionTaken  string `json:"action_taken"`
}

// POST /api/v1/ingest/tamper-log
func (h *DeviceAdminHandler) PostTamperLog(w http.ResponseWriter, r *http.Request) {
	var req TamperLogRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":{"code":"INVALID_JSON","message":"invalid json payload"}}`, http.StatusBadRequest)
		return
	}

	if req.DeviceID == "" || req.TargetIDE == "" {
		http.Error(w, `{"error":{"code":"INVALID_REQUEST","message":"device_id and target_ide required"}}`, http.StatusUnprocessableEntity)
		return
	}

	logEntry := model.DeviceTamperLog{
		DeviceID:     req.DeviceID,
		TargetIDE:    req.TargetIDE,
		DetectedDiff: req.DetectedDiff,
		ActionTaken:  req.ActionTaken,
	}

	if err := h.store.InsertTamperLog(r.Context(), &logEntry); err != nil {
		log.Printf("insert tamper log failed: %v", err)
		http.Error(w, `{"error":{"code":"INTERNAL_ERROR","message":"failed to insert tamper log"}}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
