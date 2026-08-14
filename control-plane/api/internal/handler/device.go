package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/device"
)

type DeviceHandler struct {
	store *device.Store
}

func NewDeviceHandler(store *device.Store) *DeviceHandler {
	return &DeviceHandler{store: store}
}

func (h *DeviceHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/devices", func(r chi.Router) {
		r.Post("/enroll", h.EnrollDevice)
		r.Post("/{id}/telemetry", h.RecordTelemetry)
		r.Get("/", h.ListDevices)
		r.Get("/tamper-log", h.ListTamperEvents)
	})
}

// EnrollDevice handles POST /api/v1/devices/enroll
func (h *DeviceHandler) EnrollDevice(w http.ResponseWriter, r *http.Request) {
	var req device.EnrollDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}

	orgID := r.Header.Get("X-Organization-ID")
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}

	resp, err := h.store.EnrollDevice(r.Context(), orgID, &req)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// RecordTelemetry handles POST /api/v1/devices/{id}/telemetry
func (h *DeviceHandler) RecordTelemetry(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "id")
	if deviceID == "" {
		http.Error(w, `{"error":"missing_device_id"}`, http.StatusBadRequest)
		return
	}

	var req device.TelemetryHeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	req.DeviceID = deviceID

	orgID := r.Header.Get("X-Organization-ID")
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}

	resp, err := h.store.RecordTelemetry(r.Context(), orgID, &req)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ListDevices handles GET /api/v1/devices
func (h *DeviceHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	orgID := r.Header.Get("X-Organization-ID")
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 {
			limit = val
		}
	}

	offset := 0
	if o := r.URL.Query().Get("offset"); o != "" {
		if val, err := strconv.Atoi(o); err == nil && val >= 0 {
			offset = val
		}
	}

	filter := r.URL.Query().Get("compliance_status")

	resp, err := h.store.ListDevices(r.Context(), orgID, filter, limit, offset)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ListTamperEvents handles GET /api/v1/devices/tamper-log
func (h *DeviceHandler) ListTamperEvents(w http.ResponseWriter, r *http.Request) {
	orgID := r.Header.Get("X-Organization-ID")
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 {
			limit = val
		}
	}

	offset := 0
	if o := r.URL.Query().Get("offset"); o != "" {
		if val, err := strconv.Atoi(o); err == nil && val >= 0 {
			offset = val
		}
	}

	resp, err := h.store.ListTamperEvents(r.Context(), orgID, limit, offset)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
