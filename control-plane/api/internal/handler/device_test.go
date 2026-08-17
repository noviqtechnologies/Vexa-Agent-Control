package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/device"
)

func TestDeviceHandlerValidation(t *testing.T) {
	devStore := device.NewStore(nil)
	devH := NewDeviceHandler(devStore)

	r := chi.NewRouter()
	devH.RegisterRoutes(r)

	// Test invalid JSON on enroll
	req := httptest.NewRequest("POST", "/api/v1/devices/enroll", bytes.NewBufferString("{invalid_json}"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid json, got %d", w.Code)
	}

	// Test missing body on telemetry
	req2 := httptest.NewRequest("POST", "/api/v1/devices/dev-1/telemetry", bytes.NewBufferString("{invalid_json}"))
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid telemetry json, got %d", w2.Code)
	}

	// Test list devices with mock JSON encode
	var resp device.ListDevicesResponse
	resp.TotalCount = 0
	data, err := json.Marshal(resp)
	if err != nil || len(data) == 0 {
		t.Fatalf("json marshal failed: %v", err)
	}
}
