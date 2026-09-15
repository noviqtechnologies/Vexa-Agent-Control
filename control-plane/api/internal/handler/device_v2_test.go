package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

func TestEnrollDeviceV2_FlexibilityAndValidation(t *testing.T) {
	st := store.New(nil)
	h := NewDeviceV2Handler(st)

	tests := []struct {
		name           string
		payload        map[string]interface{}
		expectedStatus int
		expectDevID    string
	}{
		{
			name: "Standard CLI registration with public_key_bytes and platform",
			payload: map[string]interface{}{
				"device_id":        "dev-zoya-f846abd6",
				"display_name":     "ZOYA",
				"platform":         "windows",
				"agent_version":    "1.0.82",
				"public_key_bytes": "6d3AYn840c9qZvZcK3r7Z8Xw==",
			},
			expectedStatus: http.StatusCreated,
			expectDevID:    "dev-zoya-f846abd6",
		},
		{
			name: "Registration with ed25519_public_key and client_platform",
			payload: map[string]interface{}{
				"device_id":          "dev-mac-1234",
				"display_name":       "MacBook",
				"client_platform":    "macos",
				"agent_version":      "1.0.82",
				"ed25519_public_key": "some-valid-key-content==",
			},
			expectedStatus: http.StatusCreated,
			expectDevID:    "dev-mac-1234",
		},
		{
			name: "Missing public key should return 400 Bad Request",
			payload: map[string]interface{}{
				"device_id":    "dev-invalid",
				"display_name": "No Key",
				"platform":     "windows",
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.payload)
			req := httptest.NewRequest(http.MethodPost, "/api/v2/devices/enroll", bytes.NewReader(body))
			w := httptest.NewRecorder()

			h.EnrollDeviceV2(w, req)

			if w.Code != tc.expectedStatus {
				t.Fatalf("expected status %d, got %d. Body: %s", tc.expectedStatus, w.Code, w.Body.String())
			}

			if tc.expectedStatus == http.StatusCreated {
				var resp map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp["device_id"] != tc.expectDevID {
					t.Errorf("expected device_id %q, got %v", tc.expectDevID, resp["device_id"])
				}
				if resp["status"] != "ACTIVE" {
					t.Errorf("expected status 'ACTIVE', got %v", resp["status"])
				}
			}
		})
	}
}
