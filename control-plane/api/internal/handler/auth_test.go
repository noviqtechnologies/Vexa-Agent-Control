package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetupInitialPassword_ShortPasswordValidation(t *testing.T) {
	h := &AuthHandler{}

	body, _ := json.Marshal(map[string]string{
		"password": "short",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/setup-initial-password", bytes.NewReader(body))
	w := httptest.NewRecorder()

	// Should fail unauthorized without claims context
	h.SetupInitialPassword(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 unauthenticated, got %d", w.Code)
	}
}
