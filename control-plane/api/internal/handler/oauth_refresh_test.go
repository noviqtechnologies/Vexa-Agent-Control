package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestToken_RefreshTokenGrant(t *testing.T) {
	h := NewPKCEOAuthHandler(nil)

	// 1. Missing refresh_token parameter
	body := `{"grant_type":"refresh_token"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Token(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for missing refresh_token, got %d", w.Code)
	}

	// 2. Valid refresh token request (in-memory mode without db pool)
	body = `{"grant_type":"refresh_token","refresh_token":"ac_ref_test12345678"}`
	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.Token(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK for refresh grant, got %d: %s", w.Code, w.Body.String())
	}

	var resp TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !strings.HasPrefix(resp.RefreshToken, "ac_ref_") {
		t.Errorf("expected rotated refresh_token with prefix ac_ref_, got %s", resp.RefreshToken)
	}
	if resp.AccessToken == "" {
		t.Error("expected non-empty access_token in refresh response")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("expected TokenType Bearer, got %s", resp.TokenType)
	}
}
