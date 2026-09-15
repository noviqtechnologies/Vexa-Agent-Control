package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/session"
)

func TestAuthorize_UnauthenticatedRedirect(t *testing.T) {
	h := NewPKCEOAuthHandler(nil)

	redirectURI := "http://127.0.0.1:18085/callback"
	reqURL := "/oauth/authorize?response_type=code&client_id=agentcontrol-cli&redirect_uri=" +
		url.QueryEscape(redirectURI) +
		"&code_challenge=test_challenge_123&code_challenge_method=S256&state=state_xyz"

	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	w := httptest.NewRecorder()

	h.Authorize(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login?return_to=") {
		t.Fatalf("expected redirect to /login?return_to=..., got %q", loc)
	}

	// Verify return_to decodes back to original request URI
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("failed to parse redirect location: %v", err)
	}
	returnTo := parsed.Query().Get("return_to")
	if returnTo != req.URL.RequestURI() {
		t.Fatalf("expected return_to %q, got %q", req.URL.RequestURI(), returnTo)
	}
}

func TestAuthorize_AuthenticatedSuccess(t *testing.T) {
	h := NewPKCEOAuthHandler(nil)

	expectedUser := "alice@company.com"
	expectedOrg := middleware.DefaultOrganizationID
	cookieVal := session.Create(expectedOrg, expectedUser, false, false)

	redirectURI := "http://127.0.0.1:18085/callback"
	reqURL := "/oauth/authorize?response_type=code&client_id=agentcontrol-cli&redirect_uri=" +
		url.QueryEscape(redirectURI) +
		"&code_challenge=test_challenge_123&code_challenge_method=S256&state=state_xyz"

	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	req.AddCookie(&http.Cookie{
		Name:  "agentcontrol_session",
		Value: cookieVal,
	})
	w := httptest.NewRecorder()

	h.Authorize(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, redirectURI) {
		t.Fatalf("expected redirect to %q, got %q", redirectURI, loc)
	}

	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("failed to parse location URL: %v", err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("expected non-empty code in query params")
	}
	if parsed.Query().Get("state") != "state_xyz" {
		t.Fatalf("expected state=state_xyz, got %q", parsed.Query().Get("state"))
	}

	// Verify internal code mapping in handler
	h.mu.Lock()
	authCode, exists := h.codes[code]
	h.mu.Unlock()

	if !exists {
		t.Fatalf("auth code %s was not stored in handler", code)
	}
	if authCode.UserID != expectedUser {
		t.Fatalf("expected auth code UserID %q, got %q", expectedUser, authCode.UserID)
	}
	if authCode.TenantID != expectedOrg {
		t.Fatalf("expected auth code TenantID %q, got %q", expectedOrg, authCode.TenantID)
	}
}

func TestToken_PKCES256Exchange(t *testing.T) {
	h := NewPKCEOAuthHandler(nil)

	expectedUser := "bob@company.com"
	expectedOrg := "00000000-0000-0000-0000-000000000001"

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hasher := sha256.New()
	hasher.Write([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

	code := "auth_code_test_valid"
	h.mu.Lock()
	h.codes[code] = PKCEAuthCode{
		Code:          code,
		ClientID:      "agentcontrol-cli",
		RedirectURI:   "http://127.0.0.1:18085/callback",
		CodeChallenge: challenge,
		UserID:        expectedUser,
		TenantID:      expectedOrg,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	h.mu.Unlock()

	body := strings.NewReader(`{
		"grant_type": "authorization_code",
		"client_id": "agentcontrol-cli",
		"code": "auth_code_test_valid",
		"code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		"redirect_uri": "http://127.0.0.1:18085/callback"
	}`)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Token(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("failed to decode TokenResponse: %v", err)
	}

	if tokenResp.UserID != expectedUser {
		t.Fatalf("expected UserID %q, got %q", expectedUser, tokenResp.UserID)
	}
	if tokenResp.TenantID != expectedOrg {
		t.Fatalf("expected TenantID %q, got %q", expectedOrg, tokenResp.TenantID)
	}
	if !strings.HasPrefix(tokenResp.AccessToken, "ac_tok_") {
		t.Fatalf("expected AccessToken starting with ac_tok_, got %q", tokenResp.AccessToken)
	}
}

func TestToken_InvalidVerifierRejected(t *testing.T) {
	h := NewPKCEOAuthHandler(nil)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hasher := sha256.New()
	hasher.Write([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

	code := "auth_code_test_invalid"
	h.mu.Lock()
	h.codes[code] = PKCEAuthCode{
		Code:          code,
		ClientID:      "agentcontrol-cli",
		RedirectURI:   "http://127.0.0.1:18085/callback",
		CodeChallenge: challenge,
		UserID:        "charlie@company.com",
		TenantID:      middleware.DefaultOrganizationID,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	h.mu.Unlock()

	body := strings.NewReader(`{
		"grant_type": "authorization_code",
		"client_id": "agentcontrol-cli",
		"code": "auth_code_test_invalid",
		"code_verifier": "wrong_verifier_string_that_does_not_match",
		"redirect_uri": "http://127.0.0.1:18085/callback"
	}`)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Token(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status 400 Bad Request on PKCE mismatch, got %d", resp.StatusCode)
	}
}
