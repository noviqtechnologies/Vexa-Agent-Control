package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/config"
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

func TestIsRequestSecure_ProtocolValidation(t *testing.T) {
	// 1. Plain HTTP without HTTPS proxy header
	reqHTTP := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/auth/login", nil)
	if isRequestSecure(reqHTTP) {
		t.Error("expected isRequestSecure to be false for plain HTTP")
	}

	// 2. HTTP with spoofed Origin/Referer (must remain false)
	reqSpoofed := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/auth/login", nil)
	reqSpoofed.Header.Set("Origin", "https://evil.com")
	reqSpoofed.Header.Set("Referer", "https://evil.com/page")
	if isRequestSecure(reqSpoofed) {
		t.Error("expected isRequestSecure to be false despite spoofed Origin/Referer headers")
	}

	// 3. Reverse Proxy with X-Forwarded-Proto: https
	reqForwarded := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/auth/login", nil)
	reqForwarded.Header.Set("X-Forwarded-Proto", "https")
	if !isRequestSecure(reqForwarded) {
		t.Error("expected isRequestSecure to be true for X-Forwarded-Proto: https")
	}
}

func TestOAuthDomainValidation_BoundaryEnforcement(t *testing.T) {
	allowedDomains := []string{"company.com", "@partner.org"}

	checkDomainAllowed := func(email string, domains []string) bool {
		for _, d := range domains {
			domain := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), "@")
			if domain == "*" || strings.HasSuffix(strings.ToLower(email), "@"+domain) {
				return true
			}
		}
		return false
	}

	// Valid emails
	if !checkDomainAllowed("alice@company.com", allowedDomains) {
		t.Error("expected alice@company.com to be allowed")
	}
	if !checkDomainAllowed("bob@partner.org", allowedDomains) {
		t.Error("expected bob@partner.org to be allowed")
	}

	// Malicious suffix collisions (must be rejected)
	if checkDomainAllowed("attacker@evilcompany.com", allowedDomains) {
		t.Error("attacker@evilcompany.com should be rejected")
	}
	if checkDomainAllowed("attacker@fakepartner.org", allowedDomains) {
		t.Error("attacker@fakepartner.org should be rejected")
	}
	if checkDomainAllowed("attacker@notcompany.com", allowedDomains) {
		t.Error("attacker@notcompany.com should be rejected")
	}
}

func TestAuthHandler_PasswordVerificationFlow(t *testing.T) {
	password := "Admin@123"
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashPassword failed: %v", err)
	}

	ok, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword error: %v", err)
	}
	if !ok {
		t.Errorf("expected VerifyPassword to return true for matching password")
	}

	wrongOk, err := VerifyPassword("WrongPassword", hash)
	if err != nil {
		t.Fatalf("VerifyPassword error on wrong password: %v", err)
	}
	if wrongOk {
		t.Errorf("expected VerifyPassword to return false for wrong password")
	}
}

func TestAuthHandler_ProductionBlocksDefaultCredentials(t *testing.T) {
	prodCfg := &config.Config{
		DevMode: false,
	}
	h := NewAuthHandler(nil, prodCfg)

	testCases := []struct {
		email    string
		password string
	}{
		{"admin", "admin123!"},
		{"admin", "admin"},
		{"admin@agentcontrol.local", "admin123!"},
		{"admin@agentcontrol.local", "admin"},
	}

	for _, tc := range testCases {
		body, _ := json.Marshal(LoginReq{
			Email:    tc.email,
			Password: tc.password,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
		w := httptest.NewRecorder()

		h.Login(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized for default credentials in production (%s:%s), got %d", tc.email, tc.password, w.Code)
		}

		if !strings.Contains(w.Body.String(), "insecure_default_credentials_blocked") {
			t.Errorf("expected error message to contain 'insecure_default_credentials_blocked', got: %s", w.Body.String())
		}
	}
}

func TestAuthHandler_ConfiguredAdminPassword(t *testing.T) {
	prodCfg := &config.Config{
		DevMode:       false,
		AdminPassword: "CustomSuperSecret2026!#",
	}
	h := NewAuthHandler(nil, prodCfg)

	// 1. Correct custom password succeeds
	body, _ := json.Marshal(LoginReq{
		Email:    "admin@agentcontrol.local",
		Password: "CustomSuperSecret2026!#",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.Login(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for configured AdminPassword, got %d", w.Code)
	}

	// 2. Default password still blocked even if AdminPassword is configured
	bodyDef, _ := json.Marshal(LoginReq{
		Email:    "admin",
		Password: "admin123!",
	})
	reqDef := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(bodyDef))
	wDef := httptest.NewRecorder()

	h.Login(wDef, reqDef)
	if wDef.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for default password, got %d", wDef.Code)
	}

	// 3. Wrong password fails
	bodyWrong, _ := json.Marshal(LoginReq{
		Email:    "admin",
		Password: "wrong_password",
	})
	reqWrong := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(bodyWrong))
	wWrong := httptest.NewRecorder()

	h.Login(wWrong, reqWrong)
	if wWrong.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for wrong password, got %d", wWrong.Code)
	}
}

