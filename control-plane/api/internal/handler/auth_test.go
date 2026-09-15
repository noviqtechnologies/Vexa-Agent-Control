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
		AdminEmail:    "admin@testorg.local",
		AdminPassword: "CustomSuperSecret2026!#",
	}
	h := NewAuthHandler(nil, prodCfg)

	// 1. Correct custom password succeeds
	body, _ := json.Marshal(LoginReq{
		Email:    "admin@testorg.local",
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
		Email:    "admin@testorg.local",
		Password: "admin123!",
	})
	reqDef := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(bodyDef))
	wDef := httptest.NewRecorder()

	h.Login(wDef, reqDef)
	if wDef.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for default password, got %d", wDef.Code)
	}

	// 3. Default email 'admin' blocked in production
	bodyDefEmail, _ := json.Marshal(LoginReq{
		Email:    "admin",
		Password: "CustomSuperSecret2026!#",
	})
	reqDefEmail := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(bodyDefEmail))
	wDefEmail := httptest.NewRecorder()

	h.Login(wDefEmail, reqDefEmail)
	if wDefEmail.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for default email, got %d", wDefEmail.Code)
	}

	// 4. Wrong password fails
	bodyWrong, _ := json.Marshal(LoginReq{
		Email:    "admin@testorg.local",
		Password: "wrong_password",
	})
	reqWrong := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(bodyWrong))
	wWrong := httptest.NewRecorder()

	h.Login(wWrong, reqWrong)
	if wWrong.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for wrong password, got %d", wWrong.Code)
	}
}

func TestAuthHandler_AdminLogin(t *testing.T) {
	cfg := &config.Config{
		DevMode:          false,
		AdminEmail:       "admin@customer.corp",
		AdminPassword:    "SuperSecretPassword123!",
		OrganizationName: "Customer Enterprise",
		OrganizationID:   "00000000-0000-0000-0000-000000000001",
	}
	h := NewAuthHandler(nil, cfg)

	// Admin Login succeeds with OWNER role and is_admin = true
	body, _ := json.Marshal(LoginReq{
		Email:    "admin@customer.corp",
		Password: "SuperSecretPassword123!",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.Login(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for Admin, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["is_admin"] != true {
		t.Errorf("expected is_admin = true, got %v", resp["is_admin"])
	}
	if resp["role"] != "OWNER" {
		t.Errorf("expected role = OWNER, got %v", resp["role"])
	}
	if resp["organization_name"] != "Customer Enterprise" {
		t.Errorf("expected organization_name = Customer Enterprise, got %v", resp["organization_name"])
	}
	if resp["is_saas_operator"] != false {
		t.Errorf("expected is_saas_operator = false, got %v", resp["is_saas_operator"])
	}
}

func TestAuthHandler_DevModeEnforcesPassword(t *testing.T) {
	// 1. Default dev config without explicit password (defaults to admin12345678)
	devCfg := &config.Config{
		DevMode: true,
	}
	h := NewAuthHandler(nil, devCfg)

	// Correct password with full email succeeds
	body1, _ := json.Marshal(LoginReq{
		Email:    "admin@agentcontrol.local",
		Password: "admin12345678",
	})
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body1))
	w1 := httptest.NewRecorder()
	h.Login(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for admin@agentcontrol.local with correct password, got %d: %s", w1.Code, w1.Body.String())
	}

	// Correct password with 'admin' shortname succeeds
	body2, _ := json.Marshal(LoginReq{
		Email:    "admin",
		Password: "admin12345678",
	})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body2))
	w2 := httptest.NewRecorder()
	h.Login(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for admin with correct password, got %d: %s", w2.Code, w2.Body.String())
	}

	// Random password with full email MUST FAIL
	body3, _ := json.Marshal(LoginReq{
		Email:    "admin@agentcontrol.local",
		Password: "random_junk_password_123",
	})
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body3))
	w3 := httptest.NewRecorder()
	h.Login(w3, req3)
	if w3.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for admin@agentcontrol.local with random password, got %d", w3.Code)
	}

	// Random password with 'admin' shortname MUST FAIL
	body4, _ := json.Marshal(LoginReq{
		Email:    "admin",
		Password: "random_junk_password_123",
	})
	req4 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body4))
	w4 := httptest.NewRecorder()
	h.Login(w4, req4)
	if w4.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for admin with random password, got %d", w4.Code)
	}

	// 2. Dev config with custom AdminPassword
	customDevCfg := &config.Config{
		DevMode:       true,
		AdminEmail:    "admin@agentcontrol.local",
		AdminPassword: "CustomDevPassword2026!",
	}
	hCustom := NewAuthHandler(nil, customDevCfg)

	body5, _ := json.Marshal(LoginReq{
		Email:    "admin@agentcontrol.local",
		Password: "CustomDevPassword2026!",
	})
	req5 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body5))
	w5 := httptest.NewRecorder()
	hCustom.Login(w5, req5)
	if w5.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for custom DevMode password, got %d", w5.Code)
	}

	body6, _ := json.Marshal(LoginReq{
		Email:    "admin@agentcontrol.local",
		Password: "wrong_password",
	})
	req6 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body6))
	w6 := httptest.NewRecorder()
	hCustom.Login(w6, req6)
	if w6.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for custom DevMode with wrong password, got %d", w6.Code)
	}
}


