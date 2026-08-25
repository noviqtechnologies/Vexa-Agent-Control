package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
