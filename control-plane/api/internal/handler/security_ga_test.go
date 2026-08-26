package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/config"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
)

func TestSecurityGA_SessionSecretCannotBeUsedAsPassword(t *testing.T) {
	cfg := &config.Config{
		SessionSecret:     "very_secret_signing_key_not_password_12345",
		SaaSOperatorEmail: "admin@example.com",
		DevMode:           false,
	}

	authH := NewAuthHandler(nil, cfg)

	// Attempt login with session secret as password
	body, _ := json.Marshal(LoginReq{
		Email:    "admin@example.com",
		Password: "very_secret_signing_key_not_password_12345",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	w := httptest.NewRecorder()

	authH.Login(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized when session secret is used as password, got %d", w.Code)
	}
}

func TestSecurityGA_DevModeRequiresBothFlags(t *testing.T) {
	// 1. cfg with DevMode = false (e.g. only DEV_MODE=true without ALLOW_DEV_MODE=true)
	cfgNoDev := &config.Config{
		DevMode: false,
	}
	authH := NewAuthHandler(nil, cfgNoDev)

	body, _ := json.Marshal(LoginReq{
		Email:    "admin",
		Password: "anypassword",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	w := httptest.NewRecorder()

	authH.Login(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized when DevMode is false, got %d", w.Code)
	}

	// 2. cfg with DevMode = true (both flags were present)
	cfgDev := &config.Config{
		DevMode: true,
	}
	authHDev := NewAuthHandler(nil, cfgDev)

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	w2 := httptest.NewRecorder()

	authHDev.Login(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK when DevMode is true, got %d", w2.Code)
	}
}

func TestSecurityGA_UnauthenticatedTenantHeaderSpoofingRejected(t *testing.T) {
	// Request without user or device claims attempting to spoof tenant ID via headers
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resource", nil)
	req.Header.Set("X-Organization-ID", "attacker-injected-tenant-uuid")
	req.Header.Set("X-Tenant-ID", "attacker-injected-tenant-uuid")

	_, err := middleware.ResolveAuthenticatedTenantScope(req)
	if err == nil {
		t.Fatalf("expected error from ResolveAuthenticatedTenantScope for unauthenticated request with headers")
	}

	// ResolveTenantScope fallback should return DefaultTenantID, never the attacker header
	resolved := middleware.ResolveTenantScope(req)
	if resolved == "attacker-injected-tenant-uuid" {
		t.Fatalf("CRITICAL: unauthenticated request was able to inject tenant ID via header!")
	}
	if resolved != middleware.DefaultTenantID {
		t.Fatalf("expected DefaultTenantID, got %s", resolved)
	}
}

func TestSecurityGA_DirectMTLSHeaderSpoofingDenied(t *testing.T) {
	// Middleware configured with required Ingress auth secret
	ingressSecret := "ingress_secret_vpc_token_987654321"
	mtlsMiddleware := middleware.StrictDeviceMTLS(nil, ingressSecret)

	nextCalled := false
	handler := mtlsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	// Attempt request directly to API with spoofed ALB mTLS headers but wrong/missing ingress auth secret
	req := httptest.NewRequest(http.MethodGet, "/api/v2/device/bootstrap", nil)
	req.Header.Set("X-Client-Cert-Present", "true")
	req.Header.Set("X-Client-Cert-Serial", "123456")
	req.Header.Set("X-Client-Cert-SHA256", "sha256:abcdef1234567890")
	// Missing X-VPC-Ingress-Auth

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for spoofed ingress request without secret, got %d", w.Code)
	}
	if nextCalled {
		t.Fatalf("handler should not have been called on ingress spoofing attempt")
	}
}
