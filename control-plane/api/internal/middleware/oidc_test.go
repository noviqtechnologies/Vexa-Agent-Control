package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func okHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// --- GatewayAuth tests ---

func TestGatewayAuth_ValidToken(t *testing.T) {
	secret := "test-gateway-secret-32chars!!"
	mw := GatewayAuth(secret)
	handler := mw(http.HandlerFunc(okHandler))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestGatewayAuth_InvalidToken(t *testing.T) {
	mw := GatewayAuth("real-secret")
	handler := mw(http.HandlerFunc(okHandler))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", nil)
	req.Header.Set("Authorization", "Bearer wrong-secret")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestGatewayAuth_MissingHeader(t *testing.T) {
	mw := GatewayAuth("real-secret")
	handler := mw(http.HandlerFunc(okHandler))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestGatewayAuth_MalformedHeader(t *testing.T) {
	mw := GatewayAuth("real-secret")
	handler := mw(http.HandlerFunc(okHandler))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestGatewayAuth_EmptySecret_Passthrough(t *testing.T) {
	mw := GatewayAuth("")
	handler := mw(http.HandlerFunc(okHandler))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("got status %d, want %d — empty secret should pass through", rr.Code, http.StatusOK)
	}
}

func TestGatewayAuth_TimingResistance(t *testing.T) {
	secret := "correct-secret"
	mw := GatewayAuth(secret)
	handler := mw(http.HandlerFunc(okHandler))

	// A token that shares a prefix should still be rejected.
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer correct-secre")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusForbidden)
	}
}

// --- PolicyReadAuth and DashboardAuth tests ---

func TestPolicyReadAuth_BearerToken(t *testing.T) {
	secret := "read-secret-123"
	mw := PolicyReadAuth(secret)
	handler := mw(http.HandlerFunc(okHandler))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/active", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestPolicyReadAuth_InvalidBearerToken(t *testing.T) {
	secret := "read-secret-123"
	mw := PolicyReadAuth(secret)
	handler := mw(http.HandlerFunc(okHandler))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/active", nil)
	req.Header.Set("Authorization", "Bearer wrong-secret")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

