package handler

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

func TestDeviceV2Handler_GetBootstrap_PolicySignature(t *testing.T) {
	h := NewDeviceV2Handler(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v2/device/bootstrap", nil)
	principal := &model.DevicePrincipal{
		DeviceID:       "dev-boot-1",
		OrganizationID: "00000000-0000-0000-0000-000000000001",
		DeviceState:    model.DeviceStateCompliant,
	}
	ctx := context.WithValue(req.Context(), middleware.DevicePrincipalKey, principal)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	h.GetBootstrap(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var resp BootstrapResponseV2
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode bootstrap response: %v", err)
	}

	// Verify SHA-256 matches the policy content
	hasher := sha256.New()
	hasher.Write([]byte(resp.Policy.Content))
	expectedHash := hex.EncodeToString(hasher.Sum(nil))

	if resp.Policy.SHA256 != expectedHash {
		t.Fatalf("policy SHA256 mismatch: got %s, want %s", resp.Policy.SHA256, expectedHash)
	}

	// Verify Ed25519 signature
	seed := sha256.Sum256([]byte("vexa-hub-policy-signing-seed-2026"))
	privKey := ed25519.NewKeyFromSeed(seed[:])
	pubKey := privKey.Public().(ed25519.PublicKey)

	sigBytes, err := base64.StdEncoding.DecodeString(resp.Policy.Signature.Value)
	if err != nil {
		t.Fatalf("failed to decode signature base64: %v", err)
	}

	if !ed25519.Verify(pubKey, []byte(resp.Policy.SHA256), sigBytes) {
		t.Fatalf("Ed25519 signature verification failed")
	}
}
