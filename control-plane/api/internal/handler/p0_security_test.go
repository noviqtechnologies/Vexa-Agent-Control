package handler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/kms"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

// ── P0-1: Telemetry Ingest Security Tests ────────────────────────────────────

func TestP0_TelemetryIngest_Unauthenticated_Rejected(t *testing.T) {
	ds := &mockStore{}
	h := NewIngestHandler(ds, nil, nil)

	body := []byte(`{"device_id":"dev-1","events":[{"event_id":"evt-1","timestamp_ms":1700000000000,"session_id":"s1","agent_id":"a1","tool_name":"bash","decision":"allow","dlp_findings":[],"injection_findings":[],"semantic_findings":[]}]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v2/telemetry/ingest", bytes.NewReader(body))
	// No device principal injected
	rec := httptest.NewRecorder()

	h.PostTelemetryIngest(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for anonymous telemetry ingest, got %d", rec.Code)
	}
}

func TestP0_TelemetryIngest_DeviceSpoofing_Rejected(t *testing.T) {
	ds := &mockStore{}
	h := NewIngestHandler(ds, nil, nil)

	// Authenticated principal is dev-legitimate
	principal := &model.DevicePrincipal{
		DeviceID:       "dev-legitimate",
		OrganizationID: "tenant-legitimate",
	}

	// Attacker tries to submit events claiming to be dev-attacker
	body := []byte(`{"device_id":"dev-attacker","events":[{"event_id":"evt-1","timestamp_ms":1700000000000,"session_id":"s1","agent_id":"a1","tool_name":"bash","decision":"allow","dlp_findings":[],"injection_findings":[],"semantic_findings":[]}]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v2/telemetry/ingest", bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), middleware.DevicePrincipalKey, principal)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.PostTelemetryIngest(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when payload device_id does not match authenticated principal, got %d", rec.Code)
	}
}

func TestP0_TelemetryIngest_BatchSizeValidation(t *testing.T) {
	ds := &mockStore{}
	h := NewIngestHandler(ds, nil, nil)

	principal := &model.DevicePrincipal{
		DeviceID:       "dev-1",
		OrganizationID: "tenant-1",
	}

	// 1. Empty batch
	emptyBody := []byte(`{"device_id":"dev-1","events":[]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v2/telemetry/ingest", bytes.NewReader(emptyBody))
	req = req.WithContext(context.WithValue(req.Context(), middleware.DevicePrincipalKey, principal))
	rec := httptest.NewRecorder()
	h.PostTelemetryIngest(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for empty batch, got %d", rec.Code)
	}

	// 2. Excessively large batch (>1000 events)
	events := make([]map[string]interface{}, 1001)
	for i := 0; i < 1001; i++ {
		events[i] = map[string]interface{}{
			"event_id":           fmt.Sprintf("evt-%d", i),
			"timestamp_ms":       1700000000000,
			"session_id":         "s1",
			"agent_id":           "a1",
			"tool_name":          "bash",
			"decision":           "allow",
			"dlp_findings":       []interface{}{},
			"injection_findings": []interface{}{},
			"semantic_findings":  []interface{}{},
		}
	}
	largePayload, _ := json.Marshal(map[string]interface{}{
		"device_id": "dev-1",
		"events":    events,
	})
	reqLarge := httptest.NewRequest(http.MethodPost, "/api/v2/telemetry/ingest", bytes.NewReader(largePayload))
	reqLarge = reqLarge.WithContext(context.WithValue(reqLarge.Context(), middleware.DevicePrincipalKey, principal))
	recLarge := httptest.NewRecorder()
	h.PostTelemetryIngest(recLarge, reqLarge)

	if recLarge.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 Payload Too Large for >1000 events, got %d", recLarge.Code)
	}
}

func TestP0_TelemetryIngest_TruthfulErrorReporting(t *testing.T) {
	insertedEvents := make([]*model.RedactedEvent, 0)
	ds := &mockStore{
		insertEventFunc: func(ctx context.Context, tenantID string, e *model.RedactedEvent) error {
			if e.EventID == "evt-db-fail" {
				return fmt.Errorf("simulated database disk failure")
			}
			insertedEvents = append(insertedEvents, e)
			return nil
		},
	}
	h := NewIngestHandler(ds, nil, nil)

	principal := &model.DevicePrincipal{
		DeviceID:       "dev-1",
		OrganizationID: "tenant-alpha",
	}

	body := []byte(`{
		"device_id":"dev-1",
		"events":[
			{"event_id":"evt-ok-1","timestamp_ms":1700000000000,"session_id":"s1","agent_id":"a1","tool_name":"bash","decision":"allowed","dlp_findings":[],"injection_findings":[],"semantic_findings":[]},
			{"event_id":"evt-db-fail","timestamp_ms":1700000000000,"session_id":"s1","agent_id":"a1","tool_name":"bash","decision":"allowed","dlp_findings":[],"injection_findings":[],"semantic_findings":[]},
			{"event_id":"","timestamp_ms":1700000000000,"session_id":"s1","agent_id":"a1","tool_name":"bash","decision":"allowed","dlp_findings":[],"injection_findings":[],"semantic_findings":[]}
		]
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v2/telemetry/ingest", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.DevicePrincipalKey, principal))
	rec := httptest.NewRecorder()

	h.PostTelemetryIngest(rec, req)

	// Since 1 succeeded and 2 failed, expected HTTP 207 Multi-Status
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("expected 207 MultiStatus on partial insert failure, got %d", rec.Code)
	}

	var resp struct {
		AcceptedCount int      `json:"accepted_count"`
		FailedCount   int      `json:"failed_count"`
		Errors        []string `json:"errors"`
		DeviceID      string   `json:"device_id"`
		TenantID      string   `json:"tenant_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.AcceptedCount != 1 {
		t.Errorf("expected accepted_count 1, got %d", resp.AcceptedCount)
	}
	if resp.FailedCount != 2 {
		t.Errorf("expected failed_count 2, got %d", resp.FailedCount)
	}
	if resp.DeviceID != "dev-1" {
		t.Errorf("expected device_id dev-1, got %s", resp.DeviceID)
	}
	if resp.TenantID != "tenant-alpha" {
		t.Errorf("expected tenant_id tenant-alpha, got %s", resp.TenantID)
	}
}

// ── P0-1: Effective Policy Manifest Security Tests ──────────────────────────

func TestP0_EffectivePolicy_Unauthenticated_Rejected(t *testing.T) {
	ds := &mockStore{}
	h := NewEffectivePolicyHandler(nil, ds)

	req := httptest.NewRequest(http.MethodGet, "/api/v2/policy/effective", nil)
	rec := httptest.NewRecorder()

	h.GetEffectiveSigned(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for unauthenticated effective policy request, got %d", rec.Code)
	}
}

func TestP0_EffectivePolicy_MissingKey_FailsClosed(t *testing.T) {
	ds := &mockStore{}
	h := NewEffectivePolicyHandler(nil, ds)

	principal := &model.DevicePrincipal{
		DeviceID:       "dev-1",
		OrganizationID: "tenant-1",
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v2/policy/effective", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.DevicePrincipalKey, principal))
	rec := httptest.NewRecorder()

	h.GetEffectiveSigned(rec, req)

	// Must fail closed with 503 rather than using a hardcoded or derived dev seed
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 Service Unavailable when no signing key is configured, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "vexa-hub-policy-signing-seed-2026") {
		t.Errorf("found hardcoded seed string in response")
	}
}

func TestP0_EffectivePolicy_CanonicalSigningAndVerification(t *testing.T) {
	ds := &mockStore{
		getActiveGroupPolicyFunc: func(ctx context.Context, tenantID, groupID string) (*store.GroupPolicyVersion, error) {
			return &store.GroupPolicyVersion{
				ID:      "gp-1",
				Version: 42,
			}, nil
		},
	}
	h := NewEffectivePolicyHandler(nil, ds)

	// Generate genuine Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	h.SetSigningKey(privKey)

	tenantID := "tenant-acme-corp"
	principal := &model.DevicePrincipal{
		DeviceID:       "dev-workstation-1",
		OrganizationID: tenantID,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v2/policy/effective", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.DevicePrincipalKey, principal))
	rec := httptest.NewRecorder()

	h.GetEffectiveSigned(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from GetEffectiveSigned, got %d: %s", rec.Code, rec.Body.String())
	}

	var manifest struct {
		PolicyVersion int                    `json:"policy_version"`
		PolicyHash    string                 `json:"policy_hash"`
		TenantID      string                 `json:"tenant_id"`
		IssuedAt      int64                  `json:"issued_at"`
		ExpiresAt     int64                  `json:"expires_at"`
		AllowedModels []string               `json:"allowed_models"`
		BlockedModels []string               `json:"blocked_models"`
		DlpRules      map[string]interface{} `json:"dlp_rules"`
		RateLimits    map[string]interface{} `json:"rate_limits"`
		Signature     string                 `json:"signature"`
		PublicKey     string                 `json:"public_key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &manifest); err != nil {
		t.Fatalf("failed to decode manifest: %v", err)
	}

	if manifest.PolicyVersion != 42 {
		t.Errorf("expected policy_version 42, got %d", manifest.PolicyVersion)
	}
	if manifest.TenantID != tenantID {
		t.Errorf("expected tenant_id %s, got %s", tenantID, manifest.TenantID)
	}

	// Decode signature
	if !strings.HasPrefix(manifest.Signature, "ed25519:") {
		t.Fatalf("signature missing ed25519: prefix: %s", manifest.Signature)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(manifest.Signature, "ed25519:"))
	if err != nil {
		t.Fatalf("failed to decode signature base64: %v", err)
	}

	// 1. Cryptographically verify signature matches canonical preimage
	preimage := CanonicalEffectivePolicyPreimage(
		manifest.TenantID,
		manifest.IssuedAt,
		manifest.ExpiresAt,
		manifest.AllowedModels,
		manifest.BlockedModels,
		manifest.DlpRules,
		manifest.RateLimits,
		manifest.PolicyVersion,
	)
	hasher := sha256.New()
	hasher.Write(preimage)
	expectedHash := fmt.Sprintf("sha256:%x", hasher.Sum(nil))

	if manifest.PolicyHash != expectedHash {
		t.Fatalf("policy_hash mismatch: expected %s, got %s", expectedHash, manifest.PolicyHash)
	}

	if !ed25519.Verify(pubKey, []byte(expectedHash), sigBytes) {
		t.Fatalf("Ed25519 signature verification failed against authoritative public key")
	}

	// 2. Tamper Test: alter one field (e.g., flip block_private_keys to false)
	tamperedDlp := make(map[string]interface{})
	for k, v := range manifest.DlpRules {
		tamperedDlp[k] = v
	}
	tamperedDlp["block_private_keys"] = false

	tamperedPreimage := CanonicalEffectivePolicyPreimage(
		manifest.TenantID,
		manifest.IssuedAt,
		manifest.ExpiresAt,
		manifest.AllowedModels,
		manifest.BlockedModels,
		tamperedDlp,
		manifest.RateLimits,
		manifest.PolicyVersion,
	)
	tamperedHasher := sha256.New()
	tamperedHasher.Write(tamperedPreimage)
	tamperedHash := fmt.Sprintf("sha256:%x", tamperedHasher.Sum(nil))

	// Verification MUST fail on tampered content
	if ed25519.Verify(pubKey, []byte(tamperedHash), sigBytes) {
		t.Fatalf("CRITICAL: Tampered manifest passed signature verification!")
	}
}

// ── P0-1: Audit Checkpoints Security Tests ──────────────────────────────────

func TestP0_AuditCheckpoints_Unauthenticated_Rejected(t *testing.T) {
	ds := &mockStore{}
	h := NewIngestHandler(ds, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v2/audit/checkpoints", nil)
	rec := httptest.NewRecorder()

	h.GetAuditCheckpoints(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for unauthenticated checkpoints request, got %d", rec.Code)
	}
}

func TestP0_AuditCheckpoints_NoFakeCheckpoints(t *testing.T) {
	ds := &mockStore{} // Returns empty slice []store.AuditCheckpoint{}
	h := NewIngestHandler(ds, nil, nil)

	principal := &model.DevicePrincipal{
		DeviceID:       "dev-1",
		OrganizationID: "tenant-acme",
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v2/audit/checkpoints", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.DevicePrincipalKey, principal))
	rec := httptest.NewRecorder()

	h.GetAuditCheckpoints(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var resp struct {
		Checkpoints []store.AuditCheckpoint `json:"checkpoints"`
		TotalCount  int                     `json:"total_count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Must be truthful: 0 checkpoints, not synthetic 1-1000 ranges!
	if resp.TotalCount != 0 || len(resp.Checkpoints) != 0 {
		t.Fatalf("expected 0 checkpoints when none committed, got %d", resp.TotalCount)
	}

	// Verify no hardcoded seed is present anywhere in output
	if strings.Contains(rec.Body.String(), "vexa-hub-audit-checkpoint-key-2026") {
		t.Fatalf("found hardcoded checkpoint seed in response")
	}
}

// ── P0-2: Credential Encryption & KMS Security Tests ────────────────────────

func TestP0_KMS_FailFast_When_DevModeFalse(t *testing.T) {
	t.Setenv("AGENTCONTROL_MASTER_KEY", "")
	t.Setenv("PROVIDER_KEY_ENCRYPTION_SECRET", "")
	t.Setenv("VEXA_MASTER_KEY", "")
	t.Setenv("DEV_MODE", "false")
	t.Setenv("ALLOW_DEV_MODE", "false")
	t.Setenv("ENV", "")

	_, err := kms.NewLocalMasterKeyProvider()
	if err == nil {
		t.Fatalf("expected fatal error when DEV_MODE=false without master key, got nil")
	}
	if !strings.Contains(err.Error(), "FATAL") {
		t.Errorf("expected FATAL error message, got: %v", err)
	}
}

func TestP0_KMS_LoadsFromProviderKeyEncryptionSecret(t *testing.T) {
	testKeyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	t.Setenv("AGENTCONTROL_MASTER_KEY", "")
	t.Setenv("VEXA_MASTER_KEY", "")
	t.Setenv("PROVIDER_KEY_ENCRYPTION_SECRET", testKeyHex)
	t.Setenv("DEV_MODE", "false")

	kp, err := kms.NewLocalMasterKeyProvider()
	if err != nil {
		t.Fatalf("failed to load master key from PROVIDER_KEY_ENCRYPTION_SECRET: %v", err)
	}
	if kp.IsDevFallback() {
		t.Fatalf("provider marked as dev fallback when valid PROVIDER_KEY_ENCRYPTION_SECRET was provided")
	}
}

func TestP0_ProviderKey_RoundTrip_SaveAndDecrypt(t *testing.T) {
	testKeyHex := "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	t.Setenv("PROVIDER_KEY_ENCRYPTION_SECRET", testKeyHex)

	kp, err := kms.NewLocalMasterKeyProvider()
	if err != nil {
		t.Fatalf("failed to initialize KMS provider: %v", err)
	}

	var savedCiphertext string
	var savedVersion int
	ds := &mockStore{
		insertEncryptedProviderKeyFunc: func(ctx context.Context, tenantID, provider, keyAlias, plainSecret string, kmsProvider kms.KMSProvider) error {
			savedVersion = 1
			aad := []byte(fmt.Sprintf("%s|%s|%s|%d", tenantID, provider, keyAlias, savedVersion))
			cBytes, encErr := kmsProvider.Encrypt(ctx, []byte(plainSecret), aad)
			if encErr != nil {
				return encErr
			}
			savedCiphertext = fmt.Sprintf("%x", cBytes)
			return nil
		},
		getDecryptedProviderKeyFunc: func(ctx context.Context, tenantID, provider string, kmsProvider kms.KMSProvider) (string, error) {
			var cBytes []byte
			_, decErr := fmt.Sscanf(savedCiphertext, "%x", &cBytes)
			if decErr != nil {
				return "", decErr
			}
			aad := []byte(fmt.Sprintf("%s|%s|default|%d", tenantID, provider, savedVersion))
			pBytes, decErr := kmsProvider.Decrypt(ctx, cBytes, aad)
			if decErr != nil {
				return "", decErr
			}
			return string(pBytes), nil
		},
	}

	h := NewProviderKeysHandler(ds, nil, kp)

	// 1. Save via handler (UI path)
	body := []byte(`{"provider":"openai","api_key":"sk-proj-super-secret-key-12345"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/providers/keys", bytes.NewReader(body))
	reqPrincipal := &middleware.RequestPrincipal{
		OrganizationID: "tenant-test",
		TenantID:       "tenant-test",
	}
	req = req.WithContext(context.WithValue(req.Context(), middleware.RequestPrincipalKey, reqPrincipal))
	rec := httptest.NewRecorder()

	h.Save(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created from Save, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Decrypt via broker retrieval path
	decrypted, err := ds.GetDecryptedProviderKey(context.Background(), "tenant-test", "openai", kp)
	if err != nil {
		t.Fatalf("failed to decrypt provider key via vault path: %v", err)
	}

	if decrypted != "sk-proj-super-secret-key-12345" {
		t.Fatalf("round-trip secret mismatch: expected sk-proj-super-secret-key-12345, got %s", decrypted)
	}
}

func TestP0_ProviderKey_TamperCiphertext_FailsClosed(t *testing.T) {
	testKeyHex := "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	t.Setenv("PROVIDER_KEY_ENCRYPTION_SECRET", testKeyHex)

	kp, err := kms.NewLocalMasterKeyProvider()
	if err != nil {
		t.Fatalf("failed to initialize KMS provider: %v", err)
	}

	ctx := context.Background()
	aad := []byte("tenant-1|openai|default|1")
	cipherBytes, err := kp.Encrypt(ctx, []byte("sk-secret"), aad)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Tamper with ciphertext by flipping last byte
	tampered := make([]byte, len(cipherBytes))
	copy(tampered, cipherBytes)
	tampered[len(tampered)-1] ^= 0xFF

	// Decrypt MUST fail closed and return error
	_, err = kp.Decrypt(ctx, tampered, aad)
	if err == nil {
		t.Fatalf("tampered ciphertext decrypted successfully when it must fail closed!")
	}
}

