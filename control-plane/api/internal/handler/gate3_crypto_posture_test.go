package handler

// gate3_crypto_posture_test.go — Gate 3: Cryptography & Posture — Canary Verification Test Suite
//
// Acceptance criteria (enterprise_implementation_plan.md §6 Gate 3):
//   - Hub terminates if master key missing in production (FATAL).
//   - Coverage API derives real posture states from device signals.
//   - PolicyRevision: 1 hardcode is gone; posture_state field present.
//   - GCM roundtrip and AAD enforcement validated.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/device"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/kms"
)

// ── KMS Hardening Tests ───────────────────────────────────────────────────────

func TestKMS_ProductionFailsWithoutKey(t *testing.T) {
	t.Setenv("ENV", "production")
	t.Setenv("AGENTCONTROL_MASTER_KEY", "")
	t.Setenv("VEXA_MASTER_KEY", "")
	_, err := kms.NewLocalMasterKeyProvider()
	if err == nil {
		t.Fatal("expected fatal error when no master key is set in production, got nil")
	}
	if !strings.Contains(err.Error(), "FATAL") {
		t.Errorf("error should contain FATAL, got: %v", err)
	}
}

func TestKMS_ProductionAcceptsValidKey(t *testing.T) {
	validKey := strings.Repeat("ab", 32)
	t.Setenv("ENV", "production")
	t.Setenv("AGENTCONTROL_MASTER_KEY", validKey)
	p, err := kms.NewLocalMasterKeyProvider()
	if err != nil {
		t.Fatalf("expected no error with valid key in production, got: %v", err)
	}
	if p.IsDevFallback() {
		t.Error("IsDevFallback should be false when a real key is configured")
	}
}

func TestKMS_DevModeAllowsFallback(t *testing.T) {
	t.Setenv("ENV", "")
	t.Setenv("APP_ENV", "")
	t.Setenv("NODE_ENV", "")
	t.Setenv("AGENTCONTROL_MASTER_KEY", "")
	t.Setenv("VEXA_MASTER_KEY", "")
	p, err := kms.NewLocalMasterKeyProvider()
	if err != nil {
		t.Fatalf("expected dev fallback to succeed, got: %v", err)
	}
	if !p.IsDevFallback() {
		t.Error("IsDevFallback should be true when using the static dev key")
	}
}

func TestKMS_ValidateProductionConfig_RejectsDevKeyInProduction(t *testing.T) {
	t.Setenv("ENV", "")
	t.Setenv("AGENTCONTROL_MASTER_KEY", "")
	t.Setenv("VEXA_MASTER_KEY", "")
	p, err := kms.NewLocalMasterKeyProvider()
	if err != nil {
		t.Skipf("dev fallback not available: %v", err)
	}
	if !p.IsDevFallback() {
		t.Skip("not using dev fallback")
	}
	t.Setenv("ENV", "production")
	if err := p.ValidateProductionConfig(); err == nil {
		t.Fatal("expected ValidateProductionConfig to reject dev key in production")
	}
}

func TestKMS_InvalidHexKeyRejected(t *testing.T) {
	t.Setenv("AGENTCONTROL_MASTER_KEY", "not-valid-hex!!")
	t.Setenv("ENV", "")
	_, err := kms.NewLocalMasterKeyProvider()
	if err == nil {
		t.Fatal("expected error for invalid hex key, got nil")
	}
}

func TestKMS_ShortKeyRejected(t *testing.T) {
	t.Setenv("AGENTCONTROL_MASTER_KEY", strings.Repeat("aa", 16))
	t.Setenv("ENV", "")
	_, err := kms.NewLocalMasterKeyProvider()
	if err == nil {
		t.Fatal("expected error for short key (16 bytes), got nil")
	}
}

func TestKMS_LegacyVexaMasterKeyAccepted(t *testing.T) {
	validKey := strings.Repeat("cd", 32)
	t.Setenv("ENV", "production")
	t.Setenv("AGENTCONTROL_MASTER_KEY", "")
	t.Setenv("VEXA_MASTER_KEY", validKey)
	p, err := kms.NewLocalMasterKeyProvider()
	if err != nil {
		t.Fatalf("VEXA_MASTER_KEY should be accepted as a legacy alias, got: %v", err)
	}
	if p.IsDevFallback() {
		t.Error("IsDevFallback should be false when VEXA_MASTER_KEY is configured")
	}
}

func TestKMS_AppEnvProductionFails(t *testing.T) {
	t.Setenv("ENV", "")
	t.Setenv("APP_ENV", "production")
	t.Setenv("AGENTCONTROL_MASTER_KEY", "")
	t.Setenv("VEXA_MASTER_KEY", "")
	_, err := kms.NewLocalMasterKeyProvider()
	if err == nil {
		t.Fatal("APP_ENV=production should trigger fail-fast, got nil error")
	}
}

// ── Coverage Health Posture Tests ─────────────────────────────────────────────

func TestDerivePostureState_CooperativeConfigured(t *testing.T) {
	now := time.Now()
	hb := now.Add(-5 * time.Minute)
	d := device.DeviceComplianceSummary{
		EnrollmentStatus:  "ACTIVE",
		LastHeartbeatAt:   &hb,
		TamperCount24h:    0,
		OverallCompliance: "COMPLIANT",
	}
	state, evidence := derivePostureState(d, now)
	if state != "COOPERATIVE_CONFIGURED" {
		t.Errorf("expected COOPERATIVE_CONFIGURED, got %q (evidence: %s)", state, evidence)
	}
}

func TestDerivePostureState_DegradedOfflineCache(t *testing.T) {
	now := time.Now()
	hb := now.Add(-30 * time.Minute)
	d := device.DeviceComplianceSummary{
		EnrollmentStatus:  "ACTIVE",
		LastHeartbeatAt:   &hb,
		TamperCount24h:    0,
		OverallCompliance: "COMPLIANT",
	}
	state, evidence := derivePostureState(d, now)
	if state != "DEGRADED (OFFLINE_CACHE)" {
		t.Errorf("expected DEGRADED (OFFLINE_CACHE), got %q (evidence: %s)", state, evidence)
	}
}

func TestDerivePostureState_NoHeartbeat_Degraded(t *testing.T) {
	now := time.Now()
	d := device.DeviceComplianceSummary{
		EnrollmentStatus:  "ACTIVE",
		LastHeartbeatAt:   nil,
		TamperCount24h:    0,
		OverallCompliance: "COMPLIANT",
	}
	state, _ := derivePostureState(d, now)
	if state != "DEGRADED (OFFLINE_CACHE)" {
		t.Errorf("expected DEGRADED (OFFLINE_CACHE) for nil heartbeat, got %q", state)
	}
}

func TestDerivePostureState_PolicyExpired(t *testing.T) {
	now := time.Now()
	hb := now.Add(-73 * time.Hour)
	d := device.DeviceComplianceSummary{
		EnrollmentStatus:  "ACTIVE",
		LastHeartbeatAt:   &hb,
		TamperCount24h:    0,
		OverallCompliance: "COMPLIANT",
	}
	state, evidence := derivePostureState(d, now)
	if state != "POLICY_EXPIRED" {
		t.Errorf("expected POLICY_EXPIRED, got %q (evidence: %s)", state, evidence)
	}
	if !strings.Contains(evidence, "73") {
		t.Errorf("evidence should contain elapsed hours, got: %s", evidence)
	}
}

func TestDerivePostureState_Revoked(t *testing.T) {
	now := time.Now()
	hb := now.Add(-1 * time.Minute)
	d := device.DeviceComplianceSummary{
		EnrollmentStatus:  "REVOKED",
		LastHeartbeatAt:   &hb,
		TamperCount24h:    0,
		OverallCompliance: "COMPLIANT",
	}
	state, _ := derivePostureState(d, now)
	if state != "REVOKED" {
		t.Errorf("expected REVOKED, got %q", state)
	}
}

func TestDerivePostureState_Exposed_Tamper(t *testing.T) {
	now := time.Now()
	hb := now.Add(-5 * time.Minute)
	d := device.DeviceComplianceSummary{
		EnrollmentStatus:  "ACTIVE",
		LastHeartbeatAt:   &hb,
		TamperCount24h:    3,
		OverallCompliance: "COMPLIANT",
	}
	state, evidence := derivePostureState(d, now)
	if state != "EXPOSED" {
		t.Errorf("expected EXPOSED with tamper events, got %q", state)
	}
	if !strings.Contains(evidence, "tamper_count_24h=3") {
		t.Errorf("evidence should cite tamper count, got: %s", evidence)
	}
}

func TestDerivePostureState_Exposed_NonCompliant(t *testing.T) {
	now := time.Now()
	hb := now.Add(-5 * time.Minute)
	d := device.DeviceComplianceSummary{
		EnrollmentStatus:  "ACTIVE",
		LastHeartbeatAt:   &hb,
		TamperCount24h:    0,
		OverallCompliance: "NON_COMPLIANT",
	}
	state, _ := derivePostureState(d, now)
	if state != "EXPOSED" {
		t.Errorf("expected EXPOSED for NON_COMPLIANT, got %q", state)
	}
}

func TestDerivePostureState_RevokedPriorityOverExpired(t *testing.T) {
	now := time.Now()
	hb := now.Add(-100 * time.Hour)
	d := device.DeviceComplianceSummary{
		EnrollmentStatus:  "REVOKED",
		LastHeartbeatAt:   &hb,
		TamperCount24h:    0,
		OverallCompliance: "COMPLIANT",
	}
	state, _ := derivePostureState(d, now)
	if state != "REVOKED" {
		t.Errorf("REVOKED should take priority over POLICY_EXPIRED, got %q", state)
	}
}

// TestCoverageHealth_NoHardcodedPolicyRevision verifies the JSON shape.
func TestCoverageHealth_NoHardcodedPolicyRevision(t *testing.T) {
	dummy := WorkstationCoverageItem{
		PostureState:    "COOPERATIVE_CONFIGURED",
		PostureEvidence: "daemon heartbeating",
	}
	b, _ := json.Marshal(dummy)
	s := string(b)
	if strings.Contains(s, "policy_revision") {
		t.Errorf("policy_revision hardcode must not appear in WorkstationCoverageItem JSON, got: %s", s)
	}
	if !strings.Contains(s, "posture_state") {
		t.Errorf("posture_state must be present in WorkstationCoverageItem JSON, got: %s", s)
	}
	if !strings.Contains(s, "posture_evidence") {
		t.Errorf("posture_evidence must be present in WorkstationCoverageItem JSON, got: %s", s)
	}
}

// TestCoverageHealth_EmptyFleet_200OK verifies the handler returns 200 with
// an empty workstations list when the device store has no records.
func TestCoverageHealth_EmptyFleet_200OK(t *testing.T) {
	ds := device.NewNilStore()
	h := NewCoverageHealthHandler(ds)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/api/v1/fleet/coverage-health", nil)
	h.GetCoverageHealth(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp CoverageHealthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Summary.TotalWorkstations != 0 {
		t.Errorf("expected 0 workstations, got %d", resp.Summary.TotalWorkstations)
	}
	if resp.GeneratedAt == "" {
		t.Error("GeneratedAt should be populated")
	}
}

// ── KMS GCM Correctness Tests ─────────────────────────────────────────────────

func TestKMS_EncryptDecryptRoundtrip(t *testing.T) {
	os.Unsetenv("ENV")
	os.Unsetenv("AGENTCONTROL_MASTER_KEY")
	os.Unsetenv("VEXA_MASTER_KEY")
	p, err := kms.NewLocalMasterKeyProvider()
	if err != nil {
		t.Skipf("cannot init KMS: %v", err)
	}
	plaintext := []byte("enterprise-api-key-super-secret-value")
	aad := []byte("tenant-id:abc123")
	ciphertext, err := p.Encrypt(nil, plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	decrypted, err := p.Decrypt(nil, ciphertext, aad)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("roundtrip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestKMS_WrongAAD_Rejected(t *testing.T) {
	os.Unsetenv("ENV")
	os.Unsetenv("AGENTCONTROL_MASTER_KEY")
	os.Unsetenv("VEXA_MASTER_KEY")
	p, err := kms.NewLocalMasterKeyProvider()
	if err != nil {
		t.Skipf("cannot init KMS: %v", err)
	}
	ciphertext, _ := p.Encrypt(nil, []byte("secret"), []byte("correct-aad"))
	_, err = p.Decrypt(nil, ciphertext, []byte("wrong-aad"))
	if err == nil {
		t.Fatal("expected decrypt to fail with wrong AAD (GCM auth tag mismatch)")
	}
}

func TestKMS_TruncatedCiphertext_Rejected(t *testing.T) {
	os.Unsetenv("ENV")
	os.Unsetenv("AGENTCONTROL_MASTER_KEY")
	os.Unsetenv("VEXA_MASTER_KEY")
	p, err := kms.NewLocalMasterKeyProvider()
	if err != nil {
		t.Skipf("cannot init KMS: %v", err)
	}
	_, err = p.Decrypt(nil, []byte{0x01, 0x02}, []byte("aad"))
	if err == nil {
		t.Fatal("expected error for truncated ciphertext, got nil")
	}
}