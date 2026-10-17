package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"
)

func TestPolicySignerRoundtrip(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	pubKeyHex := hex.EncodeToString(pubKey)

	yamlContent := "version: \"2.1\"\ndefault_action: deny\ntools: []"
	policyID := "pol-enterprise-prod"
	revision := uint64(42)

	future := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	bundle, err := SignPolicyBundle(privKey, policyID, revision, yamlContent, &future)
	if err != nil {
		t.Fatalf("SignPolicyBundle failed: %v", err)
	}

	if bundle.PolicyID != policyID || bundle.PolicyRevision != revision || bundle.PolicyYaml != yamlContent {
		t.Fatalf("bundle fields mismatched: %+v", bundle)
	}

	// Verify with matching trusted key
	if err := VerifyPolicyBundle(bundle, []string{pubKeyHex}); err != nil {
		t.Fatalf("VerifyPolicyBundle should pass: %v", err)
	}

	// Verify with empty keyring (trust on first use / unpinned)
	if err := VerifyPolicyBundle(bundle, nil); err != nil {
		t.Fatalf("VerifyPolicyBundle with nil keyring should pass: %v", err)
	}
}

func TestPolicySignerRejectsTamperedYaml(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	yamlContent := "version: \"2.1\"\ndefault_action: deny\ntools: []"
	bundle, err := SignPolicyBundle(privKey, "pol-1", 1, yamlContent, nil)
	if err != nil {
		t.Fatalf("SignPolicyBundle failed: %v", err)
	}

	// Tamper with YAML policy
	bundle.PolicyYaml = "version: \"2.1\"\ndefault_action: allow\ntools: []"

	if err := VerifyPolicyBundle(bundle, []string{hex.EncodeToString(pubKey)}); err == nil {
		t.Fatalf("expected error on tampered yaml, got nil")
	}
}

func TestPolicySignerRejectsTamperedMetadata(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	yamlContent := "version: \"2.1\"\ndefault_action: deny"
	bundle, err := SignPolicyBundle(privKey, "pol-1", 1, yamlContent, nil)
	if err != nil {
		t.Fatalf("SignPolicyBundle failed: %v", err)
	}

	// Tamper with revision
	bundle.PolicyRevision = 2
	if err := VerifyPolicyBundle(bundle, []string{hex.EncodeToString(pubKey)}); err == nil {
		t.Fatalf("expected error on tampered revision, got nil")
	}

	// Tamper with expires_at
	bundle.PolicyRevision = 1
	maliciousExpiry := time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	bundle.ExpiresAt = &maliciousExpiry
	if err := VerifyPolicyBundle(bundle, []string{hex.EncodeToString(pubKey)}); err == nil {
		t.Fatalf("expected error on tampered expires_at, got nil")
	}
}

func TestPolicySignerRejectsUntrustedKey(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	otherPubKey, _, _ := ed25519.GenerateKey(rand.Reader)

	bundle, _ := SignPolicyBundle(privKey, "pol-1", 1, "version: \"2.1\"", nil)

	err := VerifyPolicyBundle(bundle, []string{hex.EncodeToString(otherPubKey)})
	if err == nil {
		t.Fatalf("expected untrusted key error, got nil")
	}
}
