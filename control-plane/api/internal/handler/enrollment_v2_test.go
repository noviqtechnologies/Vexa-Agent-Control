package handler_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/handler"
)

func TestCanonicalTranscript_FormattingAndVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	txID := "0198d5b4-7376-7d90-8bc5-6dc3d4e80c26"
	chID := "0198d5b4-89aa-7b1f-9b1e-0c52e78b3ee0"
	audience := "enroll.vexasec.io"
	tenantID := "0198d5b4-6fd7-7e2e-a6e2-c8d4df112a11"
	edFP := hex.EncodeToString(sha256.New().Sum(pub))
	csrSHA := "ca978112ca1bbdcafac231b39a23dc4da7860819c1966ec12179e5b7b99a4fc5"
	schemaVer := "2.0"

	transcript := handler.FormatCanonicalTranscript(txID, chID, audience, tenantID, edFP, csrSHA, schemaVer)
	expected := "0198d5b4-7376-7d90-8bc5-6dc3d4e80c26|0198d5b4-89aa-7b1f-9b1e-0c52e78b3ee0|enroll.vexasec.io|0198d5b4-6fd7-7e2e-a6e2-c8d4df112a11|" + edFP + "|ca978112ca1bbdcafac231b39a23dc4da7860819c1966ec12179e5b7b99a4fc5|2.0"

	if transcript != expected {
		t.Fatalf("Transcript mismatch.\nGot:  %s\nWant: %s", transcript, expected)
	}

	sig := ed25519.Sign(priv, []byte(transcript))

	if !handler.VerifySignatureHelper(pub, transcript, sig) {
		t.Fatal("Signature verification failed on valid transcript")
	}

	// Tampered transcript must fail
	tamperedTranscript := transcript + "_tampered"
	if handler.VerifySignatureHelper(pub, tamperedTranscript, sig) {
		t.Fatal("Tampered transcript signature unexpectedly verified")
	}

	// Tampered signature must fail
	tamperedSig := make([]byte, len(sig))
	copy(tamperedSig, sig)
	tamperedSig[0] ^= 0xFF
	if handler.VerifySignatureHelper(pub, transcript, tamperedSig) {
		t.Fatal("Tampered signature unexpectedly verified")
	}

	// Invalid pubkey length must fail
	if handler.VerifySignatureHelper([]byte("short"), transcript, sig) {
		t.Fatal("Invalid pubkey length unexpectedly succeeded")
	}

	// Invalid signature length must fail
	if handler.VerifySignatureHelper(pub, transcript, []byte("short")) {
		t.Fatal("Invalid signature length unexpectedly succeeded")
	}
}

func TestCanonicalTranscript_HashComputation(t *testing.T) {
	txID := "tx-123"
	chID := "ch-456"
	audience := "enroll.vexasec.io"
	tenantID := "tenant-789"
	edFP := "fingerprint123"
	csrSHA := "csrsha256"
	schemaVer := "2.0"

	transcript := handler.FormatCanonicalTranscript(txID, chID, audience, tenantID, edFP, csrSHA, schemaVer)
	expectedTranscript := "tx-123|ch-456|enroll.vexasec.io|tenant-789|fingerprint123|csrsha256|2.0"
	if transcript != expectedTranscript {
		t.Fatalf("unexpected transcript format: got %s, want %s", transcript, expectedTranscript)
	}

	sum := sha256.Sum256([]byte(transcript))
	expectedHash := hex.EncodeToString(sum[:])
	if len(expectedHash) != 64 {
		t.Fatalf("expected 64-char sha256 hex, got %s", expectedHash)
	}
}

func TestCanonicalTranscript_RetryWithNewCSR(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	txID := "0198d5b4-7376-7d90-8bc5-6dc3d4e80c26"
	chID_1 := "0198d5b4-89aa-7b1f-9b1e-0c52e78b3ee1"
	chID_2 := "0198d5b4-89aa-7b1f-9b1e-0c52e78b3ee2"
	audience := "enroll.vexasec.io"
	tenantID := "0198d5b4-6fd7-7e2e-a6e2-c8d4df112a11"
	edFP := hex.EncodeToString(sha256.New().Sum(pub))

	// Attempt 1 CSR
	csr1 := "csr-attempt-1-sha256-hash-value-11111111111111111111111111111111"
	transcript1 := handler.FormatCanonicalTranscript(txID, chID_1, audience, tenantID, edFP, csr1, "2.0")
	hash1 := hex.EncodeToString(sha256.New().Sum([]byte(transcript1)))

	// Client generates attempt 2 with fresh CSR and fresh challenge
	csr2 := "csr-attempt-2-sha256-hash-value-22222222222222222222222222222222"
	transcript2 := handler.FormatCanonicalTranscript(txID, chID_2, audience, tenantID, edFP, csr2, "2.0")
	sum2 := sha256.Sum256([]byte(transcript2))
	hash2 := hex.EncodeToString(sum2[:])
	sig2 := ed25519.Sign(priv, []byte(transcript2))

	// If server had stale CSR1, reconstructing with CSR1 would fail hash match with client's SignedPayloadSHA256 (hash2)
	staleTranscript := handler.FormatCanonicalTranscript(txID, chID_2, audience, tenantID, edFP, csr1, "2.0")
	staleSum := sha256.Sum256([]byte(staleTranscript))
	staleHash := hex.EncodeToString(staleSum[:])
	if staleHash == hash2 {
		t.Fatal("stale transcript hash should not match new transcript hash")
	}

	// With refreshed CSR2, server transcript matches client payload hash and signature verifies
	if hash2 == hash1 {
		t.Fatal("attempt 1 and 2 hashes should differ")
	}
	if !handler.VerifySignatureHelper(pub, transcript2, sig2) {
		t.Fatal("signature on refreshed transcript must verify successfully")
	}
}

