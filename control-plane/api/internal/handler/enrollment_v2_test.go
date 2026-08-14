package handler_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/handler"
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
}
