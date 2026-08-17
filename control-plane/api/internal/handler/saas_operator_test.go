package handler

import (
	"crypto/ed25519"
	"testing"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/license"
)

func TestTierToFeatures(t *testing.T) {
	entFeatures := license.TierToFeatures("enterprise")
	if len(entFeatures) == 0 {
		t.Error("expected enterprise tier to have features")
	}

	teamFeatures := license.TierToFeatures("team")
	if len(teamFeatures) == 0 {
		t.Error("expected team tier to have features")
	}

	commFeatures := license.TierToFeatures("community")
	if len(commFeatures) != 0 {
		t.Errorf("expected community tier to have 0 features, got %d", len(commFeatures))
	}
}

func TestSaaSOperator_MintingLogic(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(nil)
	issuer := license.NewIssuer(privKey)

	// Test 15-day trial minting
	jwt15, exp15, err := issuer.MintLicense("org-trial-15", "enterprise", 50, nil, 15, true)
	if err != nil || jwt15 == "" {
		t.Fatalf("failed to mint 15d trial: %v", err)
	}
	if exp15.IsZero() {
		t.Error("expected non-zero expiration")
	}

	// Test 30-day trial minting
	jwt30, _, err := issuer.MintLicense("org-trial-30", "enterprise", 50, nil, 30, true)
	if err != nil || jwt30 == "" {
		t.Fatalf("failed to mint 30d trial: %v", err)
	}

	// Test 365-day paid minting
	jwtPaid, _, err := issuer.MintLicense("org-paid", "team", 200, nil, 365, false)
	if err != nil || jwtPaid == "" {
		t.Fatalf("failed to mint paid: %v", err)
	}
}
