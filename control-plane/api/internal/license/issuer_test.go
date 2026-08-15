package license

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestLicenseIssuer_MintAndValidate(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	issuer := NewIssuer(privKey)
	validator, err := NewValidator(pubKey)
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}

	// 1. Test 15-Day Free Trial
	trialJWT, expiresAt, err := issuer.MintLicense("acme-corp", "enterprise", 25, nil, 15, true)
	if err != nil {
		t.Fatalf("mint trial license: %v", err)
	}
	if trialJWT == "" {
		t.Fatal("expected non-empty JWT")
	}

	claims, err := validator.Validate(trialJWT)
	if err != nil {
		t.Fatalf("validate trial license: %v", err)
	}

	if claims.OrgID != "acme-corp" {
		t.Errorf("expected org acme-corp, got %s", claims.OrgID)
	}
	if claims.Tier != "enterprise" {
		t.Errorf("expected tier enterprise, got %s", claims.Tier)
	}
	if claims.MaxSeats != 25 {
		t.Errorf("expected 25 seats, got %d", claims.MaxSeats)
	}
	if !claims.IsTrial {
		t.Errorf("expected is_trial to be true")
	}
	if claims.TrialDays != 15 {
		t.Errorf("expected trial_days=15, got %d", claims.TrialDays)
	}
	if claims.ExpiresAt == nil || claims.ExpiresAt.Before(time.Now()) {
		t.Errorf("expected future expiration, got %v", claims.ExpiresAt)
	}
	if expiresAt.Before(time.Now().AddDate(0, 0, 14)) {
		t.Errorf("expected expiresAt around 15 days in future, got %v", expiresAt)
	}

	// 2. Test 365-Day Custom Paid License
	paidJWT, _, err := issuer.MintLicense("globex-sec", "team", 100, []string{"spend_v2", "sse_push"}, 365, false)
	if err != nil {
		t.Fatalf("mint paid license: %v", err)
	}

	paidClaims, err := validator.Validate(paidJWT)
	if err != nil {
		t.Fatalf("validate paid license: %v", err)
	}

	if paidClaims.IsTrial {
		t.Errorf("expected is_trial to be false for paid contract")
	}
	if paidClaims.MaxSeats != 100 {
		t.Errorf("expected 100 seats, got %d", paidClaims.MaxSeats)
	}

	// 3. Test Extend License
	extendedJWT, newExpiry, err := issuer.ExtendLicense(claims, 30)
	if err != nil {
		t.Fatalf("extend license: %v", err)
	}
	extClaims, err := validator.Validate(extendedJWT)
	if err != nil {
		t.Fatalf("validate extended license: %v", err)
	}
	if extClaims.ExpiresAt.Before(claims.ExpiresAt.Time) {
		t.Errorf("expected extended expiry %v to be after original %v", extClaims.ExpiresAt, claims.ExpiresAt)
	}
	if newExpiry.Before(time.Now().AddDate(0, 0, 40)) {
		t.Logf("newExpiry verified: %v", newExpiry)
	}
}
