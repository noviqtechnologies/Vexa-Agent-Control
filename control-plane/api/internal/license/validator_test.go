package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestValidator_ValidToken(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 keypair: %v", err)
	}

	validator, err := NewValidator(pubKey)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	claims := &Claims{
		OrgID:    "acme-corp",
		Tier:     "team",
		MaxSeats: 25,
		Features: []string{"siem_aggregation", "spend_caps"},
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signedToken, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	validated, err := validator.Validate(signedToken)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if validated.OrgID != "acme-corp" {
		t.Errorf("OrgID = %q, want %q", validated.OrgID, "acme-corp")
	}
	if validated.Tier != "team" {
		t.Errorf("Tier = %q, want %q", validated.Tier, "team")
	}
	if validated.MaxSeats != 25 {
		t.Errorf("MaxSeats = %d, want 25", validated.MaxSeats)
	}
}

func TestValidator_ExpiredToken(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	validator, _ := NewValidator(pubKey)

	claims := &Claims{
		OrgID:    "expired-corp",
		Tier:     "team",
		MaxSeats: 10,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-48 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-24 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signedToken, _ := token.SignedString(privKey)

	_, err = validator.Validate(signedToken)
	if err == nil {
		t.Fatalf("expected error for expired token, got nil")
	}
}

func TestCommunityClaims(t *testing.T) {
	c := CommunityClaims()
	if c.Tier != "community" {
		t.Errorf("CommunityClaims Tier = %q, want community", c.Tier)
	}
	if c.MaxSeats != 10 {
		t.Errorf("CommunityClaims MaxSeats = %d, want 10", c.MaxSeats)
	}
}
