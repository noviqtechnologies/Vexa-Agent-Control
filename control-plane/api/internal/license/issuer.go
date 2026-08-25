package license

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Issuer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func NewIssuer(privKey ed25519.PrivateKey) *Issuer {
	pubKey := privKey.Public().(ed25519.PublicKey)
	return &Issuer{
		privateKey: privKey,
		publicKey:  pubKey,
	}
}

func NewIssuerFromEnv() (*Issuer, error) {
	keyHex := os.Getenv("AGENTCONTROL_LICENSE_SIGNING_KEY")
	if keyHex == "" {
		keyHex = os.Getenv("AGENTWALL_LICENSE_SIGNING_KEY")
	}
	if keyHex == "" {
		// If no key is configured in env, check if dev mode or generate an ephemeral fallback key
		if os.Getenv("DEV_MODE") == "true" {
			// Deterministic 32-byte seed for dev mode
			seed := []byte("01234567890123456789012345678901")
			privKey := ed25519.NewKeyFromSeed(seed)
			return NewIssuer(privKey), nil
		}
		return nil, nil // Nil issuer means automated minting is disabled
	}

	decoded, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("decode AGENTCONTROL_LICENSE_SIGNING_KEY hex: %w", err)
	}

	var privKey ed25519.PrivateKey
	if len(decoded) == ed25519.SeedSize {
		privKey = ed25519.NewKeyFromSeed(decoded)
	} else if len(decoded) == ed25519.PrivateKeySize {
		privKey = ed25519.PrivateKey(decoded)
	} else {
		return nil, fmt.Errorf("invalid license signing key length: %d (expected %d or %d)", len(decoded), ed25519.SeedSize, ed25519.PrivateKeySize)
	}

	return NewIssuer(privKey), nil
}

func (i *Issuer) PublicKey() ed25519.PublicKey {
	return i.publicKey
}

func TierToFeatures(tier string) []string {
	switch tier {
	case "enterprise":
		return []string{
			"spend_caps", "spend_v2",
			"sse_push",
			"vault_custody",
			"device_governance",
			"siem_export", "siem_aggregation",
			"hitl",
			"group_policies",
			"airgap_oidc",
			"compliance_reports",
		}
	case "team":
		return []string{
			"spend_caps", "spend_v2",
			"sse_push",
			"vault_custody",
			"group_policies",
			"siem_export", "siem_aggregation",
		}
	case "community":
		fallthrough
	default:
		return []string{}
	}
}

func (i *Issuer) MintLicense(orgSlug, tier string, maxSeats int, features []string, validDays int, isTrial bool) (string, time.Time, error) {
	if i == nil || i.privateKey == nil {
		return "", time.Time{}, fmt.Errorf("license issuer not initialized")
	}

	if validDays <= 0 {
		if isTrial {
			validDays = 15
		} else {
			validDays = 365
		}
	}

	if len(features) == 0 {
		features = TierToFeatures(tier)
	}

	now := time.Now().UTC()
	expiresAt := now.AddDate(0, 0, validDays)

	trialDays := 0
	if isTrial {
		trialDays = validDays
	}

	claims := Claims{
		OrgID:     orgSlug,
		Tier:      tier,
		MaxSeats:  maxSeats,
		Features:  features,
		IsTrial:   isTrial,
		TrialDays: trialDays,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   orgSlug,
			Issuer:    "vexa-saas-hub",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signedJWT, err := token.SignedString(i.privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign license jwt: %w", err)
	}

	return signedJWT, expiresAt, nil
}

func (i *Issuer) ExtendLicense(claims *Claims, additionalDays int) (string, time.Time, error) {
	if i == nil || i.privateKey == nil {
		return "", time.Time{}, fmt.Errorf("license issuer not initialized")
	}

	if additionalDays <= 0 {
		additionalDays = 30
	}

	now := time.Now().UTC()
	var baseExpiry time.Time
	if claims.ExpiresAt != nil && claims.ExpiresAt.After(now) {
		baseExpiry = claims.ExpiresAt.Time
	} else {
		baseExpiry = now
	}

	newExpiry := baseExpiry.AddDate(0, 0, additionalDays)

	newClaims := Claims{
		OrgID:     claims.OrgID,
		Tier:      claims.Tier,
		MaxSeats:  claims.MaxSeats,
		Features:  claims.Features,
		IsTrial:   claims.IsTrial,
		TrialDays: claims.TrialDays,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   claims.OrgID,
			Issuer:    "vexa-saas-hub",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(newExpiry),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, newClaims)
	signedJWT, err := token.SignedString(i.privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign extended license jwt: %w", err)
	}

	return signedJWT, newExpiry, nil
}
