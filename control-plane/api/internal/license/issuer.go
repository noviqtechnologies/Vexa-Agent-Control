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
		if os.Getenv("DEV_MODE") == "true" {
			seed := []byte("01234567890123456789012345678901")
			privKey := ed25519.NewKeyFromSeed(seed)
			return NewIssuer(privKey), nil
		}
		return nil, nil
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
			"otet_enrollment",
			"aggregated_audit",
			"siem_export", "siem_aggregation",
			"hitl",
			"group_policies",
			"oidc_sso",
			"mtls_identity",
			"compliance_reports",
			"cmk_custody",
			"advanced_rbac",
		}
	case "team":
		return []string{
			"spend_caps", "spend_v2",
			"sse_push",
			"vault_custody",
			"group_policies",
			"otet_enrollment",
			"aggregated_audit",
			"alerts",
		}
	case "developer":
		fallthrough
	case "community":
		fallthrough
	default:
		return []string{}
	}
}

func TierToMaxDevices(tier string) int {
	switch tier {
	case "enterprise":
		return -1 // Unlimited
	case "team":
		return 25
	case "developer":
		fallthrough
	case "community":
		fallthrough
	default:
		return 1
	}
}

func (i *Issuer) MintLicense(orgSlug, tier string, maxDevices int, features []string, validDays int, isTrial bool) (string, time.Time, error) {
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

	if maxDevices == 0 {
		maxDevices = TierToMaxDevices(tier)
	}

	if len(features) == 0 {
		features = TierToFeatures(tier)
	}

	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(validDays) * 24 * time.Hour)

	claims := &Claims{
		OrgID:      orgSlug,
		Tier:       tier,
		MaxDevices: maxDevices,
		MaxSeats:   maxDevices,
		Features:   features,
		IsTrial:    isTrial,
		TrialDays:  validDays,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.vexa.ai",
			Subject:   orgSlug,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Minute)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenString, err := token.SignedString(i.privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign license token: %w", err)
	}

	return tokenString, expiresAt, nil
}

func (i *Issuer) ExtendLicense(existingClaims *Claims, additionalDays int) (string, time.Time, error) {
	if i == nil || i.privateKey == nil {
		return "", time.Time{}, fmt.Errorf("license issuer not initialized")
	}

	if additionalDays <= 0 {
		additionalDays = 30
	}

	currentExpiry := time.Now().UTC()
	if existingClaims.ExpiresAt != nil && existingClaims.ExpiresAt.After(currentExpiry) {
		currentExpiry = existingClaims.ExpiresAt.Time
	}

	newExpiry := currentExpiry.Add(time.Duration(additionalDays) * 24 * time.Hour)
	now := time.Now().UTC()

	claims := &Claims{
		OrgID:      existingClaims.OrgID,
		Tier:       existingClaims.Tier,
		MaxDevices: existingClaims.MaxDevices,
		MaxSeats:   existingClaims.MaxSeats,
		Features:   existingClaims.Features,
		IsTrial:    existingClaims.IsTrial,
		TrialDays:  existingClaims.TrialDays + additionalDays,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.vexa.ai",
			Subject:   existingClaims.OrgID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(newExpiry),
			NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Minute)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenString, err := token.SignedString(i.privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign extended license token: %w", err)
	}

	return tokenString, newExpiry, nil
}
