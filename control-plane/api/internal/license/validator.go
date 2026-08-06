package license

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Default embedded public key bytes (32 raw Ed25519 public key bytes)
// Replace with production public key DER/PEM when building release binaries.
var defaultPublicKeyBytes = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// Claims represents the decoded AgentWall license JWT payload.
type Claims struct {
	OrgID    string   `json:"sub"`
	Tier     string   `json:"tier"`
	MaxSeats int      `json:"max_seats"`
	Features []string `json:"features"`
	jwt.RegisteredClaims
}

// Validator verifies Ed25519-signed AgentWall license JWTs.
type Validator struct {
	publicKey ed25519.PublicKey
}

// NewValidator constructs a Validator using raw 32-byte Ed25519 public key.
func NewValidator(pubKeyBytes []byte) (*Validator, error) {
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key size: %d, expected %d", len(pubKeyBytes), ed25519.PublicKeySize)
	}
	return &Validator{
		publicKey: ed25519.PublicKey(pubKeyBytes),
	}, nil
}

// NewValidatorFromEnv constructs a Validator using env var or fallback.
func NewValidatorFromEnv() (*Validator, error) {
	if pubKeyPath := os.Getenv("AGENTWALL_LICENSE_PUB_KEY_PATH"); pubKeyPath != "" {
		data, err := os.ReadFile(pubKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read public key from %s: %w", pubKeyPath, err)
		}
		if len(data) == ed25519.PublicKeySize {
			return NewValidator(data)
		}
	}
	// Fallback to default
	return NewValidator(defaultPublicKeyBytes)
}

// Validate decodes, checks signature, and validates claims of an Ed25519 license JWT string.
func (v *Validator) Validate(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("empty license token")
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return v.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid license JWT: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid license claims or signature")
	}

	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("license expired at %s", claims.ExpiresAt.Time.Format(time.RFC3339))
	}

	return claims, nil
}

// CommunityClaims returns default claims for un-licensed Community installations.
func CommunityClaims() *Claims {
	return &Claims{
		OrgID:    "community-local",
		Tier:     "community",
		MaxSeats: 10,
		Features: []string{},
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}
}
