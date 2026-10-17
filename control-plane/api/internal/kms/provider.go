package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// KMSProvider defines the interface for envelope encryption master key operations.
type KMSProvider interface {
	Encrypt(ctx context.Context, plaintext []byte, aad []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte, aad []byte) ([]byte, error)
}

// LocalMasterKeyProvider implements KMSProvider using a 32-byte AES-256 master key.
// In production environments (ENV=production, APP_ENV=production, or NODE_ENV=production),
// NewLocalMasterKeyProvider returns a fatal error if no key is configured — the static
// dev fallback is never used in production.
type LocalMasterKeyProvider struct {
	masterKey   []byte
	devFallback bool // true iff the static dev/test key is active
}

// NewLocalMasterKeyProvider initializes a local master key from environment or
// terminates with a fatal error in production when no key is found.
//
// Key lookup order:
//  1. AGENTCONTROL_MASTER_KEY (preferred enterprise env var)
//  2. VEXA_MASTER_KEY         (legacy alias)
//  3. Static dev fallback     ("vexa-master-key-32-bytes-secure!") — ONLY when not production
//
// Production fail-fast: if ENV / APP_ENV / NODE_ENV == "production" and neither key var
// is set, this function returns an error and the caller (main.go) log.Fatalf-s the process.
func NewLocalMasterKeyProvider() (*LocalMasterKeyProvider, error) {
	keyHex := os.Getenv("AGENTCONTROL_MASTER_KEY")
	if keyHex == "" {
		keyHex = os.Getenv("PROVIDER_KEY_ENCRYPTION_SECRET")
	}
	if keyHex == "" {
		keyHex = os.Getenv("VEXA_MASTER_KEY")
	}

	var key []byte
	if keyHex != "" {
		var err error
		key, err = hex.DecodeString(strings.TrimSpace(keyHex))
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("invalid master key: must be 32 bytes hex-encoded (AGENTCONTROL_MASTER_KEY / PROVIDER_KEY_ENCRYPTION_SECRET / VEXA_MASTER_KEY)")
		}
		return &LocalMasterKeyProvider{masterKey: key, devFallback: false}, nil
	}

	// No key configured — check if we are in a production environment or non-dev mode.
	env := strings.ToLower(os.Getenv("ENV"))
	appEnv := strings.ToLower(os.Getenv("APP_ENV"))
	nodeEnv := strings.ToLower(os.Getenv("NODE_ENV"))
	devMode := strings.ToLower(os.Getenv("DEV_MODE"))
	allowDevMode := strings.ToLower(os.Getenv("ALLOW_DEV_MODE"))
	deployProfile := strings.ToLower(os.Getenv("DEPLOY_PROFILE"))

	isProduction := env == "production" || appEnv == "production" || nodeEnv == "production" ||
		devMode == "false" || allowDevMode == "false" || deployProfile == "team" || deployProfile == "production"

	if isProduction {
		return nil, errors.New(
			"FATAL: AGENTCONTROL_MASTER_KEY or PROVIDER_KEY_ENCRYPTION_SECRET must be set in production / team mode. " +
				"The static development fallback is blocked when DEV_MODE=false or ENV=production. " +
				"Configure a 32-byte hex secret in environment or secret mounts.")
	}

	// Development & testing only — emit an unmistakable warning.
	fmt.Fprintln(os.Stderr,
		"[WARN] kms: no AGENTCONTROL_MASTER_KEY or PROVIDER_KEY_ENCRYPTION_SECRET configured — using static dev/test fallback key. "+
			"This key is NOT SECRET and must NEVER be used in production or staging.")
	key = []byte("vexa-master-key-32-bytes-secure!")
	return &LocalMasterKeyProvider{masterKey: key, devFallback: true}, nil
}

// IsDevFallback returns true when the provider was initialised with the static
// development key rather than a real enterprise secret. Call this from handler
// startup code to emit a DEV_KEY_ACTIVE warning audit event.
func (p *LocalMasterKeyProvider) IsDevFallback() bool {
	return p.devFallback
}

// ValidateProductionConfig returns an error if the provider is using the static
// dev fallback key while the process environment signals production mode.
func (p *LocalMasterKeyProvider) ValidateProductionConfig() error {
	if !p.devFallback {
		return nil
	}
	env := strings.ToLower(os.Getenv("ENV"))
	appEnv := strings.ToLower(os.Getenv("APP_ENV"))
	nodeEnv := strings.ToLower(os.Getenv("NODE_ENV"))
	devMode := strings.ToLower(os.Getenv("DEV_MODE"))
	allowDevMode := strings.ToLower(os.Getenv("ALLOW_DEV_MODE"))
	deployProfile := strings.ToLower(os.Getenv("DEPLOY_PROFILE"))

	if env == "production" || appEnv == "production" || nodeEnv == "production" ||
		devMode == "false" || allowDevMode == "false" || deployProfile == "team" || deployProfile == "production" {
		return errors.New(
			"FATAL: static dev/test master key is active in a production or team environment. " +
				"Set AGENTCONTROL_MASTER_KEY or PROVIDER_KEY_ENCRYPTION_SECRET to a cryptographically random 32-byte hex secret.")
	}
	return nil
}

func (p *LocalMasterKeyProvider) Encrypt(ctx context.Context, plaintext []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.masterKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, aad)
	return ciphertext, nil
}

func (p *LocalMasterKeyProvider) Decrypt(ctx context.Context, ciphertext []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.masterKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt GCM: %w", err)
	}

	return plaintext, nil
}
