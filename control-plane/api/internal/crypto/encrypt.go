// Package crypto provides AES-256-GCM encryption for provider API keys stored in PostgreSQL.
//
// Design:
//   - Each plaintext is encrypted with a unique 12-byte random nonce.
//   - The output is base64(nonce || ciphertext || GCM-tag).
//   - The master key is a 32-byte value loaded from PROVIDER_KEY_ENCRYPTION_SECRET (hex-encoded).
//   - Decryption only happens when distributing keys to gateways — never for UI display.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// Returns base64(nonce || ciphertext || tag).
func Encrypt(masterKey []byte, plaintext string) (string, error) {
	if len(masterKey) != 32 {
		return "", fmt.Errorf("master key must be 32 bytes, got %d", len(masterKey))
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}

	// Generate a unique nonce for each encryption operation.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce generation: %w", err)
	}

	// Seal appends ciphertext+tag to the nonce prefix so the output is: nonce || ciphertext || tag
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt decrypts base64(nonce || ciphertext || tag) using AES-256-GCM.
func Decrypt(masterKey []byte, encoded string) (string, error) {
	if len(masterKey) != 32 {
		return "", fmt.Errorf("master key must be 32 bytes, got %d", len(masterKey))
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short: %d bytes, need at least %d for nonce", len(data), nonceSize)
	}

	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return "", fmt.Errorf("gcm decrypt: %w", err)
	}

	return string(plaintext), nil
}

// ParseMasterKey decodes a 64-character hex string into a 32-byte master key.
func ParseMasterKey(hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid hex in PROVIDER_KEY_ENCRYPTION_SECRET: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("PROVIDER_KEY_ENCRYPTION_SECRET must be 64 hex characters (32 bytes), got %d hex chars", len(hexKey))
	}
	return key, nil
}

// IsEncrypted performs a heuristic check on whether a stored value looks like
// our base64(nonce+ciphertext+tag) format vs plaintext. Used for auto-migration
// of pre-existing plaintext keys on first startup with encryption enabled.
//
// Returns true if the value is valid base64 and decodes to at least
// nonce_size (12) + 1 byte of ciphertext + tag_size (16) = 29 bytes.
func IsEncrypted(value string) bool {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return false
	}
	// AES-GCM: 12-byte nonce + at least 1 byte ciphertext + 16-byte tag = 29 bytes minimum
	return len(data) >= 29
}

// MaskAPIKey masks an API key for safe UI display (e.g. sk-a...1234).
func MaskAPIKey(apiKey string) string {
	if len(apiKey) > 8 {
		return apiKey[:4] + "..." + apiKey[len(apiKey)-4:]
	} else if len(apiKey) > 4 {
		return apiKey[:3] + "..."
	}
	return "sk-..."
}
