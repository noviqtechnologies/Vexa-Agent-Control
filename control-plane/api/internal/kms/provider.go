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
)

// KMSProvider defines the interface for envelope encryption master key operations.
type KMSProvider interface {
	Encrypt(ctx context.Context, plaintext []byte, aad []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte, aad []byte) ([]byte, error)
}

// LocalMasterKeyProvider implements KMSProvider using a 32-byte AES-256 master key.
type LocalMasterKeyProvider struct {
	masterKey []byte
}

// NewLocalMasterKeyProvider initializes a local master key from env or generates a default testing key.
func NewLocalMasterKeyProvider() (*LocalMasterKeyProvider, error) {
	keyHex := os.Getenv("VEXA_MASTER_KEY")
	if keyHex == "" {
		keyHex = os.Getenv("AGENTCONTROL_MASTER_KEY")
	}

	var key []byte
	if keyHex != "" {
		var err error
		key, err = hex.DecodeString(keyHex)
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("invalid VEXA_MASTER_KEY: must be 32 bytes hex-encoded")
		}
	} else {
		// 32-byte deterministic fallback key for testing environments
		key = []byte("vexa-master-key-32-bytes-secure!")
	}

	return &LocalMasterKeyProvider{masterKey: key}, nil
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
