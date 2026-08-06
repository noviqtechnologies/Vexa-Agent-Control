package crypto

import (
	"encoding/hex"
	"testing"
)

func testMasterKey() []byte {
	key, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	return key
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := testMasterKey()
	originalText := "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"

	encrypted, err := Encrypt(key, originalText)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if encrypted == originalText {
		t.Fatalf("Encrypted text matches original text!")
	}

	decrypted, err := Decrypt(key, encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if decrypted != originalText {
		t.Fatalf("Expected decrypted text %q, got %q", originalText, decrypted)
	}
}

func TestEncryptDifferentNonces(t *testing.T) {
	key := testMasterKey()
	plaintext := "sk-ant-api03-secretkey"

	enc1, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt 1 failed: %v", err)
	}

	enc2, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt 2 failed: %v", err)
	}

	if enc1 == enc2 {
		t.Errorf("Expected different ciphertexts due to random nonce, but got identical results")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := testMasterKey()
	key2, _ := hex.DecodeString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	encrypted, err := Encrypt(key1, "super-secret-key")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt(key2, encrypted)
	if err == nil {
		t.Fatalf("Expected error when decrypting with wrong key, but got success")
	}
}

func TestParseMasterKey(t *testing.T) {
	validHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	key, err := ParseMasterKey(validHex)
	if err != nil {
		t.Fatalf("Expected valid ParseMasterKey, got: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("Expected key length 32, got %d", len(key))
	}

	invalidLength := "0123456789abcdef"
	_, err = ParseMasterKey(invalidLength)
	if err == nil {
		t.Fatalf("Expected error for invalid key length, got nil")
	}

	invalidHexChar := "zz23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	_, err = ParseMasterKey(invalidHexChar)
	if err == nil {
		t.Fatalf("Expected error for non-hex string, got nil")
	}
}

func TestIsEncrypted(t *testing.T) {
	key := testMasterKey()
	encrypted, _ := Encrypt(key, "sk-test-12345")

	if !IsEncrypted(encrypted) {
		t.Errorf("Expected IsEncrypted(encrypted) to be true")
	}

	if IsEncrypted("sk-test-12345") {
		t.Errorf("IsEncrypted('sk-test-12345') returned true for plaintext API key")
	}
}
