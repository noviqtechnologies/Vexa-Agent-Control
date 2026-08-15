package handler

import (
	"testing"
)

func TestBcryptPasswordHashingAndVerification(t *testing.T) {
	rawPassword := "SuperSecretPassword123!"

	// 1. Hash with bcrypt
	hash, err := hashPassword(rawPassword)
	if err != nil {
		t.Fatalf("hashPassword failed: %v", err)
	}

	if len(hash) == 0 {
		t.Fatalf("hash is empty")
	}

	// Verify bcrypt prefix
	if hash[:4] != "$2a$" && hash[:4] != "$2b$" {
		t.Errorf("expected bcrypt prefix ($2a$ or $2b$), got: %s", hash[:4])
	}

	// 2. Positive verification
	ok, err := VerifyPassword(rawPassword, hash)
	if err != nil {
		t.Fatalf("VerifyPassword error: %v", err)
	}
	if !ok {
		t.Errorf("expected password verification to succeed")
	}

	// 3. Negative verification (wrong password)
	ok, err = VerifyPassword("WrongPassword123!", hash)
	if err != nil {
		t.Fatalf("VerifyPassword error on wrong password: %v", err)
	}
	if ok {
		t.Errorf("expected wrong password verification to fail")
	}

	// 4. Empty password / hash
	ok, err = VerifyPassword("", hash)
	if err != nil || ok {
		t.Errorf("expected empty password to return false without error, got ok=%v, err=%v", ok, err)
	}

	ok, err = VerifyPassword(rawPassword, "")
	if err != nil || ok {
		t.Errorf("expected empty hash to return false without error, got ok=%v, err=%v", ok, err)
	}
}

func TestLegacySha256PasswordFallback(t *testing.T) {
	rawPassword := "LegacyPassword123!"

	// Unsupported format check
	ok, err := VerifyPassword(rawPassword, "invalid_hash_format")
	if err == nil || ok {
		t.Errorf("expected error on unsupported hash format, got ok=%v, err=%v", ok, err)
	}
}
