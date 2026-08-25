package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSession_CreateAndValidate(t *testing.T) {
	tenantID := "123e4567-e89b-12d3-a456-426614174000"
	userID := "usr_98765"
	isAdmin := true
	isSaaSOperator := true

	cookie := Create(tenantID, userID, isAdmin, isSaaSOperator)
	if cookie == "" {
		t.Fatal("expected non-empty cookie")
	}

	info, err := Validate(cookie)
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}

	if info.TenantID != tenantID {
		t.Errorf("expected tenantID %s, got %s", tenantID, info.TenantID)
	}
	if info.UserID != userID {
		t.Errorf("expected userID %s, got %s", userID, info.UserID)
	}
	if !info.IsAdmin {
		t.Errorf("expected isAdmin true")
	}
	if !info.IsSaaSOperator {
		t.Errorf("expected isSaaSOperator true")
	}

	// Test Tampering rejection
	tamperedCookie := "tampered" + cookie[8:]
	_, err = Validate(tamperedCookie)
	if err == nil {
		t.Error("expected error validating tampered cookie, got nil")
	}

	// Test Tampered signature portion specifically
	parts := strings.Split(cookie, "|")
	if len(parts) == 6 {
		badSigCookie := fmt.Sprintf("%s|%s|%s|%s|%s|%s", parts[0], parts[1], parts[2], parts[3], parts[4], "invalidSigAAAAAAAAAAAAAAAAAAAA")
		_, err = Validate(badSigCookie)
		if err == nil {
			t.Error("expected error on forged signature, got nil")
		}
	}
}

func TestLegacySession_Validate(t *testing.T) {
	// Create legacy 4-part cookie
	userID := "legacy_admin"
	isAdmin := true
	expiry := time.Now().Add(1 * time.Hour).Unix()
	payload := fmt.Sprintf("%s|%t|%d", userID, isAdmin, expiry)

	mac := hmac.New(sha256.New, Secret)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	cookie := fmt.Sprintf("%s|%s", payload, sig)
	info, err := Validate(cookie)
	if err != nil {
		t.Fatalf("expected legacy cookie to validate successfully: %v", err)
	}
	if info.UserID != userID || !info.IsAdmin {
		t.Errorf("unexpected legacy session info: %+v", info)
	}

	// Test legacy tampering
	badCookie := fmt.Sprintf("%s|%s", payload, "badSignature==")
	if _, err := Validate(badCookie); err == nil {
		t.Error("expected error on tampered legacy cookie, got nil")
	}
}
