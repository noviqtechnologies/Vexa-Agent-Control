package session

import (
	"testing"
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
}
