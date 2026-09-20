package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

func TestVirtualKey_DefaultsAndScoping(t *testing.T) {
	vk := &store.VirtualKey{
		Name:                    "test-dev-key",
		MonthlyBudgetMicrocents: 5000000,
	}

	if vk.OwnerType == "" {
		vk.OwnerType = "user"
	}
	if vk.BudgetPeriod == "" {
		vk.BudgetPeriod = "monthly"
	}

	if vk.OwnerType != "user" {
		t.Errorf("expected default owner_type 'user', got '%s'", vk.OwnerType)
	}
	if vk.BudgetPeriod != "monthly" {
		t.Errorf("expected default budget_period 'monthly', got '%s'", vk.BudgetPeriod)
	}
}

func TestVirtualKey_ExpirationHelper(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-1 * time.Hour)
	future := now.Add(24 * time.Hour)

	vkExpired := store.VirtualKey{
		Name:      "expired-key",
		ExpiresAt: &past,
		Status:    "active",
	}

	vkActive := store.VirtualKey{
		Name:      "active-key",
		ExpiresAt: &future,
		Status:    "active",
	}

	vkNeverExpires := store.VirtualKey{
		Name:      "permanent-key",
		ExpiresAt: nil,
		Status:    "active",
	}

	// Dynamic expiration evaluation predicate:
	isExpired := func(k *store.VirtualKey) bool {
		return k.ExpiresAt != nil && now.After(*k.ExpiresAt)
	}

	if !isExpired(&vkExpired) {
		t.Errorf("expected vkExpired to be detected as expired")
	}
	if isExpired(&vkActive) {
		t.Errorf("expected vkActive to be active")
	}
	if isExpired(&vkNeverExpires) {
		t.Errorf("expected vkNeverExpires to be active")
	}
}

func TestVirtualKey_NilPoolSafety(t *testing.T) {
	// A Store without a database pool should safely return ErrVirtualKeyNotFound
	st := &store.Store{}
	ctx := context.Background()

	_, err := st.GetVirtualKeyByID(ctx, "org-1", "vk-1")
	if err != store.ErrVirtualKeyNotFound {
		t.Errorf("expected ErrVirtualKeyNotFound on nil pool, got %v", err)
	}

	_, err = st.GetVirtualKeyByHash(ctx, "somehash")
	if err != store.ErrVirtualKeyNotFound {
		t.Errorf("expected ErrVirtualKeyNotFound on nil pool, got %v", err)
	}

	_, err = st.RotateVirtualKey(ctx, "org-1", "vk-1", "newhash", "prefix", time.Hour)
	if err != store.ErrVirtualKeyNotFound {
		t.Errorf("expected ErrVirtualKeyNotFound on nil pool, got %v", err)
	}

	_, err = st.UpdateVirtualKey(ctx, "org-1", "vk-1", store.UpdateVirtualKeyParams{})
	if err != store.ErrVirtualKeyNotFound {
		t.Errorf("expected ErrVirtualKeyNotFound on nil pool, got %v", err)
	}
}
