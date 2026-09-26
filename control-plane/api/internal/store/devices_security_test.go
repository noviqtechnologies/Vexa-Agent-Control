package store_test

import (
	"context"
	"testing"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

func TestResolveDevicePrincipal_RejectsArbitraryUUIDAndFuzzy(t *testing.T) {
	// A nil pool returns false immediately
	s := store.New(nil)
	ctx := context.Background()

	// 1. Arbitrary 36-character UUID must not match any fallback
	fakeUUID := "11111111-2222-3333-4444-555555555555"
	if p, ok := s.ResolveDevicePrincipal(ctx, fakeUUID); ok || p != nil {
		t.Fatalf("expected ResolveDevicePrincipal with arbitrary UUID to return (nil, false), got (%v, %v)", p, ok)
	}

	// 2. Empty string must return false immediately
	if p, ok := s.ResolveDevicePrincipal(ctx, ""); ok || p != nil {
		t.Fatalf("expected empty token to return (nil, false), got (%v, %v)", p, ok)
	}

	// 3. Partial or fuzzy token string must not match
	fuzzyToken := "MacBook-Pro-Workstation"
	if p, ok := s.ResolveDevicePrincipal(ctx, fuzzyToken); ok || p != nil {
		t.Fatalf("expected fuzzy name token to return (nil, false), got (%v, %v)", p, ok)
	}
}
