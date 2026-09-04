package spend

import (
	"context"
	"testing"
	"time"
)

func TestStore_InputValidations(t *testing.T) {
	s := NewStore(nil)
	ctx := context.Background()

	// 1. Authorize with nil pool
	authResp, err := s.Authorize(ctx, "org-1", &AuthorizeRequest{})
	if err == nil {
		t.Fatalf("expected error for uninitialized pool, got response: %v", authResp)
	}

	// 2. Settle with nil pool
	settleResp, err := s.Settle(ctx, "org-1", "res-1", &SettleRequest{})
	if err == nil {
		t.Fatalf("expected error for uninitialized pool, got response: %v", settleResp)
	}

	// 3. Release with nil pool
	releaseResp, err := s.Release(ctx, "org-1", "res-1", &ReleaseRequest{})
	if err == nil {
		t.Fatalf("expected error for uninitialized pool, got response: %v", releaseResp)
	}

	// 4. Missing required org ID
	_, err = s.authorizeTx(ctx, "", &AuthorizeRequest{})
	if err == nil {
		t.Fatalf("expected error for empty orgID")
	}

	// 5. Price book lookup on nil pool
	item, err := s.GetPriceBookItem(ctx, "v1", "openai", "gpt-4o")
	if err == nil {
		t.Fatalf("expected error for nil pool on GetPriceBookItem, got: %v", item)
	}

	// 6. Active version ID defaults to price-book-v1 on nil pool
	verID := s.GetActivePriceBookVersionID(ctx)
	if verID != "price-book-v1" {
		t.Fatalf("expected default price-book-v1, got: %s", verID)
	}
}

func TestStore_WindowBoundsCalculation(t *testing.T) {
	refTime := time.Date(2026, 9, 3, 14, 30, 0, 0, time.UTC)

	// Daily window
	startD, endD := GetWindowBoundsUTC(PeriodDaily, refTime)
	expectedStartD := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	if !startD.Equal(expectedStartD) {
		t.Fatalf("daily start mismatch: got %v, want %v", startD, expectedStartD)
	}
	if endD.Before(startD) {
		t.Fatalf("daily end cannot be before start")
	}

	// Monthly window
	startM, endM := GetWindowBoundsUTC(PeriodMonthly, refTime)
	expectedStartM := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if !startM.Equal(expectedStartM) {
		t.Fatalf("monthly start mismatch: got %v, want %v", startM, expectedStartM)
	}
	if endM.Before(startM) {
		t.Fatalf("monthly end cannot be before start")
	}
}

func TestStore_ComputePayloadHash(t *testing.T) {
	req1 := &AuthorizeRequest{RequestID: "req-1", ProjectID: "proj-a"}
	req2 := &AuthorizeRequest{RequestID: "req-1", ProjectID: "proj-a"}
	req3 := &AuthorizeRequest{RequestID: "req-2", ProjectID: "proj-a"}

	h1 := ComputePayloadHash(req1)
	h2 := ComputePayloadHash(req2)
	h3 := ComputePayloadHash(req3)

	if h1 != h2 {
		t.Fatalf("expected identical hashes for identical payloads")
	}
	if h1 == h3 {
		t.Fatalf("expected distinct hashes for different payloads")
	}
}
