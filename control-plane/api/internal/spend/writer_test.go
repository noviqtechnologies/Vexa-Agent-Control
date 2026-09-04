package spend

import (
	"context"
	"testing"
	"time"
)

func TestSpendEventWriter_EnqueueAndShutdown(t *testing.T) {
	// Writer with nil pool to test memory buffering, backpressure and graceful drain
	writer := NewSpendEventWriter(nil, 50*time.Millisecond, 5, 2)
	writer.backpressureTimeout = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	writer.Start(ctx)

	// Enqueue events within buffer
	for i := 0; i < 3; i++ {
		err := writer.Enqueue(ctx, SpendEvent{
			EventID:          "ev-test",
			OrganizationID:   "org-1",
			ReservationID:    "res-1",
			RequestID:        "req-1",
			EventType:        "SETTLED",
			AmountMicrocents: 5000,
		})
		if err != nil {
			t.Fatalf("unexpected enqueue error: %v", err)
		}
	}

	// Stop gracefully
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer stopCancel()

	if err := writer.Stop(stopCtx); err != nil {
		t.Fatalf("writer stop failed: %v", err)
	}
}

func TestSpendEventWriter_BackpressureDropAlert(t *testing.T) {
	// Capacity of 1 to easily trigger backpressure
	writer := NewSpendEventWriter(nil, 1*time.Hour, 1, 10)
	writer.backpressureTimeout = 10 * time.Millisecond

	ctx := context.Background()

	// Fill queue
	err := writer.Enqueue(ctx, SpendEvent{EventID: "ev-1"})
	if err != nil {
		t.Fatalf("first enqueue should succeed: %v", err)
	}

	// Second enqueue should timeout and drop
	err = writer.Enqueue(ctx, SpendEvent{EventID: "ev-2"})
	if err == nil {
		t.Fatalf("expected backpressure error, got nil")
	}

	if writer.dropCount != 1 {
		t.Fatalf("expected 1 dropped event, got %d", writer.dropCount)
	}
}
