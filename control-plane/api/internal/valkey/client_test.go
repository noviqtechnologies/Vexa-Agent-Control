package valkey

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestInMemoryClient_BasicOperations(t *testing.T) {
	client := NewInMemoryClient()
	ctx := context.Background()

	// 1. Get non-existent
	_, err := client.Get(ctx, "non_existent")
	if !errors.Is(err, ErrNil) {
		t.Fatalf("expected ErrNil, got %v", err)
	}

	// 2. Set and Get
	err = client.Set(ctx, "key1", "val1", 10*time.Second)
	if err != nil {
		t.Fatalf("unexpected set error: %v", err)
	}

	val, err := client.Get(ctx, "key1")
	if err != nil || val != "val1" {
		t.Fatalf("expected val1, got %v (err: %v)", val, err)
	}

	// 3. IncrBy
	incrVal, err := client.IncrBy(ctx, "counter1", 50)
	if err != nil || incrVal != 50 {
		t.Fatalf("expected 50, got %d (err: %v)", incrVal, err)
	}

	// 4. Reserve Spend within budget
	spent, err := client.ReserveSpend(ctx, "vk-123", 1000, 5000)
	if err != nil || spent != 1000 {
		t.Fatalf("expected 1000, got %d (err: %v)", spent, err)
	}

	// 5. Reserve Spend exceeding budget
	_, err = client.ReserveSpend(ctx, "vk-123", 5000, 5000)
	if !errors.Is(err, ErrBudgetCapExceeded) {
		t.Fatalf("expected ErrBudgetCapExceeded, got %v", err)
	}
}
