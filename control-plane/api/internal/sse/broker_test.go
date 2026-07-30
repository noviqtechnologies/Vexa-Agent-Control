package sse

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBroker_SubscribeAndPublish(t *testing.T) {
	b := NewBroker()
	ch, cleanup := b.Subscribe()
	defer cleanup()

	b.Publish(map[string]string{"msg": "hello"})

	select {
	case data := <-ch:
		if !strings.Contains(string(data), `"msg":"hello"`) {
			t.Errorf("unexpected payload: %s", data)
		}
		if !strings.HasPrefix(string(data), "data: ") {
			t.Error("payload should be SSE-formatted with 'data: ' prefix")
		}
		if !strings.HasSuffix(string(data), "\n\n") {
			t.Error("payload should end with double newline")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for message")
	}
}

func TestBroker_FanOutToMultipleClients(t *testing.T) {
	b := NewBroker()

	const n = 5
	channels := make([]<-chan []byte, n)
	cleanups := make([]func(), n)
	for i := 0; i < n; i++ {
		channels[i], cleanups[i] = b.Subscribe()
		defer cleanups[i]()
	}

	if b.ClientCount() != n {
		t.Fatalf("ClientCount() = %d, want %d", b.ClientCount(), n)
	}

	b.Publish("broadcast")

	for i := 0; i < n; i++ {
		select {
		case data := <-channels[i]:
			if !strings.Contains(string(data), "broadcast") {
				t.Errorf("client %d got unexpected data: %s", i, data)
			}
		case <-time.After(time.Second):
			t.Fatalf("client %d timed out", i)
		}
	}
}

func TestBroker_Unsubscribe(t *testing.T) {
	b := NewBroker()
	_, cleanup := b.Subscribe()

	if b.ClientCount() != 1 {
		t.Fatalf("ClientCount() = %d, want 1", b.ClientCount())
	}

	cleanup()

	if b.ClientCount() != 0 {
		t.Fatalf("ClientCount() after cleanup = %d, want 0", b.ClientCount())
	}
}

func TestBroker_SlowClientDropsMessages(t *testing.T) {
	b := NewBroker()
	ch, cleanup := b.Subscribe()
	defer cleanup()

	// Fill the channel buffer (capacity 64) and then some.
	for i := 0; i < 80; i++ {
		b.Publish(i)
	}

	// We should get exactly 64 messages (buffer capacity), rest dropped.
	received := 0
	for {
		select {
		case <-ch:
			received++
		default:
			goto done
		}
	}
done:
	if received != 64 {
		t.Errorf("received %d messages, want 64 (buffer capacity)", received)
	}
}

func TestBroker_ConcurrentSafety(t *testing.T) {
	b := NewBroker()
	var wg sync.WaitGroup

	// Concurrent subscribers.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, cleanup := b.Subscribe()
			defer cleanup()
			// Drain one message if available.
			select {
			case <-ch:
			case <-time.After(50 * time.Millisecond):
			}
		}()
	}

	// Concurrent publishers.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			b.Publish(n)
		}(i)
	}

	wg.Wait()
}

func TestBroker_PublishNoSubscribers(t *testing.T) {
	b := NewBroker()
	// Should not panic.
	b.Publish("nobody listening")
}
