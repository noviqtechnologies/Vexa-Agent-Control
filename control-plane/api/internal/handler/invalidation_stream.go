package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type InvalidationEvent struct {
	Action   string `json:"action"` // e.g. "evict_key"
	KeyHash  string `json:"key_hash"`
	TenantID string `json:"tenant_id"`
}

type InvalidationBroadcaster struct {
	mu      sync.RWMutex
	clients map[chan InvalidationEvent]struct{}
}

func NewInvalidationBroadcaster() *InvalidationBroadcaster {
	return &InvalidationBroadcaster{
		clients: make(map[chan InvalidationEvent]struct{}),
	}
}

func (b *InvalidationBroadcaster) Subscribe() chan InvalidationEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan InvalidationEvent, 100)
	b.clients[ch] = struct{}{}
	return ch
}

func (b *InvalidationBroadcaster) Unsubscribe(ch chan InvalidationEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.clients, ch)
	close(ch)
}

func (b *InvalidationBroadcaster) Broadcast(event InvalidationEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.clients {
		select {
		case ch <- event:
		default:
			// Non-blocking write to avoid slow clients blocking the control plane
		}
	}
}

// ServeHTTP streams SSE invalidation events to connected edge proxies.
func (b *InvalidationBroadcaster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := b.Subscribe()
	defer b.Unsubscribe(ch)

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// Send initial connected comment
	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			bytes, err := json.Marshal(event)
			if err == nil {
				fmt.Fprintf(w, "data: %s\n\n", bytes)
				flusher.Flush()
			}
		case <-ticker.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}
