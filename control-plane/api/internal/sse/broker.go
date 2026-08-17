package sse

import (
	"encoding/json"
	"fmt"
	"sync"
)

// Broker fans out alert and policy events to connected SSE clients per tenant.
// Thread-safe; designed for concurrent subscribe/unsubscribe/publish across multiple tenants.
type Broker struct {
	mu            sync.RWMutex
	tenantClients map[string]map[uint64]chan []byte
	globalClients map[uint64]chan []byte
	nextID        uint64
}

func NewBroker() *Broker {
	return &Broker{
		tenantClients: make(map[string]map[uint64]chan []byte),
		globalClients: make(map[uint64]chan []byte),
	}
}

// Subscribe returns a channel that receives SSE-formatted payloads for the global stream.
// Maintained for backward compatibility.
func (b *Broker) Subscribe() (<-chan []byte, func()) {
	b.mu.Lock()
	id := b.nextID
	b.nextID++
	ch := make(chan []byte, 64)
	b.globalClients[id] = ch
	b.mu.Unlock()

	cleanup := func() {
		b.mu.Lock()
		delete(b.globalClients, id)
		close(ch)
		b.mu.Unlock()
	}
	return ch, cleanup
}

// SubscribeTenant returns a channel that receives SSE-formatted payloads for a specific tenant.
func (b *Broker) SubscribeTenant(tenantID string) (<-chan []byte, func()) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	b.mu.Lock()
	id := b.nextID
	b.nextID++
	ch := make(chan []byte, 64)
	if b.tenantClients[tenantID] == nil {
		b.tenantClients[tenantID] = make(map[uint64]chan []byte)
	}
	b.tenantClients[tenantID][id] = ch
	b.mu.Unlock()

	cleanup := func() {
		b.mu.Lock()
		if m, ok := b.tenantClients[tenantID]; ok {
			delete(m, id)
			if len(m) == 0 {
				delete(b.tenantClients, tenantID)
			}
		}
		close(ch)
		b.mu.Unlock()
	}
	return ch, cleanup
}

// Publish serializes the event and sends it to all globally connected clients.
func (b *Broker) Publish(event any) {
	payload := formatPayload(event)
	if payload == nil {
		return
	}

	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.globalClients {
		select {
		case ch <- payload:
		default:
		}
	}
}

// PublishTenant serializes the event and sends it to subscribers of that specific tenant.
func (b *Broker) PublishTenant(tenantID string, event any) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	payload := formatPayload(event)
	if payload == nil {
		return
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	// Deliver to tenant subscribers
	if clients, ok := b.tenantClients[tenantID]; ok {
		for _, ch := range clients {
			select {
			case ch <- payload:
			default:
			}
		}
	}

	// Also deliver to global subscribers
	for _, ch := range b.globalClients {
		select {
		case ch <- payload:
		default:
		}
	}
}

func formatPayload(event any) []byte {
	switch v := event.(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	default:
		data, err := json.Marshal(event)
		if err != nil {
			return nil
		}
		return []byte(fmt.Sprintf("data: %s\n\n", data))
	}
}

func (b *Broker) ClientCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	count := len(b.globalClients)
	for _, m := range b.tenantClients {
		count += len(m)
	}
	return count
}

func (b *Broker) TenantClientCount(tenantID string) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if m, ok := b.tenantClients[tenantID]; ok {
		return len(m)
	}
	return 0
}
