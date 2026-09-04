package spend

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// SpendEventWriter manages asynchronous, bounded, batched writes of durable spend events to PostgreSQL.
// Synchronous reservation state changes occur in the transaction, while durable append-only
// audit rows and downstream exports are safely batched without stalling client LLM calls.
type SpendEventWriter struct {
	store       *Store
	queue       chan SpendEvent
	interval    time.Duration
	batchSize   int
	backpressureTimeout time.Duration
	stopCh      chan struct{}
	wg          sync.WaitGroup
	dropAlertMu sync.Mutex
	dropCount   uint64
}

// NewSpendEventWriter initializes a unified spend event writer.
func NewSpendEventWriter(s *Store, interval time.Duration, queueCapacity, batchSize int) *SpendEventWriter {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if queueCapacity <= 0 {
		queueCapacity = 10000
	}
	if batchSize <= 0 {
		batchSize = 256
	}
	return &SpendEventWriter{
		store:               s,
		queue:               make(chan SpendEvent, queueCapacity),
		interval:            interval,
		batchSize:           batchSize,
		backpressureTimeout: 2 * time.Second,
		stopCh:              make(chan struct{}),
	}
}

// Enqueue submits a spend event to the durable writer queue.
// If the buffer is full under backpressure, it waits up to backpressureTimeout before dropping and alerting.
func (w *SpendEventWriter) Enqueue(ctx context.Context, event SpendEvent) error {
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	if event.Currency == "" {
		event.Currency = CurrencyUSD
	}

	select {
	case w.queue <- event:
		return nil
	default:
	}

	// Channel full: try with bounded timeout
	select {
	case w.queue <- event:
		return nil
	case <-time.After(w.backpressureTimeout):
		w.dropAlertMu.Lock()
		w.dropCount++
		count := w.dropCount
		w.dropAlertMu.Unlock()
		log.Printf("[spend_writer_alert] CRITICAL: Spend event queue backpressure limit exceeded; dropped event_type=%s reservation_id=%s total_dropped=%d",
			event.EventType, event.ReservationID, count)
		return fmt.Errorf("spend event queue full: dropped event after %v backpressure timeout", w.backpressureTimeout)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// QueueDepth returns the current number of queued events waiting to be flushed.
func (w *SpendEventWriter) QueueDepth() int {
	return len(w.queue)
}

// Start launches the background batching goroutine.
func (w *SpendEventWriter) Start(ctx context.Context) {
	w.wg.Add(1)
	go w.run(ctx)
}

// Stop gracefully drains remaining queued events and shuts down the writer.
func (w *SpendEventWriter) Stop(ctx context.Context) error {
	close(w.stopCh)
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *SpendEventWriter) run(ctx context.Context) {
	defer w.wg.Done()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	batch := make([]SpendEvent, 0, w.batchSize)

	for {
		select {
		case <-w.stopCh:
			// Drain remaining events
			for {
				select {
				case e := <-w.queue:
					batch = append(batch, e)
					if len(batch) >= w.batchSize {
						w.flushBatch(context.Background(), batch)
						batch = batch[:0]
					}
				default:
					if len(batch) > 0 {
						w.flushBatch(context.Background(), batch)
					}
					return
				}
			}
		case <-ctx.Done():
			if len(batch) > 0 {
				w.flushBatch(context.Background(), batch)
			}
			return
		case e := <-w.queue:
			batch = append(batch, e)
			if len(batch) >= w.batchSize {
				w.flushBatch(ctx, batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				w.flushBatch(ctx, batch)
				batch = batch[:0]
			}
		}
	}
}

func (w *SpendEventWriter) flushBatch(ctx context.Context, batch []SpendEvent) {
	if len(batch) == 0 || w.store == nil || w.store.pool == nil {
		return
	}

	start := time.Now()

	// Write batch via pgx.Batch
	b := &pgx.Batch{}
	for _, e := range batch {
		usageJSON := e.UsageJSON
		if usageJSON == "" {
			usageJSON = "{}"
		}
		actor := e.Actor
		if actor == "" {
			actor = "gateway"
		}
		reason := e.ReasonCode
		if reason == "" {
			reason = "normal"
		}

		b.Queue(`
			INSERT INTO spend_events (
				organization_id, reservation_id, request_id, event_type,
				amount_microcents, currency, usage_json, provider_request_id,
				actor, reason_code, occurred_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11)
		`, e.OrganizationID, e.ReservationID, e.RequestID, e.EventType,
			e.AmountMicrocents, e.Currency, usageJSON, e.ProviderRequestID,
			actor, reason, e.OccurredAt)
	}

	br := w.store.pool.SendBatch(ctx, b)
	defer br.Close()

	var writeErr error
	for range batch {
		if _, err := br.Exec(); err != nil && writeErr == nil {
			writeErr = err
		}
	}

	if writeErr != nil {
		log.Printf("[spend_writer] error flushing %d spend events: %v", len(batch), writeErr)
	} else {
		log.Printf("[spend_writer] flushed %d spend events in %v", len(batch), time.Since(start))
	}
}
