package spend

import (
	"context"
	"log"
	"time"
)

// Sweeper runs in the background to automatically release expired spend reservations.
type Sweeper struct {
	store    *Store
	interval time.Duration
	stopCh   chan struct{}
}

func NewSweeper(s *Store, interval time.Duration) *Sweeper {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Sweeper{
		store:    s,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

func (sw *Sweeper) Start(ctx context.Context) {
	ticker := time.NewTicker(sw.interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-sw.stopCh:
				return
			case <-ticker.C:
				count, err := sw.store.SweepExpiredReservations(ctx)
				if err != nil {
					log.Printf("[spend_sweeper] error sweeping expired reservations: %v", err)
				} else if count > 0 {
					log.Printf("[spend_sweeper] released %d expired active spend reservations", count)
				}
			}
		}
	}()
}

func (sw *Sweeper) Stop() {
	close(sw.stopCh)
}

// SweepJob implements scheduler.Job for centralized background execution.
type SweepJob struct {
	store    *Store
	interval time.Duration
}

func NewSweepJob(s *Store, interval time.Duration) *SweepJob {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &SweepJob{store: s, interval: interval}
}

func (j *SweepJob) Name() string {
	return "spend_sweep_expired_reservations"
}

func (j *SweepJob) Interval() time.Duration {
	return j.interval
}

func (j *SweepJob) Run(ctx context.Context) error {
	count, err := j.store.SweepExpiredReservations(ctx)
	if err != nil {
		return err
	}
	if count > 0 {
		log.Printf("[spend_sweep_job] released %d expired active spend reservations", count)
	}
	return nil
}

