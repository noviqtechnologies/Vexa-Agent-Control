package scheduler

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type mockJob struct {
	name     string
	interval time.Duration
	runCount atomic.Int32
	failNext bool
}

func (m *mockJob) Name() string          { return m.name }
func (m *mockJob) Interval() time.Duration { return m.interval }
func (m *mockJob) Run(ctx context.Context) error {
	m.runCount.Add(1)
	if m.failNext {
		return errors.New("simulated failure")
	}
	return nil
}

func TestScheduler_Lifecycle(t *testing.T) {
	j1 := &mockJob{name: "test_job_1", interval: 10 * time.Millisecond}
	j2 := &mockJob{name: "test_job_2", interval: 20 * time.Millisecond, failNext: true}

	sched := New(j1, j2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sched.Start(ctx)

	// Allow several ticks
	time.Sleep(50 * time.Millisecond)

	statuses := sched.Statuses()
	if len(statuses) != 2 {
		t.Fatalf("expected 2 job statuses, got %d", len(statuses))
	}

	if j1.runCount.Load() == 0 {
		t.Fatalf("expected job 1 to run at least once")
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer stopCancel()

	if err := sched.Stop(stopCtx); err != nil {
		t.Fatalf("failed to stop scheduler: %v", err)
	}
}
