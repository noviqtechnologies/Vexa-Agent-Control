package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

// AssignmentStaleSweepJob sweeps assignments in 'delivered' or 'applied' state whose owning device
// has not sent a heartbeat within the timeout window, transitioning them to 'stale' (REQ-DSM-008).
type AssignmentStaleSweepJob struct {
	store            *store.Store
	interval         time.Duration
	heartbeatTimeout time.Duration
}

// NewAssignmentStaleSweepJob constructs a periodic assignment sweep job.
func NewAssignmentStaleSweepJob(st *store.Store, interval, heartbeatTimeout time.Duration) *AssignmentStaleSweepJob {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if heartbeatTimeout <= 0 {
		heartbeatTimeout = 180 * time.Second
	}
	return &AssignmentStaleSweepJob{
		store:            st,
		interval:         interval,
		heartbeatTimeout: heartbeatTimeout,
	}
}

func (j *AssignmentStaleSweepJob) Name() string {
	return "assignment_stale_sweep"
}

func (j *AssignmentStaleSweepJob) Interval() time.Duration {
	return j.interval
}

func (j *AssignmentStaleSweepJob) Run(ctx context.Context) error {
	if j.store == nil {
		return nil
	}
	swept, err := j.store.SweepStaleAssignments(ctx, j.heartbeatTimeout)
	if err != nil {
		log.Printf("[assignment_stale_sweep] error sweeping stale assignments: %v", err)
		return err
	}
	if swept > 0 {
		log.Printf("[assignment_stale_sweep] transitioned %d timed-out assignments to 'stale'", swept)
	}
	return nil
}
