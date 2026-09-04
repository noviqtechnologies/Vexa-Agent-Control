package scheduler

import (
	"context"
	"log"
	"sync"
	"time"
)

// Job defines the standard contract for named, intervaled background tasks in the control plane.
type Job interface {
	Name() string
	Interval() time.Duration
	Run(ctx context.Context) error
}

// JobStatus provides introspection for background job execution and health monitoring.
type JobStatus struct {
	Name         string        `json:"name"`
	Interval     time.Duration `json:"interval"`
	LastRun      time.Time     `json:"last_run"`
	LastDuration time.Duration `json:"last_duration"`
	LastSuccess  bool          `json:"last_success"`
	LastError    string        `json:"last_error,omitempty"`
	RunCount     uint64        `json:"run_count"`
}

// Scheduler centrally owns, logs, and coordinates background maintenance jobs.
type Scheduler struct {
	jobs     []Job
	statuses map[string]*JobStatus
	mu       sync.RWMutex
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// New creates a new Scheduler with the given initial jobs.
func New(jobs ...Job) *Scheduler {
	s := &Scheduler{
		jobs:     make([]Job, 0, len(jobs)),
		statuses: make(map[string]*JobStatus),
		stopCh:   make(chan struct{}),
	}
	s.Register(jobs...)
	return s
}

// Register appends one or more jobs to the scheduler.
func (s *Scheduler) Register(jobs ...Job) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, j := range jobs {
		s.jobs = append(s.jobs, j)
		s.statuses[j.Name()] = &JobStatus{
			Name:     j.Name(),
			Interval: j.Interval(),
		}
	}
}

// Start launches all registered background jobs.
func (s *Scheduler) Start(ctx context.Context) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, j := range s.jobs {
		s.wg.Add(1)
		go s.runJob(ctx, j)
	}
	log.Printf("[scheduler] started %d background daemon jobs", len(s.jobs))
}

// Stop gracefully signals all running jobs to stop and waits for their current run to finish.
func (s *Scheduler) Stop(ctx context.Context) error {
	close(s.stopCh)
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("[scheduler] all background daemon jobs gracefully stopped")
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Statuses returns snapshot copies of all registered job execution states.
func (s *Scheduler) Statuses() []JobStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]JobStatus, 0, len(s.statuses))
	for _, st := range s.statuses {
		res = append(res, *st)
	}
	return res
}

func (s *Scheduler) runJob(ctx context.Context, j Job) {
	defer s.wg.Done()

	interval := j.Interval()
	if interval <= 0 {
		interval = 1 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			start := time.Now()
			err := j.Run(ctx)
			duration := time.Since(start)

			s.mu.Lock()
			if st, ok := s.statuses[j.Name()]; ok {
				st.LastRun = start
				st.LastDuration = duration
				st.RunCount++
				if err != nil {
					st.LastSuccess = false
					st.LastError = err.Error()
				} else {
					st.LastSuccess = true
					st.LastError = ""
				}
			}
			s.mu.Unlock()

			if err != nil {
				log.Printf("[scheduler] job=%s duration=%s err=%v", j.Name(), duration, err)
			} else {
				log.Printf("[scheduler] job=%s duration=%s status=ok", j.Name(), duration)
			}
		}
	}
}
