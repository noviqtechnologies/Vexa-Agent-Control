package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// PolicyLifecycleState represents the formal stage of a policy bundle (PRD FR-009).
type PolicyLifecycleState string

const (
	StateDraft        PolicyLifecycleState = "DRAFT"
	StateValidated    PolicyLifecycleState = "VALIDATED"
	StateSimulated    PolicyLifecycleState = "SIMULATED"
	StateApproved     PolicyLifecycleState = "APPROVED"
	StateStaged       PolicyLifecycleState = "STAGED"
	StateActive       PolicyLifecycleState = "ACTIVE"
	StateAcknowledged PolicyLifecycleState = "ACKNOWLEDGED"
	StateRevoked      PolicyLifecycleState = "REVOKED"
	StateSuperseded   PolicyLifecycleState = "SUPERSEDED"
)

// PolicyLifecycleRecord tracks the full governance history of a policy revision.
type PolicyLifecycleRecord struct {
	PolicyID          string               `json:"policy_id"`
	Revision          uint64               `json:"revision"`
	State             PolicyLifecycleState `json:"state"`
	ContentHash       string               `json:"content_hash"`
	AuthorID          string               `json:"author_id"`
	ApproverID        string               `json:"approver_id,omitempty"`
	RolloutCohort     string               `json:"rollout_cohort,omitempty"`
	TargetScope       string               `json:"target_scope,omitempty"`
	CreatedAt         time.Time            `json:"created_at"`
	UpdatedAt         time.Time            `json:"updated_at"`
	ApprovedAt        *time.Time           `json:"approved_at,omitempty"`
	ActivatedAt       *time.Time           `json:"activated_at,omitempty"`
	TransitionHistory []StateTransition    `json:"transition_history"`
}

// StateTransition records an individual lifecycle state change.
type StateTransition struct {
	FromState PolicyLifecycleState `json:"from_state"`
	ToState   PolicyLifecycleState `json:"to_state"`
	ActorID   string               `json:"actor_id"`
	Reason    string               `json:"reason"`
	Timestamp time.Time            `json:"timestamp"`
}

// PolicyLifecycleManager handles policy lifecycle state transitions and convergence tracking.
type PolicyLifecycleManager struct {
	mu      sync.RWMutex
	records map[string]*PolicyLifecycleRecord // key: policy_id:revision
	// Convergence tracking: policy_id:revision -> device_id -> acknowledged_at
	acks map[string]map[string]time.Time
}

// NewPolicyLifecycleManager creates a new thread-safe lifecycle manager.
func NewPolicyLifecycleManager() *PolicyLifecycleManager {
	return &PolicyLifecycleManager{
		records: make(map[string]*PolicyLifecycleRecord),
		acks:    make(map[string]map[string]time.Time),
	}
}

// AllowedTransitions defines valid state progression rules.
var allowedTransitions = map[PolicyLifecycleState][]PolicyLifecycleState{
	StateDraft:        {StateValidated, StateRevoked},
	StateValidated:    {StateSimulated, StateDraft, StateRevoked},
	StateSimulated:    {StateApproved, StateDraft, StateRevoked},
	StateApproved:     {StateStaged, StateRevoked},
	StateStaged:       {StateActive, StateApproved, StateRevoked},
	StateActive:       {StateAcknowledged, StateSuperseded, StateRevoked},
	StateAcknowledged: {StateSuperseded, StateRevoked},
	StateRevoked:      {},
	StateSuperseded:   {},
}

// CreateDraft initializes a new policy draft.
func (m *PolicyLifecycleManager) CreateDraft(policyID string, revision uint64, contentHash, authorID string) (*PolicyLifecycleRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s:%d", policyID, revision)
	if _, exists := m.records[key]; exists {
		return nil, fmt.Errorf("policy revision %s already exists", key)
	}

	now := time.Now().UTC()
	rec := &PolicyLifecycleRecord{
		PolicyID:    policyID,
		Revision:    revision,
		State:       StateDraft,
		ContentHash: contentHash,
		AuthorID:    authorID,
		CreatedAt:   now,
		UpdatedAt:   now,
		TransitionHistory: []StateTransition{
			{
				FromState: "",
				ToState:   StateDraft,
				ActorID:   authorID,
				Reason:    "Initial draft creation",
				Timestamp: now,
			},
		},
	}
	m.records[key] = rec
	return rec, nil
}

// Transition advances a policy record to a new state if allowed.
func (m *PolicyLifecycleManager) Transition(policyID string, revision uint64, toState PolicyLifecycleState, actorID, reason string) (*PolicyLifecycleRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s:%d", policyID, revision)
	rec, exists := m.records[key]
	if !exists {
		return nil, fmt.Errorf("policy record %s not found", key)
	}

	// Validate allowed transition
	validNext := allowedTransitions[rec.State]
	allowed := false
	for _, s := range validNext {
		if s == toState {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("illegal state transition from %s to %s", rec.State, toState)
	}

	now := time.Now().UTC()
	rec.TransitionHistory = append(rec.TransitionHistory, StateTransition{
		FromState: rec.State,
		ToState:   toState,
		ActorID:   actorID,
		Reason:    reason,
		Timestamp: now,
	})
	rec.State = toState
	rec.UpdatedAt = now

	if toState == StateApproved {
		rec.ApproverID = actorID
		rec.ApprovedAt = &now
	}
	if toState == StateActive {
		rec.ActivatedAt = &now
	}

	return rec, nil
}

// RecordAcknowledgement registers that an endpoint has verified and applied a policy.
func (m *PolicyLifecycleManager) RecordAcknowledgement(policyID string, revision uint64, deviceID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s:%d", policyID, revision)
	if _, ok := m.acks[key]; !ok {
		m.acks[key] = make(map[string]time.Time)
	}
	m.acks[key][deviceID] = time.Now().UTC()

	// If record exists and is in ACTIVE state, transition to ACKNOWLEDGED
	if rec, ok := m.records[key]; ok && rec.State == StateActive {
		rec.State = StateAcknowledged
		rec.UpdatedAt = time.Now().UTC()
	}
}

// GetConvergence returns fleet acknowledgement statistics for a policy revision.
func (m *PolicyLifecycleManager) GetConvergence(policyID string, revision uint64, totalTargetEndpoints int) (acknowledgedCount int, percent float64) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := fmt.Sprintf("%s:%d", policyID, revision)
	devs := m.acks[key]
	acknowledgedCount = len(devs)
	if totalTargetEndpoints > 0 {
		percent = (float64(acknowledgedCount) / float64(totalTargetEndpoints)) * 100.0
	}
	return acknowledgedCount, percent
}

// PolicyLifecycleHandler handles HTTP requests for policy lifecycle management.
type PolicyLifecycleHandler struct {
	manager *PolicyLifecycleManager
}

// NewPolicyLifecycleHandler creates a new PolicyLifecycleHandler.
func NewPolicyLifecycleHandler(mgr *PolicyLifecycleManager) *PolicyLifecycleHandler {
	return &PolicyLifecycleHandler{manager: mgr}
}

// HandleGetLifecycle returns the lifecycle record for a policy revision.
func (h *PolicyLifecycleHandler) HandleGetLifecycle(w http.ResponseWriter, r *http.Request) {
	// Path expected: /api/v2/policy/lifecycle/{policy_id}/{revision}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 {
		http.Error(w, `{"error":"invalid_path"}`, http.StatusBadRequest)
		return
	}
	policyID := parts[3]
	var revision uint64
	_, _ = fmt.Sscanf(parts[4], "%d", &revision)

	key := fmt.Sprintf("%s:%d", policyID, revision)
	h.manager.mu.RLock()
	rec, exists := h.manager.records[key]
	h.manager.mu.RUnlock()

	if !exists {
		http.Error(w, `{"error":"policy_not_found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rec)
}
