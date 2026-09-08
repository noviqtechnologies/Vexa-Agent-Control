package model_test

import (
	"testing"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

func TestAssignmentStateTransitions(t *testing.T) {
	// 1. Happy path: desired -> eligible -> delivered -> applied -> verified
	steps := []struct {
		from model.AssignmentState
		to   model.AssignmentState
	}{
		{model.AssignmentStateDesired, model.AssignmentStateEligible},
		{model.AssignmentStateEligible, model.AssignmentStateDelivered},
		{model.AssignmentStateDelivered, model.AssignmentStateApplied},
		{model.AssignmentStateApplied, model.AssignmentStateVerified},
	}
	for _, step := range steps {
		if err := model.ValidateTransition(step.from, step.to); err != nil {
			t.Errorf("expected transition %s -> %s to be valid, got: %v", step.from, step.to, err)
		}
	}

	// 2. Failure & Rollback path: applied -> failed -> rolled_back
	if err := model.ValidateTransition(model.AssignmentStateApplied, model.AssignmentStateFailed); err != nil {
		t.Errorf("expected applied -> failed to be valid, got: %v", err)
	}
	if err := model.ValidateTransition(model.AssignmentStateFailed, model.AssignmentStateRolledBack); err != nil {
		t.Errorf("expected failed -> rolled_back to be valid, got: %v", err)
	}

	// 3. Stale detection path: applied -> stale -> applied
	if err := model.ValidateTransition(model.AssignmentStateApplied, model.AssignmentStateStale); err != nil {
		t.Errorf("expected applied -> stale to be valid, got: %v", err)
	}
	if err := model.ValidateTransition(model.AssignmentStateStale, model.AssignmentStateApplied); err != nil {
		t.Errorf("expected stale -> applied to be valid, got: %v", err)
	}

	// 4. Illegal transitions per REQ-DSM-002:
	illegal := []struct {
		from model.AssignmentState
		to   model.AssignmentState
	}{
		{model.AssignmentStateFailed, model.AssignmentStateApplied},   // Cannot jump from failed to applied
		{model.AssignmentStateFailed, model.AssignmentStateVerified},  // Cannot jump from failed to verified
		{model.AssignmentStateDesired, model.AssignmentStateVerified}, // Cannot jump from desired directly to verified
		{model.AssignmentStateDesired, model.AssignmentStateApplied},  // Must go through eligible/delivered
		{model.AssignmentStateRevoked, model.AssignmentStateApplied},  // Must return through desired
	}

	for _, step := range illegal {
		if err := model.ValidateTransition(step.from, step.to); err == nil {
			t.Errorf("expected transition %s -> %s to FAIL, but it was allowed", step.from, step.to)
		}
	}
}
