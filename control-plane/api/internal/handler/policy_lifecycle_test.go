package handler

import (
	"testing"
)

func TestPolicyLifecycleTransitions(t *testing.T) {
	mgr := NewPolicyLifecycleManager()

	// 1. Create Draft
	rec, err := mgr.CreateDraft("pol-1", 1, "sha256:abc123hash", "user-lead-1")
	if err != nil {
		t.Fatalf("Failed to create draft: %v", err)
	}
	if rec.State != StateDraft {
		t.Errorf("Expected state DRAFT, got %s", rec.State)
	}

	// 2. Validate
	rec, err = mgr.Transition("pol-1", 1, StateValidated, "ci-validator", "Syntax and AST checks passed")
	if err != nil {
		t.Fatalf("Failed transition to VALIDATED: %v", err)
	}
	if rec.State != StateValidated {
		t.Errorf("Expected state VALIDATED, got %s", rec.State)
	}

	// 3. Simulate
	rec, err = mgr.Transition("pol-1", 1, StateSimulated, "sim-runner", "Simulated on 10,000 historical events, 0 false blocks")
	if err != nil {
		t.Fatalf("Failed transition to SIMULATED: %v", err)
	}
	if rec.State != StateSimulated {
		t.Errorf("Expected state SIMULATED, got %s", rec.State)
	}

	// 4. Approve
	rec, err = mgr.Transition("pol-1", 1, StateApproved, "ciso-approver", "Approved for staging")
	if err != nil {
		t.Fatalf("Failed transition to APPROVED: %v", err)
	}
	if rec.State != StateApproved || rec.ApproverID != "ciso-approver" {
		t.Errorf("Expected state APPROVED with approver, got %s, approver %s", rec.State, rec.ApproverID)
	}

	// 5. Stage
	rec, err = mgr.Transition("pol-1", 1, StateStaged, "release-eng", "Staged for Canary cohort")
	if err != nil {
		t.Fatalf("Failed transition to STAGED: %v", err)
	}

	// 6. Activate
	rec, err = mgr.Transition("pol-1", 1, StateActive, "release-eng", "Activated across fleet")
	if err != nil {
		t.Fatalf("Failed transition to ACTIVE: %v", err)
	}
	if rec.ActivatedAt == nil {
		t.Errorf("Expected ActivatedAt timestamp to be set")
	}

	// 7. Endpoint Acknowledgement
	mgr.RecordAcknowledgement("pol-1", 1, "device-mac-001")
	mgr.RecordAcknowledgement("pol-1", 1, "device-win-002")

	count, pct := mgr.GetConvergence("pol-1", 1, 2)
	if count != 2 || pct != 100.0 {
		t.Errorf("Expected 2 acks (100%%), got %d (%.1f%%)", count, pct)
	}

	// 8. Revoke
	rec, err = mgr.Transition("pol-1", 1, StateRevoked, "sec-incident-lead", "Emergency vulnerability mitigation")
	if err != nil {
		t.Fatalf("Failed transition to REVOKED: %v", err)
	}
	if rec.State != StateRevoked {
		t.Errorf("Expected state REVOKED, got %s", rec.State)
	}

	// 9. Verify Illegal Transition from Revoked fails
	_, err = mgr.Transition("pol-1", 1, StateDraft, "attacker", "reopen revoked policy")
	if err == nil {
		t.Errorf("Expected error on transition from REVOKED, but got nil")
	}
}
