package model

import (
	"errors"
	"fmt"
	"time"
)

// AssignmentState defines the 9 formal desired-state assignment states (REQ-DSM-002).
type AssignmentState string

const (
	AssignmentStateDesired    AssignmentState = "desired"
	AssignmentStateEligible   AssignmentState = "eligible"
	AssignmentStateDelivered  AssignmentState = "delivered"
	AssignmentStateApplied    AssignmentState = "applied"
	AssignmentStateVerified   AssignmentState = "verified"
	AssignmentStateFailed     AssignmentState = "failed"
	AssignmentStateStale      AssignmentState = "stale"
	AssignmentStateRevoked    AssignmentState = "revoked"
	AssignmentStateRolledBack AssignmentState = "rolled_back"
)

// AssignmentKind defines what configuration/profile is being assigned.
type AssignmentKind string

const (
	AssignmentKindPolicy       AssignmentKind = "policy"
	AssignmentKindProviderKeys AssignmentKind = "provider_keys"
	AssignmentKindCursorMode   AssignmentKind = "cursor_mode"
	AssignmentKindLLMProfile   AssignmentKind = "llm_profile"
)

// StateTransition records an append-only state mutation for audit (REQ-DSM-001).
type StateTransition struct {
	FromState AssignmentState `json:"from_state"`
	ToState   AssignmentState `json:"to_state"`
	Reason    string          `json:"reason,omitempty"`
	Actor     string          `json:"actor,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
}

// Assignment represents a tenant-scoped desired-state assignment (REQ-DSM-001).
type Assignment struct {
	ID                       string            `json:"id"`
	OrganizationID           string            `json:"organization_id"`
	TargetType               string            `json:"target_type"` // "device", "user", "group"
	TargetID                 string            `json:"target_id"`
	Kind                     AssignmentKind    `json:"kind"`
	PayloadRef               string            `json:"payload_ref"` // SHA-256 hash or version snapshot
	State                    AssignmentState   `json:"state"`
	RollbackFromAssignmentID *string           `json:"rollback_from_assignment_id,omitempty"`
	StateHistory             []StateTransition `json:"state_history"`
	CreatedAt                time.Time         `json:"created_at"`
	UpdatedAt                time.Time         `json:"updated_at"`
}

// ValidateTransition enforces strict server-side state machine rules (REQ-DSM-002).
// E.g., 'applied' cannot follow 'failed' without returning through 'desired'.
func ValidateTransition(from, to AssignmentState) error {
	if from == to {
		return nil
	}

	validTransitions := map[AssignmentState][]AssignmentState{
		AssignmentStateDesired: {
			AssignmentStateEligible,
			AssignmentStateRevoked,
			AssignmentStateFailed,
		},
		AssignmentStateEligible: {
			AssignmentStateDelivered,
			AssignmentStateStale,
			AssignmentStateRevoked,
			AssignmentStateFailed,
		},
		AssignmentStateDelivered: {
			AssignmentStateApplied,
			AssignmentStateFailed,
			AssignmentStateStale,
			AssignmentStateRevoked,
		},
		AssignmentStateApplied: {
			AssignmentStateVerified,
			AssignmentStateFailed,
			AssignmentStateStale,
			AssignmentStateRevoked,
			AssignmentStateDesired, // On new configuration rollout
		},
		AssignmentStateVerified: {
			AssignmentStateStale,
			AssignmentStateRevoked,
			AssignmentStateDesired, // On new configuration rollout
			AssignmentStateFailed,
		},
		AssignmentStateFailed: {
			AssignmentStateRolledBack,
			AssignmentStateDesired, // Must return through desired before re-applying
			AssignmentStateRevoked,
		},
		AssignmentStateStale: {
			AssignmentStateDelivered,
			AssignmentStateApplied,
			AssignmentStateVerified,
			AssignmentStateRevoked,
			AssignmentStateDesired,
			AssignmentStateFailed,
		},
		AssignmentStateRevoked: {
			AssignmentStateDesired, // Re-instatement
		},
		AssignmentStateRolledBack: {
			AssignmentStateDesired, // New rollout
		},
	}

	allowed, ok := validTransitions[from]
	if !ok {
		return fmt.Errorf("unknown initial assignment state: %q", from)
	}

	for _, state := range allowed {
		if state == to {
			return nil
		}
	}

	return fmt.Errorf("illegal assignment state transition from %q to %q", from, to)
}

// AssignmentAckRequest is sent by endpoints to acknowledge local delivery and application.
type AssignmentAckRequest struct {
	AssignmentID string          `json:"assignment_id"`
	State        AssignmentState `json:"state"` // "delivered", "applied", "failed"
	PayloadHash  string          `json:"payload_hash"`
	ErrorMessage string          `json:"error_message,omitempty"`
}

// VerifyProbeSubmission is submitted by 'agentcontrol verify --hub' (REQ-VER-004).
type VerifyProbeSubmission struct {
	DeviceID      string                 `json:"device_id"`
	UserID        string                 `json:"user_id"`
	AssignmentID  string                 `json:"assignment_id"`
	ProbeType     string                 `json:"probe_type"` // e.g. "3_point_security_probe"
	Success       bool                   `json:"success"`
	FindingsCount int                    `json:"findings_count"`
	Details       map[string]interface{} `json:"details,omitempty"`
}

var (
	ErrAssignmentNotFound = errors.New("assignment not found")
	ErrInvalidState       = errors.New("invalid assignment state")
)
