package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

// EnsureAssignmentsSchema ensures assignments table exists.
func (s *Store) EnsureAssignmentsSchema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	q := `
		CREATE TABLE IF NOT EXISTS assignments (
			id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id             UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			target_type                 TEXT NOT NULL,
			target_id                   TEXT NOT NULL,
			kind                        TEXT NOT NULL,
			payload_ref                 TEXT NOT NULL,
			state                       VARCHAR(32) NOT NULL DEFAULT 'desired',
			rollback_from_assignment_id UUID REFERENCES assignments(id) ON DELETE SET NULL,
			state_history               JSONB NOT NULL DEFAULT '[]'::jsonb,
			created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT uq_assignments_org_target_kind UNIQUE (organization_id, target_type, target_id, kind),
			CONSTRAINT chk_assignment_state CHECK (state IN (
				'desired', 'eligible', 'delivered', 'applied', 'verified', 'failed', 'stale', 'revoked', 'rolled_back'
			))
		);
		CREATE INDEX IF NOT EXISTS idx_assignments_org_target ON assignments(organization_id, target_type, target_id);
		CREATE INDEX IF NOT EXISTS idx_assignments_state ON assignments(state);
		CREATE INDEX IF NOT EXISTS idx_assignments_updated ON assignments(updated_at DESC);
	`
	_, err := s.pool.Exec(ctx, q)
	return err
}

// CreateOrUpdateAssignment creates a new assignment or updates desired payload for a target.
func (s *Store) CreateOrUpdateAssignment(ctx context.Context, asgn *model.Assignment) error {
	if s.pool == nil {
		return errors.New("database pool uninitialized")
	}
	if asgn.OrganizationID == "" {
		asgn.OrganizationID = DefaultOrgID
	}
	if asgn.State == "" {
		asgn.State = model.AssignmentStateDesired
	}

	initialHistory := []model.StateTransition{
		{
			FromState: "",
			ToState:   asgn.State,
			Reason:    "Initial assignment creation",
			Actor:     "admin",
			Timestamp: time.Now().UTC(),
		},
	}
	histJSON, err := json.Marshal(initialHistory)
	if err != nil {
		return fmt.Errorf("marshal state history: %w", err)
	}

	query := `
		INSERT INTO assignments (
			organization_id, target_type, target_id, kind, payload_ref, state, state_history, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())
		ON CONFLICT (organization_id, target_type, target_id, kind)
		DO UPDATE SET
			payload_ref = EXCLUDED.payload_ref,
			state = 'desired',
			state_history = assignments.state_history || jsonb_build_array(jsonb_build_object(
				'from_state', assignments.state,
				'to_state', 'desired',
				'reason', 'Assignment payload updated',
				'actor', 'admin',
				'timestamp', now()
			)),
			updated_at = now()
		RETURNING id, state, created_at, updated_at
	`
	return s.pool.QueryRow(ctx, query,
		asgn.OrganizationID,
		asgn.TargetType,
		asgn.TargetID,
		string(asgn.Kind),
		asgn.PayloadRef,
		string(asgn.State),
		histJSON,
	).Scan(&asgn.ID, &asgn.State, &asgn.CreatedAt, &asgn.UpdatedAt)
}

// GetAssignment returns a specific assignment by ID.
func (s *Store) GetAssignment(ctx context.Context, organizationID, assignmentID string) (*model.Assignment, error) {
	if s.pool == nil {
		return nil, errors.New("database pool uninitialized")
	}

	query := `
		SELECT id, organization_id, target_type, target_id, kind, payload_ref, state, rollback_from_assignment_id, state_history, created_at, updated_at
		FROM assignments
		WHERE organization_id = $1 AND id = $2
	`
	row := s.pool.QueryRow(ctx, query, organizationID, assignmentID)

	var asgn model.Assignment
	var kindStr, stateStr string
	var rollbackID *string
	var histRaw []byte

	err := row.Scan(
		&asgn.ID,
		&asgn.OrganizationID,
		&asgn.TargetType,
		&asgn.TargetID,
		&kindStr,
		&asgn.PayloadRef,
		&stateStr,
		&rollbackID,
		&histRaw,
		&asgn.CreatedAt,
		&asgn.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, model.ErrAssignmentNotFound
		}
		return nil, err
	}

	asgn.Kind = model.AssignmentKind(kindStr)
	asgn.State = model.AssignmentState(stateStr)
	asgn.RollbackFromAssignmentID = rollbackID
	if len(histRaw) > 0 {
		_ = json.Unmarshal(histRaw, &asgn.StateHistory)
	}

	return &asgn, nil
}

// GetActiveAssignmentForTarget retrieves an assignment for a specific target and kind.
func (s *Store) GetActiveAssignmentForTarget(ctx context.Context, organizationID, targetType, targetID string, kind model.AssignmentKind) (*model.Assignment, error) {
	if s.pool == nil {
		return nil, errors.New("database pool uninitialized")
	}

	query := `
		SELECT id, organization_id, target_type, target_id, kind, payload_ref, state, rollback_from_assignment_id, state_history, created_at, updated_at
		FROM assignments
		WHERE organization_id = $1 AND target_type = $2 AND target_id = $3 AND kind = $4
	`
	row := s.pool.QueryRow(ctx, query, organizationID, targetType, targetID, string(kind))

	var asgn model.Assignment
	var kindStr, stateStr string
	var rollbackID *string
	var histRaw []byte

	err := row.Scan(
		&asgn.ID,
		&asgn.OrganizationID,
		&asgn.TargetType,
		&asgn.TargetID,
		&kindStr,
		&asgn.PayloadRef,
		&stateStr,
		&rollbackID,
		&histRaw,
		&asgn.CreatedAt,
		&asgn.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, model.ErrAssignmentNotFound
		}
		return nil, err
	}

	asgn.Kind = model.AssignmentKind(kindStr)
	asgn.State = model.AssignmentState(stateStr)
	asgn.RollbackFromAssignmentID = rollbackID
	if len(histRaw) > 0 {
		_ = json.Unmarshal(histRaw, &asgn.StateHistory)
	}

	return &asgn, nil
}

// ListAssignmentsForDevice returns all active assignments targeting this device or user.
func (s *Store) ListAssignmentsForDevice(ctx context.Context, organizationID, deviceID, userID string) ([]*model.Assignment, error) {
	if s.pool == nil {
		return nil, errors.New("database pool uninitialized")
	}

	query := `
		SELECT id, organization_id, target_type, target_id, kind, payload_ref, state, rollback_from_assignment_id, state_history, created_at, updated_at
		FROM assignments
		WHERE organization_id = $1
		  AND (
			(target_type = 'device' AND target_id = $2)
			OR (target_type = 'user' AND target_id = $3 AND $3 != '')
			OR (target_type = 'group' AND target_id = 'default')
		  )
		ORDER BY updated_at DESC
	`
	rows, err := s.pool.Query(ctx, query, organizationID, deviceID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*model.Assignment
	for rows.Next() {
		var asgn model.Assignment
		var kindStr, stateStr string
		var rollbackID *string
		var histRaw []byte

		if err := rows.Scan(
			&asgn.ID,
			&asgn.OrganizationID,
			&asgn.TargetType,
			&asgn.TargetID,
			&kindStr,
			&asgn.PayloadRef,
			&stateStr,
			&rollbackID,
			&histRaw,
			&asgn.CreatedAt,
			&asgn.UpdatedAt,
		); err != nil {
			return nil, err
		}

		asgn.Kind = model.AssignmentKind(kindStr)
		asgn.State = model.AssignmentState(stateStr)
		asgn.RollbackFromAssignmentID = rollbackID
		if len(histRaw) > 0 {
			_ = json.Unmarshal(histRaw, &asgn.StateHistory)
		}
		result = append(result, &asgn)
	}

	return result, rows.Err()
}

// UpdateAssignmentState validates and transitions assignment state, appending to history (REQ-DSM-002).
func (s *Store) UpdateAssignmentState(ctx context.Context, organizationID, assignmentID string, toState model.AssignmentState, reason, actor string) (*model.Assignment, error) {
	if s.pool == nil {
		return nil, errors.New("database pool uninitialized")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var curStateStr string
	err = tx.QueryRow(ctx, `
		SELECT state FROM assignments
		WHERE organization_id = $1 AND id = $2
		FOR UPDATE
	`, organizationID, assignmentID).Scan(&curStateStr)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, model.ErrAssignmentNotFound
		}
		return nil, err
	}

	curState := model.AssignmentState(curStateStr)
	if err := model.ValidateTransition(curState, toState); err != nil {
		return nil, err
	}

	transitionJSON, err := json.Marshal(map[string]interface{}{
		"from_state": curState,
		"to_state":   toState,
		"reason":     reason,
		"actor":      actor,
		"timestamp":  time.Now().UTC(),
	})
	if err != nil {
		return nil, err
	}

	updateQuery := `
		UPDATE assignments
		SET state = $3,
		    state_history = state_history || jsonb_build_array($4::jsonb),
		    updated_at = now()
		WHERE organization_id = $1 AND id = $2
		RETURNING id, organization_id, target_type, target_id, kind, payload_ref, state, rollback_from_assignment_id, state_history, created_at, updated_at
	`
	row := tx.QueryRow(ctx, updateQuery, organizationID, assignmentID, string(toState), string(transitionJSON))

	var asgn model.Assignment
	var kindStr, stateStr string
	var rollbackID *string
	var histRaw []byte

	err = row.Scan(
		&asgn.ID,
		&asgn.OrganizationID,
		&asgn.TargetType,
		&asgn.TargetID,
		&kindStr,
		&asgn.PayloadRef,
		&stateStr,
		&rollbackID,
		&histRaw,
		&asgn.CreatedAt,
		&asgn.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	asgn.Kind = model.AssignmentKind(kindStr)
	asgn.State = model.AssignmentState(stateStr)
	asgn.RollbackFromAssignmentID = rollbackID
	if len(histRaw) > 0 {
		_ = json.Unmarshal(histRaw, &asgn.StateHistory)
	}

	return &asgn, nil
}

// AcknowledgeAssignment handles endpoint acknowledgment (REQ-DSM-006).
func (s *Store) AcknowledgeAssignment(ctx context.Context, organizationID string, req *model.AssignmentAckRequest) (*model.Assignment, error) {
	reason := fmt.Sprintf("Client ACK received (payload hash: %s)", req.PayloadHash)
	if req.ErrorMessage != "" {
		reason = fmt.Sprintf("Client ACK failed: %s", req.ErrorMessage)
	}
	return s.UpdateAssignmentState(ctx, organizationID, req.AssignmentID, req.State, reason, "workstation-agent")
}

// SweepStaleAssignments checks assignments in 'delivered' or 'applied' whose device heartbeat has timed out (REQ-DSM-008).
func (s *Store) SweepStaleAssignments(ctx context.Context, heartbeatTimeout time.Duration) (int64, error) {
	if s.pool == nil {
		return 0, errors.New("database pool uninitialized")
	}

	threshold := time.Now().Add(-heartbeatTimeout)

	query := `
		WITH timed_out_assignments AS (
			SELECT a.id, a.organization_id
			FROM assignments a
			JOIN devices d ON a.target_id = d.stable_device_id AND a.target_type = 'device'
			WHERE a.state IN ('delivered', 'applied')
			  AND d.last_heartbeat_at < $1
		)
		UPDATE assignments a
		SET state = 'stale',
		    state_history = a.state_history || jsonb_build_array(jsonb_build_object(
				'from_state', a.state,
				'to_state', 'stale',
				'reason', 'Device heartbeat timed out',
				'actor', 'stale-sweep-scheduler',
				'timestamp', now()
			)),
		    updated_at = now()
		FROM timed_out_assignments toa
		WHERE a.id = toa.id AND a.organization_id = toa.organization_id
	`
	cmdTag, err := s.pool.Exec(ctx, query, threshold)
	if err != nil {
		return 0, err
	}
	return cmdTag.RowsAffected(), nil
}

// RollbackAssignment moves failed assignment to 'rolled_back' referencing previous assignment (REQ-DSM-010).
func (s *Store) RollbackAssignment(ctx context.Context, organizationID, assignmentID, restoreAssignmentID, actor, reason string) (*model.Assignment, error) {
	if s.pool == nil {
		return nil, errors.New("database pool uninitialized")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var curStateStr string
	err = tx.QueryRow(ctx, `
		SELECT state FROM assignments
		WHERE organization_id = $1 AND id = $2
		FOR UPDATE
	`, organizationID, assignmentID).Scan(&curStateStr)
	if err != nil {
		return nil, err
	}

	curState := model.AssignmentState(curStateStr)
	if curState != model.AssignmentStateFailed {
		return nil, fmt.Errorf("assignment must be in 'failed' state to rollback, current state: %s", curState)
	}

	transitionJSON, _ := json.Marshal(map[string]interface{}{
		"from_state": curState,
		"to_state":   model.AssignmentStateRolledBack,
		"reason":     reason,
		"actor":      actor,
		"timestamp":  time.Now().UTC(),
	})

	updateQuery := `
		UPDATE assignments
		SET state = 'rolled_back',
		    rollback_from_assignment_id = $3,
		    state_history = state_history || jsonb_build_array($4::jsonb),
		    updated_at = now()
		WHERE organization_id = $1 AND id = $2
		RETURNING id, organization_id, target_type, target_id, kind, payload_ref, state, rollback_from_assignment_id, state_history, created_at, updated_at
	`
	row := tx.QueryRow(ctx, updateQuery, organizationID, assignmentID, restoreAssignmentID, string(transitionJSON))

	var asgn model.Assignment
	var kindStr, stateStr string
	var rollbackID *string
	var histRaw []byte

	err = row.Scan(
		&asgn.ID,
		&asgn.OrganizationID,
		&asgn.TargetType,
		&asgn.TargetID,
		&kindStr,
		&asgn.PayloadRef,
		&stateStr,
		&rollbackID,
		&histRaw,
		&asgn.CreatedAt,
		&asgn.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	asgn.Kind = model.AssignmentKind(kindStr)
	asgn.State = model.AssignmentState(stateStr)
	asgn.RollbackFromAssignmentID = rollbackID
	if len(histRaw) > 0 {
		_ = json.Unmarshal(histRaw, &asgn.StateHistory)
	}

	return &asgn, nil
}
