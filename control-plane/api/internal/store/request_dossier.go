package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

var (
	ErrBrokerRequestNotFound = errors.New("broker request not found")
)

// RecordBrokerRequest persists an admitted logical request before any provider attempts.
func (s *Store) RecordBrokerRequest(ctx context.Context, req *model.BrokerRequest) error {
	if s.pool == nil {
		return nil
	}
	if req.OrganizationID == "" {
		req.OrganizationID = DefaultOrgID
	}
	if req.Status == "" {
		req.Status = "admitted"
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO broker_requests (
			request_id, organization_id, idempotency_key, trace_id,
			principal_device_id, principal_user_id, route_profile_id, policy_version_id,
			requested_provider, requested_model, stream, status, spend_reservation_id,
			settled_microcents, request_hash
		) VALUES (
			$1, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
		)
		ON CONFLICT (request_id) DO UPDATE SET
			status = EXCLUDED.status,
			spend_reservation_id = COALESCE(EXCLUDED.spend_reservation_id, broker_requests.spend_reservation_id)
	`,
		req.RequestID, req.OrganizationID, req.IdempotencyKey, req.TraceID,
		req.PrincipalDeviceID, req.PrincipalUserID, req.RouteProfileID, req.PolicyVersionID,
		req.RequestedProvider, req.RequestedModel, req.Stream, req.Status, req.SpendReservationID,
		req.SettledMicrocents, req.RequestHash,
	)
	return err
}

// GetBrokerRequestByIdempotencyKey fetches an existing request by idempotency key.
func (s *Store) GetBrokerRequestByIdempotencyKey(ctx context.Context, orgID, key string) (*model.BrokerRequest, error) {
	if s.pool == nil || key == "" {
		return nil, ErrBrokerRequestNotFound
	}
	if orgID == "" {
		orgID = DefaultOrgID
	}

	var req model.BrokerRequest
	var compAt *time.Time
	var cachedJSON []byte
	err := s.pool.QueryRow(ctx, `
		SELECT request_id, organization_id, idempotency_key, trace_id,
		       principal_device_id, principal_user_id, route_profile_id, policy_version_id,
		       requested_provider, requested_model, stream, status, terminal_reason_code,
		       spend_reservation_id, settled_microcents, request_hash, cached_response,
		       created_at, completed_at
		FROM broker_requests
		WHERE organization_id::text = $1 AND idempotency_key = $2
	`, orgID, key).Scan(
		&req.RequestID, &req.OrganizationID, &req.IdempotencyKey, &req.TraceID,
		&req.PrincipalDeviceID, &req.PrincipalUserID, &req.RouteProfileID, &req.PolicyVersionID,
		&req.RequestedProvider, &req.RequestedModel, &req.Stream, &req.Status, &req.TerminalReasonCode,
		&req.SpendReservationID, &req.SettledMicrocents, &req.RequestHash, &cachedJSON,
		&req.CreatedAt, &compAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrBrokerRequestNotFound
		}
		return nil, err
	}
	req.CompletedAt = compAt
	req.CachedResponse = cachedJSON
	return &req, nil
}

// RecordBrokerAttemptStart writes an append-only start event before an upstream call.
func (s *Store) RecordBrokerAttemptStart(ctx context.Context, att *model.BrokerAttempt) error {
	if s.pool == nil {
		return nil
	}
	if att.StartedAt.IsZero() {
		att.StartedAt = time.Now().UTC()
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO broker_attempts (
			attempt_id, request_id, attempt_number, target_type, provider, model,
			started_at, stream_committed, usage_source
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)
		ON CONFLICT (request_id, attempt_number) DO NOTHING
	`,
		att.AttemptID, att.RequestID, att.AttemptNumber, att.TargetType, att.Provider, att.Model,
		att.StartedAt, att.StreamCommitted, att.UsageSource,
	)
	return err
}

// RecordBrokerAttemptComplete updates the attempt with latency, status, and usage.
func (s *Store) RecordBrokerAttemptComplete(ctx context.Context, att *model.BrokerAttempt) error {
	if s.pool == nil {
		return nil
	}
	now := time.Now().UTC()
	if att.CompletedAt == nil || att.CompletedAt.IsZero() {
		att.CompletedAt = &now
	}

	_, err := s.pool.Exec(ctx, `
		UPDATE broker_attempts
		SET completed_at = $1,
		    latency_ms = $2,
		    http_status = $3,
		    error_class = $4,
		    error_message_redacted = $5,
		    stream_committed = $6,
		    input_tokens = $7,
		    output_tokens = $8,
		    cached_tokens = $9,
		    usage_source = $10
		WHERE attempt_id = $11
	`,
		att.CompletedAt, att.LatencyMs, att.HTTPStatus, att.ErrorClass,
		att.ErrorMessageRedacted, att.StreamCommitted, att.InputTokens,
		att.OutputTokens, att.CachedTokens, att.UsageSource, att.AttemptID,
	)
	return err
}

// FinalizeBrokerRequest updates the logical request with terminal outcome and cached response.
func (s *Store) FinalizeBrokerRequest(
	ctx context.Context,
	reqID, status, reasonCode string,
	settledMicrocents int64,
	cachedResp []byte,
) error {
	if s.pool == nil {
		return nil
	}
	now := time.Now().UTC()
	_, err := s.pool.Exec(ctx, `
		UPDATE broker_requests
		SET status = $1,
		    terminal_reason_code = $2,
		    settled_microcents = $3,
		    cached_response = $4,
		    completed_at = $5
		WHERE request_id = $6
	`, status, reasonCode, settledMicrocents, cachedResp, now, reqID)
	return err
}

// GetRequestDossier retrieves the complete dossier including logical request and ordered attempts.
func (s *Store) GetRequestDossier(ctx context.Context, orgID, reqID string) (*model.RequestDossier, error) {
	if s.pool == nil {
		return nil, ErrBrokerRequestNotFound
	}
	if orgID == "" {
		orgID = DefaultOrgID
	}

	var req model.BrokerRequest
	var compAt *time.Time
	var cachedJSON []byte
	err := s.pool.QueryRow(ctx, `
		SELECT request_id, organization_id, idempotency_key, trace_id,
		       principal_device_id, principal_user_id, route_profile_id, policy_version_id,
		       requested_provider, requested_model, stream, status, terminal_reason_code,
		       spend_reservation_id, settled_microcents, request_hash, cached_response,
		       created_at, completed_at
		FROM broker_requests
		WHERE request_id = $1 AND (organization_id::text = $2 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
	`, reqID, orgID).Scan(
		&req.RequestID, &req.OrganizationID, &req.IdempotencyKey, &req.TraceID,
		&req.PrincipalDeviceID, &req.PrincipalUserID, &req.RouteProfileID, &req.PolicyVersionID,
		&req.RequestedProvider, &req.RequestedModel, &req.Stream, &req.Status, &req.TerminalReasonCode,
		&req.SpendReservationID, &req.SettledMicrocents, &req.RequestHash, &cachedJSON,
		&req.CreatedAt, &compAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrBrokerRequestNotFound
		}
		return nil, err
	}
	req.CompletedAt = compAt
	req.CachedResponse = cachedJSON

	// Fetch ordered attempts
	rows, err := s.pool.Query(ctx, `
		SELECT attempt_id, request_id, attempt_number, target_type, provider, model,
		       started_at, completed_at, latency_ms, http_status, error_class,
		       error_message_redacted, stream_committed, input_tokens, output_tokens,
		       cached_tokens, usage_source
		FROM broker_attempts
		WHERE request_id = $1
		ORDER BY attempt_number ASC
	`, reqID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attempts []model.BrokerAttempt
	var totalLatency int
	for rows.Next() {
		var att model.BrokerAttempt
		var attCompAt *time.Time
		if err := rows.Scan(
			&att.AttemptID, &att.RequestID, &att.AttemptNumber, &att.TargetType, &att.Provider, &att.Model,
			&att.StartedAt, &attCompAt, &att.LatencyMs, &att.HTTPStatus, &att.ErrorClass,
			&att.ErrorMessageRedacted, &att.StreamCommitted, &att.InputTokens, &att.OutputTokens,
			&att.CachedTokens, &att.UsageSource,
		); err != nil {
			return nil, err
		}
		att.CompletedAt = attCompAt
		totalLatency += att.LatencyMs
		attempts = append(attempts, att)
	}

	dossier := &model.RequestDossier{
		Request:        req,
		Attempts:       attempts,
		TotalLatencyMs: totalLatency,
		AuditLink:      fmt.Sprintf("/api/v1/observability/audit?request_id=%s", req.RequestID),
	}
	if req.TraceID != "" {
		dossier.TraceLink = fmt.Sprintf("/api/v1/observability/traces/%s", req.TraceID)
	}

	return dossier, nil
}
