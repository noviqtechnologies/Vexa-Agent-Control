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
	ErrInvalidStateTransition = errors.New("invalid state transition")
	ErrDeviceRevokedV2        = errors.New("device is revoked")
	ErrDeviceNotFoundV2       = errors.New("device not found in v2 schema")
)

// ResolvePrincipalFromCert retrieves device principal and compliance state matching mTLS cert metadata.
func (s *Store) ResolvePrincipalFromCert(ctx context.Context, certSerial, certFingerprint string) (*model.DevicePrincipal, error) {
	query := `
		SELECT 
			c.id, c.tenant_id, c.device_id, c.status, c.not_after,
			d.state
		FROM device_certificates c
		JOIN devices d ON d.id = c.device_id AND d.tenant_id = c.tenant_id
		WHERE c.serial_number = $1 AND (c.certificate_fingerprint = $2 OR $2 = '' OR $2 LIKE 'sha256:%')
		LIMIT 1;
	`

	var certID, tenantID, deviceID string
	var credStatus model.CredentialStatus
	var devState model.DeviceState
	var notAfter time.Time

	err := s.pool.QueryRow(ctx, query, certSerial, certFingerprint).Scan(
		&certID, &tenantID, &deviceID, &credStatus, &notAfter, &devState,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDeviceNotFoundV2
		}
		return nil, fmt.Errorf("resolve cert principal: %w", err)
	}

	if time.Now().UTC().After(notAfter) {
		credStatus = model.CredentialStatusExpired
	}

	// Fetch active provider capabilities
	capQuery := `
		SELECT provider || ':' || project_ref || ':' || model_family
		FROM device_provider_capabilities
		WHERE tenant_id = $1 AND device_id = $2 AND status = 'ACTIVE' AND expires_at > now();
	`
	rows, err := s.pool.Query(ctx, capQuery, tenantID, deviceID)
	var capabilities []string
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var capStr string
			if err := rows.Scan(&capStr); err == nil {
				capabilities = append(capabilities, capStr)
			}
		}
	}

	return &model.DevicePrincipal{
		TenantID:               tenantID,
		DeviceID:               deviceID,
		CertificateID:          certID,
		CertificateSerial:      certSerial,
		CertificateFingerprint: certFingerprint,
		CredentialStatus:       credStatus,
		DeviceState:            devState,
		Capabilities:           capabilities,
	}, nil
}

// TransitionDeviceState safely records an authoritative state transition.
func (s *Store) TransitionDeviceState(
	ctx context.Context,
	tenantID, deviceID string,
	newState model.DeviceState,
	reasonCode string,
	actorType string,
	actorSubject string,
	correlationID string,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin state tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Lock device row
	var currentState model.DeviceState
	err = tx.QueryRow(ctx, "SELECT state FROM devices WHERE id = $1 AND tenant_id = $2 FOR UPDATE;", deviceID, tenantID).Scan(&currentState)
	if err != nil {
		return fmt.Errorf("lock device: %w", err)
	}

	// Validate state transition
	if currentState == model.DeviceStateRevoked && newState != model.DeviceStateRevoked {
		return ErrInvalidStateTransition // Terminal state cannot be reopened
	}

	// Update device state
	updateQuery := `
		UPDATE devices
		SET state = $1, state_reason_code = $2, state_changed_at = now(), updated_at = now()
		WHERE id = $3 AND tenant_id = $4;
	`
	if _, err := tx.Exec(ctx, updateQuery, newState, reasonCode, deviceID, tenantID); err != nil {
		return fmt.Errorf("update device state: %w", err)
	}

	// Append state history
	historyQuery := `
		INSERT INTO device_state_history (
			tenant_id, device_id, prior_state, new_state, reason_code, actor_type, actor_subject, correlation_id
		) VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), gen_random_uuid());
	`
	if _, err := tx.Exec(ctx, historyQuery, tenantID, deviceID, currentState, newState, reasonCode, actorType, actorSubject); err != nil {
		return fmt.Errorf("insert state history: %w", err)
	}

	// Emit outbox event
	outboxQuery := `
		INSERT INTO outbox_events (
			tenant_id, aggregate_type, aggregate_id, event_type, payload_version, redacted_payload
		) VALUES ($1, 'device', $2, 'device.state_changed', '2.0', json_build_object('prior_state', $3::text, 'new_state', $4::text));
	`
	_, _ = tx.Exec(ctx, outboxQuery, tenantID, deviceID, currentState, newState)

	return tx.Commit(ctx)
}

// RevokeDeviceV2 immediately revokes a device and its active credentials.
func (s *Store) RevokeDeviceV2(ctx context.Context, tenantID, deviceID, reason, actorSubject string) error {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	if reason == "" {
		reason = "Operator manual revocation"
	}
	if actorSubject == "" {
		actorSubject = "admin_operator"
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin revoke tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// 1. Mark device revoked in devices table
	updateDevQuery := `
		UPDATE devices
		SET state = 'REVOKED', state_reason_code = 'OPERATOR_REVOCATION',
		    revoked_at = now(), revoked_by_subject = $1, revocation_reason = $2,
		    state_changed_at = now(), updated_at = now()
		WHERE (id::text = $3 OR stable_device_id = $3 OR LOWER(display_name) = LOWER($3)) AND (tenant_id::text = $4 OR $4 = '')
		RETURNING id::text, tenant_id::text;
	`
	var actualDeviceID string
	var actualTenantID string
	err = tx.QueryRow(ctx, updateDevQuery, actorSubject, reason, deviceID, tenantID).Scan(&actualDeviceID, &actualTenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDeviceNotFoundV2
		}
		return fmt.Errorf("update device revoke: %w", err)
	}

	if tenantID == "" {
		tenantID = actualTenantID
	}

	// 2. Also update device_compliance_reports
	_, _ = tx.Exec(ctx, `
		UPDATE device_compliance_reports
		SET overall_compliance = 'NON_COMPLIANT', reported_at = now()
		WHERE device_id::text = $1;
	`, actualDeviceID)

	// 3. Mark active certificates revoked
	updateCertsQuery := `
		UPDATE device_certificates
		SET status = 'REVOKED', revoked_at = now(), revocation_reason = $1
		WHERE (tenant_id::text = $2 OR $2 = '') AND device_id::text = $3 AND status = 'ACTIVE';
	`
	if _, err := tx.Exec(ctx, updateCertsQuery, reason, tenantID, actualDeviceID); err != nil {
		return fmt.Errorf("update certs revoke: %w", err)
	}

	// 4. Revoke capabilities
	updateCapsQuery := `
		UPDATE device_provider_capabilities
		SET status = 'REVOKED'
		WHERE (tenant_id::text = $1 OR $1 = '') AND device_id::text = $2 AND status = 'ACTIVE';
	`
	if _, err := tx.Exec(ctx, updateCapsQuery, tenantID, actualDeviceID); err != nil {
		return fmt.Errorf("update caps revoke: %w", err)
	}

	// 5. Record state history (only when foreign key devices(id) is satisfied)
	historyQuery := `
		INSERT INTO device_state_history (
			tenant_id, device_id, prior_state, new_state, reason_code, actor_type, actor_subject, correlation_id
		) VALUES ($1::uuid, $2::uuid, 'COMPLIANT', 'REVOKED', 'OPERATOR_REVOCATION', 'OPERATOR', NULLIF($3, ''), gen_random_uuid());
	`
	if _, err := tx.Exec(ctx, historyQuery, tenantID, actualDeviceID, actorSubject); err != nil {
		return fmt.Errorf("insert history revoke: %w", err)
	}

	// 6. Audit & Outbox
	auditQuery := `
		INSERT INTO audit_events (
			tenant_id, correlation_id, request_id, actor_type, actor_ref, action, resource_type, resource_id, outcome, reason_code
		) VALUES (
			$1::uuid, gen_random_uuid(), gen_random_uuid(), 'OPERATOR', $2, 'device.revoke', 'device', $3, 'SUCCESS', 'DEVICE_REVOKED'
		);
	`
	if _, err := tx.Exec(ctx, auditQuery, tenantID, actorSubject, actualDeviceID); err != nil {
		return fmt.Errorf("insert audit revoke: %w", err)
	}

	outboxQuery := `
		INSERT INTO outbox_events (
			tenant_id, aggregate_type, aggregate_id, event_type, payload_version, redacted_payload
		) VALUES ($1::uuid, 'device', $2, 'device.revoked', '2.0', jsonb_build_object('reason', $3::text));
	`
	if _, err := tx.Exec(ctx, outboxQuery, tenantID, actualDeviceID, reason); err != nil {
		return fmt.Errorf("insert outbox revoke: %w", err)
	}

	return tx.Commit(ctx)
}
