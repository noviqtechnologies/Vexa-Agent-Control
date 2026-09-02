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
	if s.pool == nil {
		return nil, ErrDeviceNotFoundV2
	}
	query := `
		SELECT 
			c.id, c.organization_id, c.device_id, c.status, c.not_after,
			d.state
		FROM device_certificates c
		JOIN devices d ON d.id = c.device_id
		WHERE c.serial_number = $1
		LIMIT 1;
	`

	var certID, orgID, deviceID string
	var credStatus model.CredentialStatus
	var devState model.DeviceState
	var notAfter time.Time

	err := s.pool.QueryRow(ctx, query, certSerial).Scan(
		&certID, &orgID, &deviceID, &credStatus, &notAfter, &devState,
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

	return &model.DevicePrincipal{
		OrganizationID:         orgID,
		DeviceID:               deviceID,
		CertificateID:          certID,
		CertificateSerial:      certSerial,
		CertificateFingerprint: certFingerprint,
		CredentialStatus:       credStatus,
		DeviceState:            devState,
		Capabilities:           []string{},
	}, nil
}

// TransitionDeviceState safely records an authoritative state transition.
func (s *Store) TransitionDeviceState(
	ctx context.Context,
	organizationID, deviceID string,
	newState model.DeviceState,
	reasonCode string,
	actorType string,
	actorSubject string,
	correlationID string,
) error {
	if s.pool == nil {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin state tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var currentState model.DeviceState
	err = tx.QueryRow(ctx, "SELECT state FROM devices WHERE id::text = $1 FOR UPDATE;", deviceID).Scan(&currentState)
	if err != nil {
		return fmt.Errorf("lock device: %w", err)
	}

	if currentState == model.DeviceStateRevoked && newState != model.DeviceStateRevoked {
		return ErrDeviceRevokedV2
	}

	updateQuery := `
		UPDATE devices 
		SET state = $2::device_state,
		    state_reason_code = $3,
		    state_changed_at = now(),
		    updated_at = now()
		WHERE id::text = $1;
	`
	if _, err := tx.Exec(ctx, updateQuery, deviceID, newState, reasonCode); err != nil {
		return fmt.Errorf("update device state: %w", err)
	}

	return tx.Commit(ctx)
}
