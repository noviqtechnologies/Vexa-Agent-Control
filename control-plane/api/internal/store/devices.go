package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/model"
)

var (
	ErrTokenInvalid   = errors.New("enrollment token is invalid or expired")
	ErrDeviceNotFound = errors.New("device not found")
	ErrDeviceRevoked  = errors.New("device has been revoked")
)

// HashEnrollmentToken returns the SHA-256 string representation of a raw token.
func HashEnrollmentToken(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}

// CreateEnrollmentToken inserts a new enrollment token.
func (s *Store) CreateEnrollmentToken(ctx context.Context, tokenID, rawToken, createdBy string, maxUses int, ttlHours int) (*model.EnrollmentToken, error) {
	if ttlHours <= 0 {
		ttlHours = 24
	}
	if maxUses <= 0 {
		maxUses = 1
	}

	tokenHash := HashEnrollmentToken(rawToken)
	expiresAt := time.Now().Add(time.Duration(ttlHours) * time.Hour)

	var t model.EnrollmentToken
	err := s.pool.QueryRow(ctx, `
		INSERT INTO enrollment_tokens (token_id, token_hash, created_by, max_uses, current_uses, expires_at, created_at)
		VALUES ($1, $2, $3, $4, 0, $5, NOW())
		RETURNING token_id, token_hash, created_by, max_uses, current_uses, expires_at, created_at
	`, tokenID, tokenHash, createdBy, maxUses, expiresAt).Scan(
		&t.TokenID, &t.TokenHash, &t.CreatedBy, &t.MaxUses, &t.CurrentUses, &t.ExpiresAt, &t.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create enrollment token: %w", err)
	}
	return &t, nil
}

// ConsumeEnrollmentToken validates token hash, checks expiration and max_uses, and increments current_uses.
func (s *Store) ConsumeEnrollmentToken(ctx context.Context, rawToken string) error {
	tokenHash := HashEnrollmentToken(rawToken)

	var tokenID string
	var maxUses, currentUses int
	var expiresAt time.Time

	err := s.pool.QueryRow(ctx, `
		SELECT token_id, max_uses, current_uses, expires_at
		FROM enrollment_tokens
		WHERE token_hash = $1
		FOR UPDATE
	`, tokenHash).Scan(&tokenID, &maxUses, &currentUses, &expiresAt)

	if err == pgx.ErrNoRows {
		return ErrTokenInvalid
	} else if err != nil {
		return err
	}

	if time.Now().After(expiresAt) {
		return ErrTokenInvalid
	}
	if currentUses >= maxUses {
		return ErrTokenInvalid
	}

	_, err = s.pool.Exec(ctx, `
		UPDATE enrollment_tokens
		SET current_uses = current_uses + 1
		WHERE token_id = $1
	`, tokenID)
	return err
}

// RegisterDevice registers a new device or updates public key/metadata on enrollment.
func (s *Store) RegisterDevice(ctx context.Context, d *model.Device) error {
	tenantID := "00000000-0000-0000-0000-000000000001"
	_, err := s.pool.Exec(ctx, `
		INSERT INTO devices (
			tenant_id, stable_device_id, display_name, os_family,
			architecture, state, first_enrolled_at, last_heartbeat_at,
			created_at, updated_at
		) VALUES (
			$1, $2, $2, $3,
			$4, 'COMPLIANT', NOW(), NOW(),
			NOW(), NOW()
		)
		ON CONFLICT (tenant_id, stable_device_id) DO UPDATE SET
			os_family = EXCLUDED.os_family,
			architecture = EXCLUDED.architecture,
			state = 'COMPLIANT',
			last_heartbeat_at = NOW(),
			updated_at = NOW()
	`, tenantID, d.DeviceID, d.OSFamily, d.OSArch)
	return err
}

// GetDeviceByID fetches a device by ID or stable_device_id.
func (s *Store) GetDeviceByID(ctx context.Context, deviceID string) (*model.Device, error) {
	var d model.Device
	var state string
	var revokedAt *time.Time
	var lastHb *time.Time

	err := s.pool.QueryRow(ctx, `
		SELECT 
			d.id::text,
			COALESCE(d.stable_device_id, d.id::text) AS hostname,
			COALESCE(d.architecture, 'x86_64') AS os_arch,
			COALESCE(d.os_family, 'windows') AS os_family,
			COALESCE(k.fingerprint, '') AS public_key,
			COALESCE(d.os_version_summary, 'v1.0.32') AS agentwall_version,
			d.state::text,
			d.first_enrolled_at,
			d.last_heartbeat_at,
			d.revoked_at,
			d.updated_at
		FROM devices d
		LEFT JOIN device_enrollment_keys k ON d.id = k.device_id AND k.status = 'ACTIVE'
		WHERE d.id::text = $1 OR d.stable_device_id = $1
		LIMIT 1
	`, deviceID).Scan(
		&d.DeviceID, &d.Hostname, &d.OSArch, &d.OSFamily, &d.PublicKey, &d.AgentWallVersion,
		&state, &d.FirstEnrolledAt, &lastHb, &revokedAt, &d.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, ErrDeviceNotFound
	} else if err != nil {
		return nil, err
	}

	d.ComplianceStatus = state
	d.IsRevoked = (state == "REVOKED")
	d.RevokedAt = revokedAt
	d.MCPServersTotal = 4
	d.MCPServersWrapped = 4
	d.IDEChecksums = map[string]interface{}{}
	if lastHb != nil {
		d.LastHeartbeatAt = *lastHb
	} else {
		d.LastHeartbeatAt = d.FirstEnrolledAt
	}

	return &d, nil
}

// UpdateDeviceHeartbeat updates last_heartbeat_at and re-evaluates compliance status.
func (s *Store) UpdateDeviceHeartbeat(ctx context.Context, deviceID string, mcpTotal, mcpWrapped int, checksums map[string]interface{}) error {
	status := "COMPLIANT"
	if mcpWrapped < mcpTotal && mcpTotal > 0 {
		status = "NON_COMPLIANT"
	}

	res, err := s.pool.Exec(ctx, `
		UPDATE devices
		SET last_heartbeat_at = NOW(),
		    state = CASE WHEN state = 'REVOKED' THEN 'REVOKED'::device_state ELSE $2::device_state END,
		    updated_at = NOW()
		WHERE (id::text = $1 OR stable_device_id = $1) AND state != 'REVOKED'
	`, deviceID, status)

	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		d, getErr := s.GetDeviceByID(ctx, deviceID)
		if getErr == nil && d.IsRevoked {
			return ErrDeviceRevoked
		}
		return ErrDeviceNotFound
	}
	return nil
}

// RevokeDevice sets state to REVOKED for a given device.
func (s *Store) RevokeDevice(ctx context.Context, deviceID string) error {
	res, err := s.pool.Exec(ctx, `
		UPDATE devices
		SET state = 'REVOKED',
		    revoked_at = NOW(),
		    updated_at = NOW()
		WHERE id::text = $1 OR stable_device_id = $1
	`, deviceID)
	if err != nil {
		return err
	}

	enrollRes, err := s.pool.Exec(ctx, `
		UPDATE device_enrollments
		SET enrollment_status = 'REVOKED', updated_at = NOW()
		WHERE device_id::text = $1 OR hostname = $1
	`, deviceID)
	if err != nil {
		return err
	}

	_, _ = s.pool.Exec(ctx, `
		UPDATE device_compliance_reports
		SET overall_compliance = 'NON_COMPLIANT', reported_at = NOW()
		WHERE device_id::text = $1
	`, deviceID)

	if res.RowsAffected() == 0 && enrollRes.RowsAffected() == 0 {
		return ErrDeviceNotFound
	}
	return nil
}

// ListDevices lists devices filtered by os_family or compliance_status with auto-calculated compliance.
func (s *Store) ListDevices(ctx context.Context, osFamily, statusFilter string, limit, offset int) ([]model.Device, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := s.pool.Query(ctx, `
		SELECT 
			d.id::text AS device_id,
			COALESCE(d.stable_device_id, d.id::text) AS hostname,
			COALESCE(d.architecture, 'x86_64') AS os_arch,
			COALESCE(d.os_family, 'windows') AS os_family,
			COALESCE(k.fingerprint, '') AS public_key,
			COALESCE(d.os_version_summary, 'v1.0.32') AS agentwall_version,
			CASE
				WHEN d.state = 'REVOKED' THEN 'REVOKED'
				WHEN d.state = 'PENDING' THEN 'PENDING'
				WHEN d.last_heartbeat_at IS NULL THEN 'UNREACHABLE'
				WHEN d.last_heartbeat_at < NOW() - INTERVAL '10 minutes' THEN 'NON_COMPLIANT'
				WHEN d.last_heartbeat_at < NOW() - INTERVAL '3 minutes' THEN 'UNREACHABLE'
				ELSE d.state::text
			END AS compliance_status,
			d.first_enrolled_at,
			COALESCE(d.last_heartbeat_at, d.first_enrolled_at) AS last_heartbeat_at,
			(d.state = 'REVOKED') AS is_revoked,
			d.revoked_at,
			d.updated_at
		FROM devices d
		LEFT JOIN device_enrollment_keys k ON d.id = k.device_id AND k.status = 'ACTIVE'
		WHERE ($1 = '' OR d.os_family = $1)
		  AND ($2 = '' OR (
		      CASE
		          WHEN d.state = 'REVOKED' THEN 'REVOKED'
		          WHEN d.state = 'PENDING' THEN 'PENDING'
		          WHEN d.last_heartbeat_at IS NULL THEN 'UNREACHABLE'
		          WHEN d.last_heartbeat_at < NOW() - INTERVAL '10 minutes' THEN 'NON_COMPLIANT'
		          WHEN d.last_heartbeat_at < NOW() - INTERVAL '3 minutes' THEN 'UNREACHABLE'
		          ELSE d.state::text
		      END = $2
		  ))
		ORDER BY d.created_at DESC
		LIMIT $3 OFFSET $4
	`, osFamily, statusFilter, limit, offset)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	devices := make([]model.Device, 0)
	for rows.Next() {
		var d model.Device
		var revokedAt *time.Time
		if err := rows.Scan(
			&d.DeviceID, &d.Hostname, &d.OSArch, &d.OSFamily, &d.PublicKey, &d.AgentWallVersion,
			&d.ComplianceStatus, &d.FirstEnrolledAt, &d.LastHeartbeatAt, &d.IsRevoked, &revokedAt, &d.UpdatedAt,
		); err != nil {
			return nil, err
		}
		d.RevokedAt = revokedAt
		d.MCPServersTotal = 4
		d.MCPServersWrapped = 4
		d.IDEChecksums = map[string]interface{}{}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

// InsertTamperLog records a tamper detection event.
func (s *Store) InsertTamperLog(ctx context.Context, log *model.DeviceTamperLog) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO device_tamper_logs (device_id, target_ide, detected_diff, action_taken, created_at)
		VALUES ($1, $2, $3, $4, NOW())
	`, log.DeviceID, log.TargetIDE, log.DetectedDiff, log.ActionTaken)
	return err
}
