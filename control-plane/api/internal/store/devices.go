package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
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

// CreateEnrollmentToken inserts a new enrollment token for a tenant.
func (s *Store) CreateEnrollmentToken(ctx context.Context, tenantID, tokenID, rawToken, createdBy string, maxUses int, ttlHours int) (*model.EnrollmentToken, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
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
		INSERT INTO enrollment_tokens (tenant_id, token_hash, token_hint, status, max_uses, current_uses, reason, expires_at, created_by_subject, created_at)
		VALUES ($1, $2, $3, 'ACTIVE', $4, 0, 'Standard enrollment', $5, $6, NOW())
		RETURNING id::text, token_hash, created_by_subject, max_uses, current_uses, expires_at, created_at
	`, tenantID, []byte(tokenHash), tokenID, maxUses, expiresAt, createdBy).Scan(
		&t.TokenID, &t.TokenHash, &t.CreatedBy, &t.MaxUses, &t.CurrentUses, &t.ExpiresAt, &t.CreatedAt,
	)
	if err != nil {
		// Fallback for v1 compatibility table
		err = s.pool.QueryRow(ctx, `
			INSERT INTO enrollment_tokens (tenant_id, token_id, token_hash, created_by, max_uses, current_uses, expires_at, created_at)
			VALUES ($1, $2, $3, $4, $5, 0, $6, NOW())
			RETURNING token_id, token_hash, created_by, max_uses, current_uses, expires_at, created_at
		`, tenantID, tokenID, tokenHash, createdBy, maxUses, expiresAt).Scan(
			&t.TokenID, &t.TokenHash, &t.CreatedBy, &t.MaxUses, &t.CurrentUses, &t.ExpiresAt, &t.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("create enrollment token: %w", err)
		}
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
		SELECT COALESCE(id::text, token_id), max_uses, current_uses, expires_at
		FROM enrollment_tokens
		WHERE token_hash = $1 OR token_hash = $2
		FOR UPDATE
	`, tokenHash, []byte(tokenHash)).Scan(&tokenID, &maxUses, &currentUses, &expiresAt)

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
		SET current_uses = current_uses + 1,
		    status = CASE WHEN current_uses + 1 >= max_uses THEN 'CONSUMED'::token_status ELSE status END
		WHERE id::text = $1 OR token_id = $1
	`, tokenID)
	return err
}

// RegisterDevice registers a new device or updates public key/metadata on enrollment.
func (s *Store) RegisterDevice(ctx context.Context, tenantID string, d *model.Device) error {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
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

// GetDeviceByID fetches a device by ID or stable_device_id scoped to a tenant.
func (s *Store) GetDeviceByID(ctx context.Context, tenantID, deviceID string) (*model.Device, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
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
			COALESCE(d.os_version_summary, 'v1.0.32') AS agentcontrol_version,
			d.state::text,
			d.first_enrolled_at,
			d.last_heartbeat_at,
			d.revoked_at,
			d.updated_at
		FROM devices d
		LEFT JOIN device_enrollment_keys k ON d.id = k.device_id AND k.status = 'ACTIVE' AND k.tenant_id = d.tenant_id
		WHERE (d.id::text = $1 OR d.stable_device_id = $1) AND d.tenant_id = $2
		LIMIT 1
	`, deviceID, tenantID).Scan(
		&d.DeviceID, &d.Hostname, &d.OSArch, &d.OSFamily, &d.PublicKey, &d.AgentControlVersion,
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
func (s *Store) UpdateDeviceHeartbeat(ctx context.Context, tenantID, deviceID string, mcpTotal, mcpWrapped int, checksums map[string]interface{}) error {
	status := "COMPLIANT"
	if mcpWrapped < mcpTotal && mcpTotal > 0 {
		status = "NON_COMPLIANT"
	}

	// Update devices table
	_, err := s.pool.Exec(ctx, `
		UPDATE devices
		SET last_heartbeat_at = NOW(),
		    state = CASE WHEN state = 'REVOKED' THEN 'REVOKED'::device_state ELSE $2::device_state END,
		    updated_at = NOW()
		WHERE (id::text = $1 OR stable_device_id = $1) AND state != 'REVOKED'
	`, deviceID, status)
	if err != nil {
		return err
	}

	// Also update device_enrollments table
	_, _ = s.pool.Exec(ctx, `
		UPDATE device_enrollments
		SET last_heartbeat_at = NOW(),
		    enrollment_status = 'ACTIVE',
		    updated_at = NOW()
		WHERE (device_id::text = $1 OR hostname = $1) AND enrollment_status != 'REVOKED'
	`, deviceID)

	return nil
}

// RevokeDevice sets state to REVOKED for a given device within a tenant.
func (s *Store) RevokeDevice(ctx context.Context, tenantID, deviceID string) error {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	res, err := s.pool.Exec(ctx, `
		UPDATE devices
		SET state = 'REVOKED',
		    revoked_at = NOW(),
		    updated_at = NOW()
		WHERE (id::text = $1 OR stable_device_id = $1) AND tenant_id = $2
	`, deviceID, tenantID)
	if err != nil {
		return err
	}

	enrollRes, err := s.pool.Exec(ctx, `
		UPDATE device_enrollments
		SET enrollment_status = 'REVOKED', updated_at = NOW()
		WHERE (device_id::text = $1 OR hostname = $1) AND organization_id = $2
	`, deviceID, tenantID)
	if err != nil {
		return err
	}

	_, _ = s.pool.Exec(ctx, `
		UPDATE device_compliance_reports
		SET overall_compliance = 'NON_COMPLIANT', reported_at = NOW()
		WHERE device_id::text = $1 AND organization_id = $2
	`, deviceID, tenantID)

	if res.RowsAffected() == 0 && enrollRes.RowsAffected() == 0 {
		return ErrDeviceNotFound
	}
	return nil
}

// ListDevices lists devices filtered by os_family or compliance_status strictly scoped to tenant.
func (s *Store) ListDevices(ctx context.Context, tenantID, osFamily, statusFilter string, limit, offset int) ([]model.Device, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
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
			COALESCE(d.os_version_summary, 'v1.0.32') AS agentcontrol_version,
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
		LEFT JOIN device_enrollment_keys k ON d.id = k.device_id AND k.status = 'ACTIVE' AND k.tenant_id = d.tenant_id
		WHERE d.tenant_id = $1
		  AND ($2 = '' OR d.os_family = $2)
		  AND ($3 = '' OR (
		      CASE
		          WHEN d.state = 'REVOKED' THEN 'REVOKED'
		          WHEN d.state = 'PENDING' THEN 'PENDING'
		          WHEN d.last_heartbeat_at IS NULL THEN 'UNREACHABLE'
		          WHEN d.last_heartbeat_at < NOW() - INTERVAL '10 minutes' THEN 'NON_COMPLIANT'
		          WHEN d.last_heartbeat_at < NOW() - INTERVAL '3 minutes' THEN 'UNREACHABLE'
		          ELSE d.state::text
		      END = $3
		  ))
		ORDER BY d.created_at DESC
		LIMIT $4 OFFSET $5
	`, tenantID, osFamily, statusFilter, limit, offset)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	devices := make([]model.Device, 0)
	for rows.Next() {
		var d model.Device
		var revokedAt *time.Time
		if err := rows.Scan(
			&d.DeviceID, &d.Hostname, &d.OSArch, &d.OSFamily, &d.PublicKey, &d.AgentControlVersion,
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

// InsertTamperLog records a tamper detection event scoped to tenant.
func (s *Store) InsertTamperLog(ctx context.Context, tenantID string, log *model.DeviceTamperLog) error {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO device_tamper_logs (tenant_id, device_id, target_ide, detected_diff, action_taken, created_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
	`, tenantID, log.DeviceID, log.TargetIDE, log.DetectedDiff, log.ActionTaken)
	return err
}

// ResolveDevicePrincipal returns the DevicePrincipal (with TenantID) for an enrolled token or device ID.
func (s *Store) ResolveDevicePrincipal(ctx context.Context, token string) (*model.DevicePrincipal, bool) {
	if token == "" {
		return nil, false
	}
	var principal model.DevicePrincipal
	// 1. Check devices table
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, tenant_id::text
		FROM devices
		WHERE (id::text = $1 OR stable_device_id = $1)
		  AND state != 'REVOKED'
		LIMIT 1
	`, token).Scan(&principal.DeviceID, &principal.TenantID)
	if err == nil && principal.TenantID != "" {
		return &principal, true
	}

	// 2. Check device_enrollments table
	err = s.pool.QueryRow(ctx, `
		SELECT device_id::text, organization_id::text
		FROM device_enrollments
		WHERE (device_id::text = $1 OR hostname = $1)
		  AND enrollment_status != 'REVOKED'
		LIMIT 1
	`, token).Scan(&principal.DeviceID, &principal.TenantID)
	if err == nil && principal.TenantID != "" {
		return &principal, true
	}

	return nil, false
}

// ValidateDeviceToken returns true if the token matches an enrolled/active device or enrollment.
func (s *Store) ValidateDeviceToken(ctx context.Context, token string) bool {
	if token == "" {
		return false
	}
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM devices 
			WHERE (id::text = $1 OR stable_device_id = $1)
			  AND state != 'REVOKED'
			UNION
			SELECT 1 FROM device_enrollments
			WHERE (device_id::text = $1 OR hostname = $1)
			  AND enrollment_status != 'REVOKED'
		)
	`, token).Scan(&exists)
	return err == nil && exists
}

