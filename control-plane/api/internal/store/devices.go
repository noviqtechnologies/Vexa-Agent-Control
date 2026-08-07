package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	checksumsJSON, _ := json.Marshal(d.IDEChecksums)

	_, err := s.pool.Exec(ctx, `
		INSERT INTO devices
			(device_id, hostname, os_arch, os_family, public_key, agentwall_version,
			 compliance_status, mcp_servers_total, mcp_servers_wrapped, ide_checksums,
			 first_enrolled_at, last_heartbeat_at, is_revoked, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'COMPLIANT', $7, $8, $9, NOW(), NOW(), FALSE, NOW())
		ON CONFLICT (device_id) DO UPDATE SET
			hostname            = EXCLUDED.hostname,
			os_arch             = EXCLUDED.os_arch,
			os_family           = EXCLUDED.os_family,
			public_key          = EXCLUDED.public_key,
			agentwall_version   = EXCLUDED.agentwall_version,
			mcp_servers_total   = EXCLUDED.mcp_servers_total,
			mcp_servers_wrapped = EXCLUDED.mcp_servers_wrapped,
			ide_checksums       = EXCLUDED.ide_checksums,
			last_heartbeat_at   = NOW(),
			updated_at         = NOW()
	`, d.DeviceID, d.Hostname, d.OSArch, d.OSFamily, d.PublicKey, d.AgentWallVersion,
		d.MCPServersTotal, d.MCPServersWrapped, checksumsJSON)

	return err
}

// GetDeviceByID fetches a device by ID.
func (s *Store) GetDeviceByID(ctx context.Context, deviceID string) (*model.Device, error) {
	var d model.Device
	var checksumsRaw []byte

	err := s.pool.QueryRow(ctx, `
		SELECT device_id, hostname, os_arch, os_family, public_key, agentwall_version,
		       compliance_status, mcp_servers_total, mcp_servers_wrapped, ide_checksums,
		       first_enrolled_at, last_heartbeat_at, is_revoked, revoked_at, updated_at
		FROM devices
		WHERE device_id = $1
	`, deviceID).Scan(
		&d.DeviceID, &d.Hostname, &d.OSArch, &d.OSFamily, &d.PublicKey, &d.AgentWallVersion,
		&d.ComplianceStatus, &d.MCPServersTotal, &d.MCPServersWrapped, &checksumsRaw,
		&d.FirstEnrolledAt, &d.LastHeartbeatAt, &d.IsRevoked, &d.RevokedAt, &d.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, ErrDeviceNotFound
	} else if err != nil {
		return nil, err
	}

	if len(checksumsRaw) > 0 {
		_ = json.Unmarshal(checksumsRaw, &d.IDEChecksums)
	}

	return &d, nil
}

// UpdateDeviceHeartbeat updates last_heartbeat_at and re-evaluates compliance status.
func (s *Store) UpdateDeviceHeartbeat(ctx context.Context, deviceID string, mcpTotal, mcpWrapped int, checksums map[string]interface{}) error {
	checksumsJSON, _ := json.Marshal(checksums)

	status := "COMPLIANT"
	if mcpWrapped < mcpTotal {
		status = "NON_COMPLIANT"
	}

	res, err := s.pool.Exec(ctx, `
		UPDATE devices
		SET last_heartbeat_at = NOW(),
		    mcp_servers_total = $2,
		    mcp_servers_wrapped = $3,
		    ide_checksums = $4,
		    compliance_status = $5,
		    updated_at = NOW()
		WHERE device_id = $1 AND is_revoked = FALSE
	`, deviceID, mcpTotal, mcpWrapped, checksumsJSON, status)

	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		// Device could be revoked or not found
		d, getErr := s.GetDeviceByID(ctx, deviceID)
		if getErr == nil && d.IsRevoked {
			return ErrDeviceRevoked
		}
		return ErrDeviceNotFound
	}
	return nil
}

// RevokeDevice sets is_revoked to true for a given device.
func (s *Store) RevokeDevice(ctx context.Context, deviceID string) error {
	res, err := s.pool.Exec(ctx, `
		UPDATE devices
		SET is_revoked = TRUE,
		    revoked_at = NOW(),
		    compliance_status = 'NON_COMPLIANT',
		    updated_at = NOW()
		WHERE device_id = $1
	`, deviceID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
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
		SELECT device_id, hostname, os_arch, os_family, public_key, agentwall_version,
		       CASE
		           WHEN is_revoked THEN 'NON_COMPLIANT'
		           WHEN last_heartbeat_at < NOW() - INTERVAL '10 minutes' THEN 'NON_COMPLIANT'
		           WHEN last_heartbeat_at < NOW() - INTERVAL '3 minutes' THEN 'UNREACHABLE'
		           WHEN mcp_servers_wrapped < mcp_servers_total THEN 'NON_COMPLIANT'
		           ELSE 'COMPLIANT'
		       END AS compliance_status,
		       mcp_servers_total, mcp_servers_wrapped, ide_checksums,
		       first_enrolled_at, last_heartbeat_at, is_revoked, revoked_at, updated_at
		FROM devices
		WHERE ($1 = '' OR os_family = $1)
		  AND ($2 = '' OR (
		      CASE
		          WHEN is_revoked THEN 'NON_COMPLIANT'
		          WHEN last_heartbeat_at < NOW() - INTERVAL '10 minutes' THEN 'NON_COMPLIANT'
		          WHEN last_heartbeat_at < NOW() - INTERVAL '3 minutes' THEN 'UNREACHABLE'
		          WHEN mcp_servers_wrapped < mcp_servers_total THEN 'NON_COMPLIANT'
		          ELSE 'COMPLIANT'
		      END = $2
		  ))
		ORDER BY last_heartbeat_at DESC
		LIMIT $3 OFFSET $4
	`, osFamily, statusFilter, limit, offset)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	devices := make([]model.Device, 0)
	for rows.Next() {
		var d model.Device
		var checksumsRaw []byte
		if err := rows.Scan(
			&d.DeviceID, &d.Hostname, &d.OSArch, &d.OSFamily, &d.PublicKey, &d.AgentWallVersion,
			&d.ComplianceStatus, &d.MCPServersTotal, &d.MCPServersWrapped, &checksumsRaw,
			&d.FirstEnrolledAt, &d.LastHeartbeatAt, &d.IsRevoked, &d.RevokedAt, &d.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if len(checksumsRaw) > 0 {
			_ = json.Unmarshal(checksumsRaw, &d.IDEChecksums)
		}
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
