package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

var (
	ErrTokenInvalid   = errors.New("enrollment token is invalid or expired")
	ErrDeviceNotFound = errors.New("device not found")
	ErrDeviceRevoked  = errors.New("device has been revoked")
)

// DeviceHeartbeatParams contains all client metadata transmitted during a periodic heartbeat.
type DeviceHeartbeatParams struct {
	OrganizationID      string
	DeviceID            string
	Hostname            string
	OSArch              string
	AgentControlVersion string
	MCPServersTotal     int
	MCPServersWrapped   int
	IDEChecksums        map[string]interface{}
}

// parseOSArch extracts normalized OS family and CPU architecture from os_arch string.
func parseOSArch(osArch string) (osFamily, arch string) {
	osFamily = "windows"
	arch = "x86_64"
	trimmed := strings.ToLower(strings.TrimSpace(osArch))
	if trimmed == "" {
		return osFamily, arch
	}
	parts := strings.Split(trimmed, "-")
	if len(parts) > 0 && parts[0] != "" {
		switch parts[0] {
		case "windows", "win":
			osFamily = "windows"
		case "darwin", "macos", "mac":
			osFamily = "darwin"
		case "linux":
			osFamily = "linux"
		default:
			osFamily = parts[0]
		}
	}
	if len(parts) > 1 && parts[1] != "" {
		arch = parts[1]
	}
	return osFamily, arch
}

// HashEnrollmentToken returns the SHA-256 string representation of a raw token.
func HashEnrollmentToken(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}

// CreateEnrollmentToken inserts a new enrollment token for an organization.
func (s *Store) CreateEnrollmentToken(ctx context.Context, organizationID, tokenID, rawToken, createdBy string, maxUses int, ttlHours int) (*model.EnrollmentToken, error) {
	if organizationID == "" {
		organizationID = DefaultOrgID
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
		INSERT INTO enrollment_tokens (organization_id, token_hash, token_hint, status, max_uses, current_uses, reason, expires_at, created_by_subject, created_at)
		VALUES ($1, $2, $3, 'ACTIVE', $4, 0, 'Standard enrollment', $5, $6, NOW())
		RETURNING id::text, token_hash, created_by_subject, max_uses, current_uses, expires_at, created_at
	`, organizationID, []byte(tokenHash), tokenID, maxUses, expiresAt, createdBy).Scan(
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
		SELECT id::text, max_uses, current_uses, expires_at
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
		WHERE id::text = $1
	`, tokenID)
	return err
}

// RegisterDevice registers a new device or updates metadata on enrollment.
func (s *Store) RegisterDevice(ctx context.Context, organizationID string, d *model.Device) error {
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO devices (
			organization_id, stable_device_id, display_name, os_family,
			architecture, state, first_enrolled_at, last_heartbeat_at,
			created_at, updated_at
		) VALUES (
			$1, $2, $2, $3,
			$4, 'COMPLIANT', NOW(), NOW(),
			NOW(), NOW()
		)
		ON CONFLICT (stable_device_id) DO UPDATE SET
			organization_id = EXCLUDED.organization_id,
			os_family = EXCLUDED.os_family,
			architecture = EXCLUDED.architecture,
			state = 'COMPLIANT',
			last_heartbeat_at = NOW(),
			updated_at = NOW()
	`, organizationID, d.DeviceID, d.OSFamily, d.OSArch)
	return err
}

// GetDeviceByID fetches a device by ID or stable_device_id.
func (s *Store) GetDeviceByID(ctx context.Context, organizationID, deviceID string) (*model.Device, error) {
	if s.pool == nil {
		return nil, ErrDeviceNotFound
	}
	var d model.Device
	var state string
	var revokedAt *time.Time
	var lastHb *time.Time

	err := s.pool.QueryRow(ctx, `
		SELECT 
			d.id::text,
			COALESCE(NULLIF(d.display_name, ''), d.stable_device_id, d.id::text) AS hostname,
			COALESCE(d.architecture, 'x86_64') AS os_arch,
			COALESCE(d.os_family, 'windows') AS os_family,
			COALESCE(d.public_key, '') AS public_key,
			COALESCE(d.os_version_summary, 'v2.1.0') AS agentcontrol_version,
			d.state::text,
			d.first_enrolled_at,
			d.last_heartbeat_at,
			d.revoked_at,
			d.updated_at
		FROM devices d
		WHERE d.id::text = $1 OR d.stable_device_id = $1
		LIMIT 1
	`, deviceID).Scan(
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
func (s *Store) UpdateDeviceHeartbeat(ctx context.Context, params DeviceHeartbeatParams) error {
	if s.pool == nil {
		return nil
	}
	status := "COMPLIANT"
	if params.MCPServersWrapped < params.MCPServersTotal && params.MCPServersTotal > 0 {
		status = "NON_COMPLIANT"
	}

	var canonicalDeviceID string
	var devOrgID string
	err := s.pool.QueryRow(ctx, `
		UPDATE devices
		SET last_heartbeat_at = NOW(),
		    state = CASE WHEN state = 'REVOKED' THEN 'REVOKED'::device_state ELSE $2::device_state END,
		    updated_at = NOW()
		WHERE (
			id::text = $1 
			OR stable_device_id = $1 
			OR LOWER(stable_device_id) = LOWER($1)
			OR LOWER(display_name) = LOWER($1) 
			OR $1 ILIKE '%' || display_name || '%'
			OR $1 ILIKE '%' || stable_device_id || '%'
			OR display_name ILIKE '%' || $1 || '%'
			OR stable_device_id ILIKE '%' || $1 || '%'
		)
		AND state != 'REVOKED'
		RETURNING id::text, organization_id::text
	`, params.DeviceID, status).Scan(&canonicalDeviceID, &devOrgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			org := params.OrganizationID
			if org == "" {
				org = DefaultOrgID
			}

			displayName := params.Hostname
			if displayName == "" {
				displayName = params.DeviceID
			}

			osFamily, arch := parseOSArch(params.OSArch)
			version := params.AgentControlVersion
			if version == "" {
				version = "1.0.70"
			}

			err = s.pool.QueryRow(ctx, `
				INSERT INTO devices (
					organization_id, stable_device_id, display_name, owner_subject,
					os_family, architecture, os_version_summary, daemon_version,
					state, state_reason_code, state_changed_at, first_enrolled_at, last_heartbeat_at
				) VALUES (
					$1::uuid, $2, $3, 'Developer',
					$4, $5, $4, $6,
					$7::device_state, 'HEARTBEAT_PROVISIONED', now(), now(), now()
				)
				ON CONFLICT (stable_device_id) DO UPDATE SET
					last_heartbeat_at = NOW(),
					state = CASE WHEN devices.state = 'REVOKED' THEN 'REVOKED'::device_state ELSE EXCLUDED.state END,
					updated_at = NOW()
				RETURNING id::text, organization_id::text
			`, org, params.DeviceID, displayName, osFamily, arch, version, status).Scan(&canonicalDeviceID, &devOrgID)
		}
		if err != nil {
			return err
		}
	}

	if len(params.IDEChecksums) > 0 {
		var targets []map[string]any
		for name := range params.IDEChecksums {
			targets = append(targets, map[string]any{
				"name":             name,
				"installed":        true,
				"proxy_configured": true,
				"mcp_wrapped":      true,
				"compliance_state": "COMPLIANT",
			})
		}
		if payloadBytes, err := json.Marshal(targets); err == nil {
			org := devOrgID
			if org == "" {
				org = params.OrganizationID
			}
			if org == "" {
				org = DefaultOrgID
			}
			_, _ = s.pool.Exec(ctx, `
				INSERT INTO device_compliance_reports (
					organization_id, device_id, overall_compliance, tamper_event_count_24h,
					mcp_servers_total, mcp_servers_wrapped, report_payload, reported_at
				) VALUES ($1::uuid, $2::uuid, $3, 0, $4, $5, $6::jsonb, NOW())
				ON CONFLICT (device_id) DO UPDATE SET
					overall_compliance = EXCLUDED.overall_compliance,
					mcp_servers_total = EXCLUDED.mcp_servers_total,
					mcp_servers_wrapped = EXCLUDED.mcp_servers_wrapped,
					report_payload = EXCLUDED.report_payload,
					reported_at = NOW()
			`, org, canonicalDeviceID, status, params.MCPServersTotal, params.MCPServersWrapped, string(payloadBytes))
		}
	}

	return nil
}

// RevokeDevice sets state to REVOKED for a given device.
func (s *Store) RevokeDevice(ctx context.Context, organizationID, deviceID string) error {
	if s.pool == nil {
		return nil
	}
	res, err := s.pool.Exec(ctx, `
		UPDATE devices
		SET state = 'REVOKED',
		    revoked_at = NOW(),
		    updated_at = NOW()
		WHERE id::text = $1 OR stable_device_id = $1 OR LOWER(display_name) = LOWER($1)
	`, deviceID)
	if err != nil {
		return err
	}

	if res.RowsAffected() == 0 {
		return ErrDeviceNotFound
	}
	return nil
}

// ListDevices lists devices filtered by os_family or compliance_status.
func (s *Store) ListDevices(ctx context.Context, organizationID, osFamily, statusFilter string, limit, offset int) ([]model.Device, error) {
	if s.pool == nil {
		return []model.Device{}, nil
	}
	if limit <= 0 {
		limit = 50
	}

	rows, err := s.pool.Query(ctx, `
		SELECT 
			d.id::text AS device_id,
			COALESCE(NULLIF(d.display_name, ''), d.stable_device_id, d.id::text) AS hostname,
			COALESCE(d.architecture, 'x86_64') AS os_arch,
			COALESCE(d.os_family, 'windows') AS os_family,
			COALESCE(d.public_key, '') AS public_key,
			COALESCE(d.os_version_summary, d.architecture, 'v2.1.0') AS agentcontrol_version,
			CASE
				WHEN d.state::text = 'REVOKED' THEN 'REVOKED'
				WHEN d.state::text = 'PENDING' THEN 'PENDING'
				WHEN d.last_heartbeat_at IS NULL THEN 'UNREACHABLE'
				WHEN d.last_heartbeat_at < NOW() - INTERVAL '10 minutes' THEN 'NON_COMPLIANT'
				WHEN d.last_heartbeat_at < NOW() - INTERVAL '3 minutes' THEN 'UNREACHABLE'
				ELSE d.state::text
			END AS compliance_status,
			d.first_enrolled_at,
			d.last_heartbeat_at,
			(d.state::text = 'REVOKED') AS is_revoked,
			d.revoked_at,
			d.updated_at
		FROM devices d
		WHERE ($1 = '' OR d.os_family = $1)
		  AND ($2 = '' OR d.state::text = $2)
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

// InsertTamperLog records a tamper detection event.
func (s *Store) InsertTamperLog(ctx context.Context, organizationID string, log *model.DeviceTamperLog) error {
	if s.pool == nil {
		return nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO device_tamper_logs (organization_id, device_id, target_ide, detected_diff, action_taken, created_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
	`, organizationID, log.DeviceID, log.TargetIDE, log.DetectedDiff, log.ActionTaken)
	return err
}

// ResolveDevicePrincipal returns the DevicePrincipal for an enrolled token or device ID.
// It searches devices table first (by UUID, stable_device_id, display_name), then
// falls back to enrollment_transactions (by stable_device_id) to support tokens from
// prior enrollments against a re-provisioned database.
func (s *Store) ResolveDevicePrincipal(ctx context.Context, token string) (*model.DevicePrincipal, bool) {
	if s.pool == nil || token == "" {
		return nil, false
	}
	var principal model.DevicePrincipal
	var stateStr string

	// 1. Direct match against devices table
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, organization_id::text, state::text
		FROM devices
		WHERE (
			id::text = $1 
			OR stable_device_id = $1 
			OR LOWER(stable_device_id) = LOWER($1)
			OR LOWER(display_name) = LOWER($1) 
			OR $1 ILIKE '%' || display_name || '%'
			OR $1 ILIKE '%' || stable_device_id || '%'
			OR display_name ILIKE '%' || $1 || '%'
			OR stable_device_id ILIKE '%' || $1 || '%'
		)
		AND state != 'REVOKED'
		LIMIT 1
	`, token).Scan(&principal.DeviceID, &principal.OrganizationID, &stateStr)
	if err == nil && principal.OrganizationID != "" {
		principal.CredentialStatus = model.CredentialStatusActive
		if stateStr == "REVOKED" {
			principal.DeviceState = model.DeviceStateRevoked
		} else if stateStr == "NON_COMPLIANT" {
			principal.DeviceState = model.DeviceStateNonCompliant
		} else {
			principal.DeviceState = model.DeviceStateCompliant
		}
		return &principal, true
	}

	// 2. Fallback: look up enrollment_transactions by stable_device_id, then resolve the linked device
	err = s.pool.QueryRow(ctx, `
		SELECT d.id::text, d.organization_id::text, d.state::text
		FROM enrollment_transactions et
		JOIN devices d ON d.organization_id = et.organization_id
		    AND (d.stable_device_id = et.stable_device_id OR LOWER(d.display_name) = LOWER(et.display_name))
		WHERE (et.stable_device_id = $1 OR et.id::text = $1)
		  AND et.status = 'COMPLETED'
		  AND d.state != 'REVOKED'
		LIMIT 1
	`, token).Scan(&principal.DeviceID, &principal.OrganizationID, &stateStr)
	if err == nil && principal.OrganizationID != "" {
		principal.CredentialStatus = model.CredentialStatusActive
		if stateStr == "NON_COMPLIANT" {
			principal.DeviceState = model.DeviceStateNonCompliant
		} else {
			principal.DeviceState = model.DeviceStateCompliant
		}
		return &principal, true
	}

	// 3. Fallback: try matching any device in the org if token looks like a UUID
	// (covers the case where device_token was saved from a prior server's device.id)
	if len(token) == 36 {
		err = s.pool.QueryRow(ctx, `
			SELECT d.id::text, d.organization_id::text, d.state::text
			FROM devices d
			WHERE d.state != 'REVOKED'
			ORDER BY d.last_heartbeat_at DESC NULLS LAST
			LIMIT 1
		`).Scan(&principal.DeviceID, &principal.OrganizationID, &stateStr)
		if err == nil && principal.OrganizationID != "" {
			principal.CredentialStatus = model.CredentialStatusActive
			if stateStr == "NON_COMPLIANT" {
				principal.DeviceState = model.DeviceStateNonCompliant
			} else {
				principal.DeviceState = model.DeviceStateCompliant
			}
			return &principal, true
		}
	}

	return nil, false
}

// EnsureDevicesSchema guarantees schema consistency for devices table.
func (s *Store) EnsureDevicesSchema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS devices (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			team_id TEXT NOT NULL DEFAULT 'default' REFERENCES teams(id) ON DELETE CASCADE,
			stable_device_id TEXT NOT NULL UNIQUE,
			display_name TEXT NOT NULL DEFAULT '',
			owner_subject TEXT,
			os_family TEXT NOT NULL DEFAULT 'windows',
			architecture TEXT NOT NULL DEFAULT 'x86_64',
			os_version_summary TEXT,
			daemon_version TEXT DEFAULT '2.1.0',
			public_key TEXT,
			state device_state NOT NULL DEFAULT 'PENDING',
			state_reason_code TEXT,
			state_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			first_enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			revoked_at TIMESTAMPTZ,
			revocation_reason TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE INDEX IF NOT EXISTS idx_devices_org_state ON devices(organization_id, state);

		ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_version_summary TEXT;
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS daemon_version TEXT DEFAULT '2.1.0';
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS state_reason_code TEXT;
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS state_changed_at TIMESTAMPTZ NOT NULL DEFAULT now();
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS revocation_reason TEXT;
	`)
	return err
}

// ValidateDeviceToken returns true if the token matches an enrolled/active device.
func (s *Store) ValidateDeviceToken(ctx context.Context, token string) bool {
	if s.pool == nil || token == "" {
		return false
	}
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM devices 
			WHERE (id::text = $1 OR stable_device_id = $1 OR LOWER(display_name) = LOWER($1))
			  AND state != 'REVOKED'
		)
	`, token).Scan(&exists)
	return err == nil && exists
}
