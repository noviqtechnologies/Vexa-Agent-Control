package device

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) EnsureSchema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}

	_, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS devices (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES organizations(id) ON DELETE CASCADE,
			team_id TEXT NOT NULL DEFAULT 'default',
			stable_device_id TEXT NOT NULL DEFAULT '',
			display_name TEXT NOT NULL DEFAULT '',
			owner_subject TEXT,
			os_family TEXT NOT NULL DEFAULT 'windows',
			architecture TEXT NOT NULL DEFAULT 'x86_64',
			os_version_summary TEXT,
			daemon_version TEXT DEFAULT '2.1.0',
			public_key TEXT,
			state VARCHAR(32) NOT NULL DEFAULT 'PENDING',
			state_reason_code TEXT,
			state_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			first_enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			revoked_at TIMESTAMPTZ,
			revocation_reason TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
	`)
	return err
}

func generateToken(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

// EnrollDevice registers or updates a workstation in the devices table
func (s *Store) EnrollDevice(ctx context.Context, orgID string, req *EnrollDeviceRequest) (*EnrollDeviceResponse, error) {
	if s.pool == nil {
		return nil, errors.New("database pool uninitialized")
	}
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}
	if req.Hostname == "" {
		return nil, errors.New("hostname is required")
	}
	if req.UserIdentifier == "" {
		req.UserIdentifier = "default-developer"
	}
	if req.OS == "" {
		req.OS = "windows"
	}
	if req.DaemonVersion == "" {
		req.DaemonVersion = "2.1.0"
	}

	var deviceID string
	var createdAt time.Time
	var existingID string
	err := s.pool.QueryRow(ctx, `
		SELECT id::text FROM devices 
		WHERE (organization_id = $1::uuid OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
		  AND (stable_device_id = $2 OR LOWER(display_name) = LOWER($2))
		ORDER BY last_heartbeat_at DESC NULLS LAST
		LIMIT 1
	`, orgID, req.Hostname).Scan(&existingID)

	if err == nil && existingID != "" {
		err = s.pool.QueryRow(ctx, `
			UPDATE devices SET
				display_name = $2,
				owner_subject = COALESCE(NULLIF($3, ''), devices.owner_subject),
				os_family = $4,
				os_version_summary = $5,
				public_key = COALESCE(NULLIF($6, ''), devices.public_key),
				daemon_version = $7,
				state = CASE WHEN devices.state::text = 'REVOKED' THEN devices.state ELSE 'COMPLIANT'::device_state END,
				last_heartbeat_at = now(),
				updated_at = now()
			WHERE id::text = $1
			RETURNING id::text, created_at
		`, existingID, req.Hostname, req.UserIdentifier, req.OS, req.OSVersion, req.PublicKey, req.DaemonVersion).
			Scan(&deviceID, &createdAt)
	} else {
		err = s.pool.QueryRow(ctx, `
			INSERT INTO devices (
				organization_id, stable_device_id, display_name, owner_subject,
				os_family, architecture, os_version_summary, public_key, daemon_version, state, state_changed_at, updated_at
			) VALUES ($1, $2, $2, $3, $4, 'x86_64', $5, $6, $7, 'COMPLIANT', now(), now())
			ON CONFLICT (stable_device_id)
			DO UPDATE SET 
				display_name = EXCLUDED.display_name,
				owner_subject = COALESCE(NULLIF(EXCLUDED.owner_subject, ''), devices.owner_subject),
				os_family = EXCLUDED.os_family,
				os_version_summary = EXCLUDED.os_version_summary,
				public_key = COALESCE(NULLIF(EXCLUDED.public_key, ''), devices.public_key),
				daemon_version = EXCLUDED.daemon_version,
				state = CASE WHEN devices.state::text = 'REVOKED' THEN devices.state ELSE 'COMPLIANT'::device_state END,
				last_heartbeat_at = now(),
				updated_at = now()
			RETURNING id::text, created_at
		`, orgID, req.Hostname, req.UserIdentifier, req.OS, req.OSVersion, req.PublicKey, req.DaemonVersion).
			Scan(&deviceID, &createdAt)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to enroll device: %w", err)
	}

	localToken := generateToken("otet_dev")

	return &EnrollDeviceResponse{
		DeviceID:        deviceID,
		OrganizationID:  orgID,
		Status:          "ACTIVE",
		LocalProxyToken: localToken,
		EnrolledAt:      createdAt,
	}, nil
}

// RecordTelemetry records incoming 60s heartbeat telemetry from a workstation
func (s *Store) RecordTelemetry(ctx context.Context, orgID string, req *TelemetryHeartbeatRequest) (*TelemetryHeartbeatResponse, error) {
	if s.pool == nil {
		return nil, errors.New("database pool uninitialized")
	}
	if req.DeviceID == "" {
		return nil, errors.New("device_id is required")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin telemetry transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var canonicalDeviceID string
	var registeredOrgID string
	var devState string
	var devHostname string

	err = tx.QueryRow(ctx, `
		SELECT id::text, organization_id::text, state::text, COALESCE(stable_device_id, display_name, id::text)
		FROM devices
		WHERE id::text = $1 
		   OR stable_device_id = $1 
		   OR LOWER(stable_device_id) = LOWER($1)
		   OR LOWER(display_name) = LOWER($1)
		   OR $1 ILIKE '%' || display_name || '%'
		   OR $1 ILIKE '%' || stable_device_id || '%'
		   OR display_name ILIKE '%' || $1 || '%'
		   OR stable_device_id ILIKE '%' || $1 || '%'
		LIMIT 1
	`, req.DeviceID).Scan(&canonicalDeviceID, &registeredOrgID, &devState, &devHostname)

	targetState := "COMPLIANT"
	if req.OverallCompliance == "NON_COMPLIANT" || len(req.TamperEvents) > 0 {
		targetState = "NON_COMPLIANT"
	}

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			if orgID == "" {
				orgID = "00000000-0000-0000-0000-000000000001"
			}
			err = tx.QueryRow(ctx, `
				INSERT INTO devices (
					organization_id, stable_device_id, display_name, owner_subject,
					os_family, architecture, os_version_summary, daemon_version,
					state, state_reason_code, state_changed_at, first_enrolled_at, last_heartbeat_at
				) VALUES ($1, $2, $2, 'Developer Workstation', 'windows', 'x86_64', 'v1.0', '2.1.0', $3, 'HEARTBEAT_PROVISIONED', now(), now(), now())
				RETURNING id::text, state::text, stable_device_id
			`, orgID, req.DeviceID, targetState).
				Scan(&canonicalDeviceID, &devState, &devHostname)
			if err != nil {
				return nil, fmt.Errorf("auto-provision device: %w", err)
			}
		} else {
			return nil, fmt.Errorf("lookup device: %w", err)
		}
	} else {
		if devState == "REVOKED" {
			targetState = "REVOKED"
		}
		_, err = tx.Exec(ctx, `
			UPDATE devices 
			SET last_heartbeat_at = now(),
			    state = $2,
			    updated_at = now()
			WHERE id::text = $1
		`, canonicalDeviceID, targetState)
		if err != nil {
			return nil, fmt.Errorf("update device heartbeat: %w", err)
		}
	}

	for _, tEvent := range req.TamperEvents {
		_, _ = tx.Exec(ctx, `
			INSERT INTO device_tamper_logs (organization_id, device_id, target_ide, detected_diff, action_taken, created_at)
			VALUES ($1, $2, $3, $4, $5, now())
		`, orgID, canonicalDeviceID, tEvent.IdeName, tEvent.TamperDetails, "HEALED_RESTORED_PROXY")
	}

	if payloadBytes, err := json.Marshal(req.IdeTargets); err == nil {
		_, _ = tx.Exec(ctx, `
			INSERT INTO device_compliance_reports (
				organization_id, device_id, overall_compliance, tamper_event_count_24h,
				mcp_servers_total, mcp_servers_wrapped, report_payload, reported_at
			) VALUES ($1, $2::uuid, $3, $4, $5, $6, $7::jsonb, now())
			ON CONFLICT (device_id) DO UPDATE SET
				overall_compliance = EXCLUDED.overall_compliance,
				tamper_event_count_24h = EXCLUDED.tamper_event_count_24h,
				mcp_servers_total = EXCLUDED.mcp_servers_total,
				mcp_servers_wrapped = EXCLUDED.mcp_servers_wrapped,
				report_payload = EXCLUDED.report_payload,
				reported_at = now()
		`, orgID, canonicalDeviceID, targetState, len(req.TamperEvents), len(req.IdeTargets), len(req.IdeTargets), string(payloadBytes))
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit telemetry: %w", err)
	}

	return &TelemetryHeartbeatResponse{
		Acknowledged:                 true,
		NextHeartbeatIntervalSeconds: 60,
		PolicyVersion:                "v1.0.0",
	}, nil
}

func (s *Store) ListDevices(ctx context.Context, orgID string) ([]DeviceComplianceSummary, error) {
	if s.pool == nil {
		return []DeviceComplianceSummary{}, nil
	}
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT 
			d.id::text, 
			COALESCE(NULLIF(d.display_name, ''), d.stable_device_id, d.id::text), 
			COALESCE(d.owner_subject, 'Developer'), 
			d.os_family, 
			COALESCE(d.os_version_summary, 'v1.0'), 
			d.state::text, 
			d.first_enrolled_at, 
			d.last_heartbeat_at,
			COALESCE(r.report_payload, '[]'::jsonb),
			COALESCE(r.tamper_event_count_24h, 0)
		FROM devices d
		LEFT JOIN device_compliance_reports r ON r.device_id = d.id
		WHERE d.organization_id::text = $1 OR d.organization_id = '00000000-0000-0000-0000-000000000001'::uuid
		ORDER BY d.last_heartbeat_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []DeviceComplianceSummary
	for rows.Next() {
		var w DeviceComplianceSummary
		var stateStr string
		var firstEnroll time.Time
		var lastHb *time.Time
		var rawPayload []byte
		var tamperCount int
		if err := rows.Scan(&w.DeviceID, &w.Hostname, &w.UserIdentifier, &w.OS, &w.OSVersion, &stateStr, &firstEnroll, &lastHb, &rawPayload, &tamperCount); err != nil {
			return nil, err
		}
		w.OverallCompliance = stateStr
		w.EnrollmentStatus = stateStr
		w.LastHeartbeatAt = lastHb
		w.TamperCount24h = tamperCount

		activeMap := make(map[string]bool)
		if len(rawPayload) > 0 {
			var targets []IdeTargetStatus
			if err := json.Unmarshal(rawPayload, &targets); err == nil {
				for _, t := range targets {
					if t.Installed || t.McpWrapped || t.ProxyConfigured || t.ComplianceState == "COMPLIANT" {
						activeMap[t.Name] = true
					}
				}
			}
		}

		// Also discover any protected IDEs from mcp_servers table
		mcpRows, err := s.pool.Query(ctx, `
			SELECT DISTINCT ide_target 
			FROM mcp_servers 
			WHERE (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
			  AND (agent_id = $2 OR agent_id = $3 OR agent_id = $4)
		`, orgID, w.DeviceID, w.Hostname, w.UserIdentifier)
		if err == nil {
			for mcpRows.Next() {
				var ideName string
				if err := mcpRows.Scan(&ideName); err == nil && ideName != "" {
					activeMap[ideName] = true
				}
			}
			mcpRows.Close()
		}

		var activeIDEs []string
		for ide := range activeMap {
			activeIDEs = append(activeIDEs, ide)
		}
		if activeIDEs == nil {
			activeIDEs = []string{}
		}
		w.ActiveIDEs = activeIDEs
		list = append(list, w)
	}
	return list, rows.Err()
}

func (s *Store) GetDevice(ctx context.Context, orgID, deviceID string) (*DeviceDetailResponse, error) {
	if s.pool == nil {
		return nil, errors.New("database uninitialized")
	}
	var w DeviceDetailResponse
	var stateStr string
	var lastHb *time.Time
	var created, updated time.Time
	var rawPayload []byte
	var tamperCount int
	var deviceUUID string

	err := s.pool.QueryRow(ctx, `
		SELECT 
			d.id::text, 
			d.organization_id::text, 
			COALESCE(d.stable_device_id, d.display_name, d.id::text), 
			COALESCE(d.owner_subject, 'Developer'), 
			d.os_family, 
			COALESCE(d.os_version_summary, 'v1.0'), 
			d.state::text, 
			d.created_at,
			d.updated_at,
			d.last_heartbeat_at,
			COALESCE(r.report_payload, '[]'::jsonb),
			COALESCE(r.tamper_event_count_24h, 0)
		FROM devices d
		LEFT JOIN device_compliance_reports r ON r.device_id = d.id
	WHERE (
		d.id::text = $1 
		OR d.stable_device_id = $1 
		OR LOWER(d.stable_device_id) = LOWER($1)
		OR LOWER(d.display_name) = LOWER($1)
		OR $1 ILIKE '%' || d.display_name || '%'
		OR $1 ILIKE '%' || d.stable_device_id || '%'
		OR d.display_name ILIKE '%' || $1 || '%'
		OR d.stable_device_id ILIKE '%' || $1 || '%'
	)
		LIMIT 1
	`, deviceID).Scan(&deviceUUID, &w.OrganizationID, &w.Hostname, &w.UserIdentifier, &w.OS, &w.OSVersion, &stateStr, &created, &updated, &lastHb, &rawPayload, &tamperCount)
	if err != nil {
		return nil, err
	}
	w.DeviceID = deviceUUID
	w.OverallCompliance = stateStr
	w.EnrollmentStatus = stateStr
	w.LastHeartbeatAt = lastHb
	w.CreatedAt = created
	w.UpdatedAt = updated
	w.TamperCount24h = tamperCount

	var statuses []IdeTargetStatus
	if len(rawPayload) > 0 {
		var allStatuses []IdeTargetStatus
		if err := json.Unmarshal(rawPayload, &allStatuses); err == nil {
			for _, st := range allStatuses {
				if st.Installed || st.McpWrapped || st.ProxyConfigured || st.ComplianceState == "COMPLIANT" {
					statuses = append(statuses, st)
				}
			}
		}
	}

	if len(statuses) == 0 {
		mcpRows, err := s.pool.Query(ctx, `
			SELECT ide_target, COUNT(*), COUNT(*) FILTER (WHERE wrapped = true)
			FROM mcp_servers
			WHERE (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
			  AND (agent_id = $2 OR agent_id = $3)
			GROUP BY ide_target
		`, w.OrganizationID, deviceUUID, w.Hostname)
		if err == nil {
			for mcpRows.Next() {
				var target string
				var total, wrapped int
				if err := mcpRows.Scan(&target, &total, &wrapped); err == nil {
					compliance := "COMPLIANT"
					if wrapped < total {
						compliance = "NON_COMPLIANT"
					}
					statuses = append(statuses, IdeTargetStatus{
						Name:            target,
						Installed:       true,
						ProxyConfigured: true,
						McpWrapped:      wrapped > 0,
						ComplianceState: compliance,
					})
				}
			}
			mcpRows.Close()
		}
	}

	if statuses == nil {
		statuses = []IdeTargetStatus{}
	}
	w.IdeStatuses = statuses
	w.RecentTamperEvents = []DeviceTamperEventLog{}
	return &w, nil
}

func (s *Store) ListTamperEvents(ctx context.Context, orgID string, limit, offset int) (*ListTamperEventsResponse, error) {
	return &ListTamperEventsResponse{
		Events:     []DeviceTamperEventLog{},
		TotalCount: 0,
	}, nil
}
