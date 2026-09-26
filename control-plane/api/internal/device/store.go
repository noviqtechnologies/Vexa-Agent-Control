package device

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
			last_freshness VARCHAR(32) NOT NULL DEFAULT 'STALE',
			state_reason_code TEXT,
			state_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			first_enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			revoked_at TIMESTAMPTZ,
			revocation_reason TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_stable_device_id ON devices(stable_device_id);
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_freshness VARCHAR(32) NOT NULL DEFAULT 'STALE';

		CREATE TABLE IF NOT EXISTS device_compliance_reports (
			report_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES organizations(id) ON DELETE CASCADE,
			device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE UNIQUE,
			overall_compliance TEXT NOT NULL DEFAULT 'COMPLIANT',
			tamper_event_count_24h INT NOT NULL DEFAULT 0,
			mcp_servers_total INT NOT NULL DEFAULT 0,
			mcp_servers_wrapped INT NOT NULL DEFAULT 0,
			report_payload JSONB NOT NULL DEFAULT '[]'::jsonb,
			generated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE INDEX IF NOT EXISTS idx_compliance_reports_device ON device_compliance_reports(device_id);

		CREATE TABLE IF NOT EXISTS device_client_logs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES organizations(id) ON DELETE CASCADE,
			device_id TEXT NOT NULL,
			hostname TEXT NOT NULL DEFAULT '',
			user_identifier TEXT NOT NULL DEFAULT '',
			level TEXT NOT NULL DEFAULT 'error',
			event TEXT NOT NULL,
			error_code TEXT,
			message TEXT,
			origin TEXT,
			request_id TEXT,
			details JSONB NOT NULL DEFAULT '{}'::jsonb,
			logged_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE INDEX IF NOT EXISTS idx_client_logs_org_logged ON device_client_logs(organization_id, logged_at DESC);
		CREATE INDEX IF NOT EXISTS idx_client_logs_device ON device_client_logs(device_id, logged_at DESC);
		CREATE INDEX IF NOT EXISTS idx_client_logs_request ON device_client_logs(request_id);
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
				state = CASE WHEN devices.state::text = 'REVOKED' THEN devices.state ELSE 'COMPLIANT' END,
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
				state = CASE WHEN devices.state::text = 'REVOKED' THEN devices.state ELSE 'COMPLIANT' END,
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
			return nil, fmt.Errorf("device not found or not enrolled: %s", req.DeviceID)
		}
		return nil, fmt.Errorf("lookup device: %w", err)
	}

	if devState == "REVOKED" {
		return nil, fmt.Errorf("device is revoked: %s", req.DeviceID)
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
			COALESCE(NULLIF(d.stable_device_id, ''), d.id::text), 
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
		WHERE (d.organization_id::text = $1 OR d.organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
		  AND d.state != 'REVOKED'
		  AND d.revoked_at IS NULL
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
		if strings.ToUpper(stateStr) != "REVOKED" && strings.ToUpper(stateStr) != "NON_COMPLIANT" {
			if lastHb == nil || time.Since(*lastHb) > 15*time.Minute {
				w.OverallCompliance = "OFFLINE"
			}
		}

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
	if strings.ToUpper(stateStr) != "REVOKED" && strings.ToUpper(stateStr) != "NON_COMPLIANT" {
		if lastHb == nil || time.Since(*lastHb) > 15*time.Minute {
			w.OverallCompliance = "OFFLINE"
		}
	}

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
					if total > 0 && wrapped < total {
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
	if s.pool == nil {
		return &ListTamperEventsResponse{
			Events:     []DeviceTamperEventLog{},
			TotalCount: 0,
		}, nil
	}
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT 
			t.id::text AS event_id,
			t.device_id,
			COALESCE(NULLIF(d.display_name, ''), NULLIF(d.stable_device_id, ''), t.device_id) AS hostname,
			COALESCE(NULLIF(d.owner_subject, ''), 'Developer') AS user_identifier,
			COALESCE(t.target_ide, 'ide') AS ide_name,
			'CONFIG_TAMPERED' AS event_type,
			COALESCE(t.detected_diff, 'Configuration drift detected and remediated') AS tamper_details,
			(t.action_taken = 'RESTORED' OR t.action_taken = 'AUTO_HEALED' OR t.action_taken = 'remediated') AS healed_successfully,
			t.created_at AS occurred_at
		FROM device_tamper_logs t
		LEFT JOIN devices d ON (
			d.organization_id = t.organization_id
			AND (d.id::text = t.device_id OR d.stable_device_id = t.device_id OR d.display_name = t.device_id)
		)
		WHERE (t.organization_id::text = $1 OR t.organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
		ORDER BY t.created_at DESC
		LIMIT $2 OFFSET $3
	`, orgID, limit, offset)
	if err != nil {
		return &ListTamperEventsResponse{
			Events:     []DeviceTamperEventLog{},
			TotalCount: 0,
		}, nil
	}
	defer rows.Close()

	events := make([]DeviceTamperEventLog, 0)
	for rows.Next() {
		var e DeviceTamperEventLog
		if err := rows.Scan(
			&e.EventID, &e.DeviceID, &e.Hostname, &e.UserIdentifier,
			&e.IdeName, &e.EventType, &e.TamperDetails, &e.HealedSuccessfully, &e.OccurredAt,
		); err == nil {
			events = append(events, e)
		}
	}

	return &ListTamperEventsResponse{
		Events:     events,
		TotalCount: len(events),
	}, nil
}

func (s *Store) DeleteDevice(ctx context.Context, orgID, deviceID string) error {
	if s.pool == nil {
		return nil
	}
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}
	_, err := s.pool.Exec(ctx, `
		DELETE FROM devices
		WHERE (id::text = $1 OR stable_device_id = $1)
		  AND (organization_id::text = $2 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
	`, deviceID, orgID)
	return err
}

// RecordClientLogs persists batch client error and diagnostic logs from a workstation daemon
func (s *Store) RecordClientLogs(ctx context.Context, orgID, deviceID, hostname, userIdentifier string, logs []map[string]interface{}) error {
	if s.pool == nil || len(logs) == 0 {
		return nil
	}
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}

	for _, logItem := range logs {
		level, _ := logItem["level"].(string)
		if level == "" {
			level = "error"
		}
		event, _ := logItem["event"].(string)
		if event == "" {
			event = "unknown_event"
		}
		errorCode, _ := logItem["error_code"].(string)
		msg, _ := logItem["message"].(string)
		origin, _ := logItem["origin"].(string)
		reqID, _ := logItem["request_id"].(string)
		if reqID == "" {
			if r, ok := logItem["req_id"].(string); ok {
				reqID = r
			}
		}

		loggedAt := time.Now().UTC()
		if tsStr, ok := logItem["ts"].(string); ok {
			if parsed, err := time.Parse(time.RFC3339, tsStr); err == nil {
				loggedAt = parsed
			}
		}

		detailsJSON, _ := json.Marshal(logItem)

		_, _ = s.pool.Exec(ctx, `
			INSERT INTO device_client_logs (
				organization_id, device_id, hostname, user_identifier,
				level, event, error_code, message, origin, request_id, details, logged_at, created_at
			) VALUES (
				$1::uuid, $2, $3, $4,
				$5, $6, $7, $8, $9, $10, $11::jsonb, $12, now()
			)
		`, orgID, deviceID, hostname, userIdentifier, level, event, errorCode, msg, origin, reqID, detailsJSON, loggedAt)
	}
	return nil
}

// ListClientLogs retrieves diagnostic logs across all workstations in the organization
func (s *Store) ListClientLogs(ctx context.Context, orgID string, query ClientLogQuery) ([]ClientLogEntry, error) {
	if s.pool == nil {
		return []ClientLogEntry{}, nil
	}
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}
	limit := query.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	sql := `
		SELECT 
			id::text, organization_id::text, device_id, hostname, user_identifier,
			logged_at, level, event, COALESCE(error_code, ''), COALESCE(message, ''),
			COALESCE(origin, ''), COALESCE(request_id, ''), details
		FROM device_client_logs
		WHERE (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
	`
	args := []interface{}{orgID}
	argIdx := 2

	if query.DeviceID != "" {
		sql += fmt.Sprintf(" AND (device_id = $%d OR hostname ILIKE $%d)", argIdx, argIdx)
		args = append(args, query.DeviceID)
		argIdx++
	}
	if query.Level != "" && query.Level != "all" {
		sql += fmt.Sprintf(" AND LOWER(level) = LOWER($%d)", argIdx)
		args = append(args, query.Level)
		argIdx++
	}
	if query.Event != "" {
		sql += fmt.Sprintf(" AND event ILIKE $%d", argIdx)
		args = append(args, "%"+query.Event+"%")
		argIdx++
	}
	if query.RequestID != "" {
		sql += fmt.Sprintf(" AND request_id = $%d", argIdx)
		args = append(args, query.RequestID)
		argIdx++
	}
	if !query.Since.IsZero() {
		sql += fmt.Sprintf(" AND logged_at >= $%d", argIdx)
		args = append(args, query.Since)
		argIdx++
	}

	sql += fmt.Sprintf(" ORDER BY logged_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, query.Offset)

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return []ClientLogEntry{}, nil
	}
	defer rows.Close()

	entries := make([]ClientLogEntry, 0)
	for rows.Next() {
		var e ClientLogEntry
		var detailsRaw []byte
		if err := rows.Scan(
			&e.ID, &e.OrganizationID, &e.DeviceID, &e.Hostname, &e.UserIdentifier,
			&e.Timestamp, &e.Level, &e.Event, &e.ErrorCode, &e.Message,
			&e.Origin, &e.RequestID, &detailsRaw,
		); err == nil {
			if len(detailsRaw) > 0 {
				_ = json.Unmarshal(detailsRaw, &e.Details)
			}
			entries = append(entries, e)
		}
	}
	return entries, nil
}

