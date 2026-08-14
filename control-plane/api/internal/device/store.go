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
	schemaSQL := `
		CREATE TABLE IF NOT EXISTS device_enrollments (
			device_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL,
			hostname VARCHAR(255) NOT NULL,
			user_identifier VARCHAR(255) NOT NULL,
			os VARCHAR(32) NOT NULL,
			os_version VARCHAR(255) NOT NULL,
			public_key TEXT NOT NULL,
			daemon_version VARCHAR(32) NOT NULL,
			enrollment_status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',
			last_heartbeat_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT uq_device_org_host UNIQUE (organization_id, hostname, user_identifier)
		);

		CREATE TABLE IF NOT EXISTS device_compliance_reports (
			report_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			device_id UUID NOT NULL REFERENCES device_enrollments(device_id) ON DELETE CASCADE,
			organization_id UUID NOT NULL,
			overall_compliance VARCHAR(32) NOT NULL,
			tamper_event_count_24h INT NOT NULL DEFAULT 0,
			report_payload JSONB NOT NULL,
			reported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT uq_device_compliance UNIQUE (device_id)
		);

		CREATE TABLE IF NOT EXISTS device_ide_status (
			status_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			device_id UUID NOT NULL REFERENCES device_enrollments(device_id) ON DELETE CASCADE,
			ide_name VARCHAR(64) NOT NULL,
			is_installed BOOLEAN NOT NULL DEFAULT false,
			config_path TEXT NOT NULL,
			proxy_configured BOOLEAN NOT NULL DEFAULT false,
			configured_base_url TEXT,
			mcp_wrapped BOOLEAN NOT NULL DEFAULT false,
			compliance_state VARCHAR(32) NOT NULL,
			last_healed_at TIMESTAMPTZ,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT uq_device_ide UNIQUE (device_id, ide_name)
		);

		CREATE TABLE IF NOT EXISTS device_tamper_events (
			event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			device_id UUID NOT NULL REFERENCES device_enrollments(device_id) ON DELETE CASCADE,
			organization_id UUID NOT NULL,
			ide_name VARCHAR(64) NOT NULL,
			event_type VARCHAR(64) NOT NULL,
			tamper_details TEXT NOT NULL,
			healed_successfully BOOLEAN NOT NULL DEFAULT true,
			occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
	`
	_, err := s.pool.Exec(ctx, schemaSQL)
	return err
}

func generateToken(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

// EnrollDevice registers or updates a workstation enrollment
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
	err := s.pool.QueryRow(ctx, `
		INSERT INTO device_enrollments (
			organization_id, hostname, user_identifier, os, os_version,
			public_key, daemon_version, enrollment_status, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 'ACTIVE', now())
		ON CONFLICT (organization_id, hostname, user_identifier)
		DO UPDATE SET 
			os = EXCLUDED.os,
			os_version = EXCLUDED.os_version,
			public_key = EXCLUDED.public_key,
			daemon_version = EXCLUDED.daemon_version,
			enrollment_status = 'ACTIVE',
			updated_at = now()
		RETURNING device_id, created_at
	`, orgID, req.Hostname, req.UserIdentifier, req.OS, req.OSVersion, req.PublicKey, req.DaemonVersion).
		Scan(&deviceID, &createdAt)

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

	// 1. Verify device exists and is ACTIVE
	var status string
	var registeredOrgID string
	err = tx.QueryRow(ctx, `
		SELECT enrollment_status, organization_id FROM device_enrollments WHERE device_id = $1
	`, req.DeviceID).Scan(&status, &registeredOrgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("device not found")
		}
		return nil, err
	}

	if status != "ACTIVE" {
		return nil, errors.New("device enrollment is not active")
	}

	now := time.Now().UTC()

	// 2. Update device last heartbeat
	_, err = tx.Exec(ctx, `
		UPDATE device_enrollments SET last_heartbeat_at = $1, updated_at = $1 WHERE device_id = $2
	`, now, req.DeviceID)
	if err != nil {
		return nil, err
	}

	// 3. Upsert compliance report snapshot
	reportPayloadJSON, _ := json.Marshal(req)
	_, err = tx.Exec(ctx, `
		INSERT INTO device_compliance_reports (
			device_id, organization_id, overall_compliance, tamper_event_count_24h, report_payload, reported_at
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (device_id)
		DO UPDATE SET
			overall_compliance = EXCLUDED.overall_compliance,
			tamper_event_count_24h = device_compliance_reports.tamper_event_count_24h + EXCLUDED.tamper_event_count_24h,
			report_payload = EXCLUDED.report_payload,
			reported_at = EXCLUDED.reported_at
	`, req.DeviceID, registeredOrgID, req.OverallCompliance, len(req.TamperEvents), reportPayloadJSON, now)
	if err != nil {
		return nil, err
	}

	// 4. Upsert per-IDE configuration statuses
	for _, ide := range req.IdeTargets {
		_, err = tx.Exec(ctx, `
			INSERT INTO device_ide_status (
				device_id, ide_name, is_installed, config_path, proxy_configured,
				configured_base_url, mcp_wrapped, compliance_state, last_healed_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (device_id, ide_name)
			DO UPDATE SET
				is_installed = EXCLUDED.is_installed,
				config_path = EXCLUDED.config_path,
				proxy_configured = EXCLUDED.proxy_configured,
				configured_base_url = EXCLUDED.configured_base_url,
				mcp_wrapped = EXCLUDED.mcp_wrapped,
				compliance_state = EXCLUDED.compliance_state,
				last_healed_at = COALESCE(EXCLUDED.last_healed_at, device_ide_status.last_healed_at),
				updated_at = EXCLUDED.updated_at
		`, req.DeviceID, ide.Name, ide.Installed, ide.ConfigPath, ide.ProxyConfigured,
			ide.ConfiguredBaseURL, ide.McpWrapped, ide.ComplianceState, ide.LastHealedAt, now)
		if err != nil {
			return nil, err
		}
	}

	// 5. Insert tamper events into immutable log
	for _, te := range req.TamperEvents {
		eventOccurred := te.OccurredAt
		if eventOccurred.IsZero() {
			eventOccurred = now
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO device_tamper_events (
				device_id, organization_id, ide_name, event_type, tamper_details, healed_successfully, occurred_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, req.DeviceID, registeredOrgID, te.IdeName, te.EventType, te.TamperDetails, te.HealedSuccessfully, eventOccurred)
		if err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit telemetry: %w", err)
	}

	return &TelemetryHeartbeatResponse{
		Acknowledged:                 true,
		NextHeartbeatIntervalSeconds: 60,
		PolicyVersion:                "v1.2.0",
	}, nil
}

// ListDevices returns all registered devices and compliance statistics
func (s *Store) ListDevices(ctx context.Context, orgID string, filter string, limit, offset int) (*ListDevicesResponse, error) {
	if s.pool == nil {
		return nil, errors.New("database pool uninitialized")
	}
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	rows, err := s.pool.Query(ctx, `
		SELECT 
			d.device_id, d.hostname, d.user_identifier, d.os, d.os_version,
			d.enrollment_status, d.last_heartbeat_at,
			COALESCE(c.overall_compliance, 'OFFLINE') as overall_compliance,
			COALESCE(c.tamper_event_count_24h, 0) as tamper_count_24h
		FROM device_enrollments d
		LEFT JOIN device_compliance_reports c ON d.device_id = c.device_id
		WHERE d.organization_id = $1
		ORDER BY d.last_heartbeat_at DESC NULLS LAST, d.created_at DESC
		LIMIT $2 OFFSET $3
	`, orgID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}
	defer rows.Close()

	var summaries []DeviceComplianceSummary
	compliantCount := 0
	nonCompliantCount := 0
	offlineCount := 0

	for rows.Next() {
		var item DeviceComplianceSummary
		var lastHeartbeat *time.Time
		if err := rows.Scan(
			&item.DeviceID, &item.Hostname, &item.UserIdentifier, &item.OS, &item.OSVersion,
			&item.EnrollmentStatus, &lastHeartbeat, &item.OverallCompliance, &item.TamperCount24h,
		); err != nil {
			return nil, err
		}
		item.LastHeartbeatAt = lastHeartbeat

		// Check if heartbeat is stale (> 3 minutes = OFFLINE)
		if lastHeartbeat == nil || time.Since(*lastHeartbeat) > 3*time.Minute {
			item.OverallCompliance = ComplianceStateOffline
		}

		switch item.OverallCompliance {
		case ComplianceStateCompliant:
			compliantCount++
		case ComplianceStateNonCompliant:
			nonCompliantCount++
		default:
			offlineCount++
		}

		// Retrieve active IDE list for this device
		item.ActiveIDEs = []string{}
		ideRows, ideErr := s.pool.Query(ctx, `
			SELECT ide_name FROM device_ide_status WHERE device_id = $1 AND is_installed = true
		`, item.DeviceID)
		if ideErr == nil {
			for ideRows.Next() {
				var name string
				if err := ideRows.Scan(&name); err == nil {
					item.ActiveIDEs = append(item.ActiveIDEs, name)
				}
			}
			ideRows.Close()
		}

		summaries = append(summaries, item)
	}

	return &ListDevicesResponse{
		Devices:           summaries,
		TotalCount:        len(summaries),
		CompliantCount:    compliantCount,
		NonCompliantCount: nonCompliantCount,
		OfflineCount:      offlineCount,
	}, nil
}

// ListTamperEvents returns recent tampering and auto-healing events across the fleet
func (s *Store) ListTamperEvents(ctx context.Context, orgID string, limit, offset int) (*ListTamperEventsResponse, error) {
	if s.pool == nil {
		return nil, errors.New("database pool uninitialized")
	}
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	rows, err := s.pool.Query(ctx, `
		SELECT 
			e.event_id, e.device_id, d.hostname, d.user_identifier,
			e.ide_name, e.event_type, e.tamper_details, e.healed_successfully, e.occurred_at
		FROM device_tamper_events e
		JOIN device_enrollments d ON e.device_id = d.device_id
		WHERE e.organization_id = $1
		ORDER BY e.occurred_at DESC
		LIMIT $2 OFFSET $3
	`, orgID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list tamper events: %w", err)
	}
	defer rows.Close()

	var events []DeviceTamperEventLog
	for rows.Next() {
		var log DeviceTamperEventLog
		if err := rows.Scan(
			&log.EventID, &log.DeviceID, &log.Hostname, &log.UserIdentifier,
			&log.IdeName, &log.EventType, &log.TamperDetails, &log.HealedSuccessfully, &log.OccurredAt,
		); err != nil {
			return nil, err
		}
		events = append(events, log)
	}

	return &ListTamperEventsResponse{
		Events:     events,
		TotalCount: len(events),
	}, nil
}
