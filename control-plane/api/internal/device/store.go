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
	var canonicalDeviceID string = req.DeviceID
	var devHostname string

	err = tx.QueryRow(ctx, `
		SELECT device_id::text, enrollment_status, organization_id::text, hostname 
		FROM device_enrollments 
		WHERE device_id::text = $1 OR hostname = $1
		ORDER BY CASE WHEN user_identifier != 'Developer Workstation' AND user_identifier != '' THEN 0 ELSE 1 END, last_heartbeat_at DESC NULLS LAST
		LIMIT 1
	`, req.DeviceID).Scan(&canonicalDeviceID, &status, &registeredOrgID, &devHostname)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Fallback: check if registered in devices table
			var devTenantID string
			var devState string
			var devOS string
			var devArch string
			var devDisplayName string
			devErr := tx.QueryRow(ctx, `
				SELECT id::text, tenant_id::text, state::text, COALESCE(stable_device_id, id::text), COALESCE(os_family, 'windows'), COALESCE(architecture, 'x86_64'), COALESCE(owner_subject, display_name, 'Developer Workstation')
				FROM devices
				WHERE id::text = $1 OR stable_device_id = $1
				LIMIT 1
			`, req.DeviceID).Scan(&canonicalDeviceID, &devTenantID, &devState, &devHostname, &devOS, &devArch, &devDisplayName)

			if devErr != nil {
				if errors.Is(devErr, pgx.ErrNoRows) {
					return nil, errors.New("device not found")
				}
				return nil, devErr
			}

			if devState == "REVOKED" {
				return nil, errors.New("device enrollment is not active")
			}

			status = "ACTIVE"
			registeredOrgID = devTenantID
			if registeredOrgID == "" {
				registeredOrgID = "00000000-0000-0000-0000-000000000001"
			}

			// Ensure entry in device_enrollments exists so FK constraints succeed
			var existingEnrollmentID string
			errLookup := tx.QueryRow(ctx, `
				SELECT device_id::text 
				FROM device_enrollments 
				WHERE (organization_id = $1 AND hostname = $2) OR device_id::text = $3 
				LIMIT 1
			`, registeredOrgID, devHostname, canonicalDeviceID).Scan(&existingEnrollmentID)

			if errLookup == nil && existingEnrollmentID != "" {
				canonicalDeviceID = existingEnrollmentID
			} else {
				_, err = tx.Exec(ctx, `
					INSERT INTO device_enrollments (
						device_id, organization_id, hostname, user_identifier, os, os_version,
						public_key, daemon_version, enrollment_status, last_heartbeat_at, created_at, updated_at
					) VALUES ($1, $2, $3, $4, $5, $6, '', '2.1.0', 'ACTIVE', now(), now(), now())
					ON CONFLICT (device_id) DO UPDATE SET last_heartbeat_at = now(), updated_at = now()
				`, canonicalDeviceID, registeredOrgID, devHostname, devDisplayName, devOS, devArch)
				if err != nil {
					_ = tx.QueryRow(ctx, `SELECT device_id::text FROM device_enrollments WHERE organization_id = $1 AND hostname = $2 LIMIT 1`, registeredOrgID, devHostname).Scan(&canonicalDeviceID)
				}
			}
		} else {
			return nil, err
		}
	}

	if status != "ACTIVE" {
		return nil, errors.New("device enrollment is not active")
	}

	now := time.Now().UTC()

	// 2. Update device last heartbeat across device_enrollments and devices
	_, err = tx.Exec(ctx, `
		UPDATE device_enrollments SET last_heartbeat_at = $1, updated_at = $1 WHERE device_id::text = $2
	`, now, canonicalDeviceID)
	if err != nil {
		return nil, err
	}

	_, _ = tx.Exec(ctx, `
		UPDATE devices 
		SET last_heartbeat_at = $1, state = 'COMPLIANT'::device_state, updated_at = $1 
		WHERE (id::text = $2 OR stable_device_id = $3) AND state != 'REVOKED'
	`, now, canonicalDeviceID, devHostname)
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
	`, canonicalDeviceID, registeredOrgID, req.OverallCompliance, len(req.TamperEvents), reportPayloadJSON, now)
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
		`, canonicalDeviceID, ide.Name, ide.Installed, ide.ConfigPath, ide.ProxyConfigured,
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
		`, canonicalDeviceID, registeredOrgID, te.IdeName, te.EventType, te.TamperDetails, te.HealedSuccessfully, eventOccurred)
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
		WITH deduped_enrollments AS (
			SELECT DISTINCT ON (organization_id, hostname)
				device_id, organization_id, hostname, user_identifier, os, os_version,
				public_key, daemon_version, enrollment_status, last_heartbeat_at, created_at, updated_at
			FROM device_enrollments
			WHERE ($1 = '' OR organization_id::text = $1)
			ORDER BY organization_id, hostname,
				CASE WHEN user_identifier != 'Developer Workstation' AND user_identifier != '' THEN 0 ELSE 1 END,
				last_heartbeat_at DESC NULLS LAST
		),
		deduped_devices AS (
			SELECT DISTINCT ON (tenant_id, COALESCE(stable_device_id, id::text))
				id, tenant_id, COALESCE(stable_device_id, id::text) AS hostname,
				display_name, owner_subject, os_family, architecture, os_version_summary,
				state, first_enrolled_at, last_heartbeat_at, created_at, updated_at
			FROM devices
			WHERE ($1 = '' OR tenant_id::text = $1)
			ORDER BY tenant_id, COALESCE(stable_device_id, id::text),
				last_heartbeat_at DESC NULLS LAST
		),
		unified AS (
			SELECT 
				COALESCE(de.device_id::text, d.id::text) AS device_id,
				COALESCE(de.hostname, d.hostname) AS hostname,
				COALESCE(
					NULLIF(de.user_identifier, 'Developer Workstation'),
					NULLIF(d.owner_subject, ''),
					NULLIF(d.display_name, ''),
					de.user_identifier,
					'Developer Workstation'
				) AS user_identifier,
				COALESCE(de.os, d.os_family, 'windows') AS os,
				COALESCE(de.os_version, d.os_version_summary, 'v1.0.35') AS os_version,
				COALESCE(de.enrollment_status, d.state::text, 'ACTIVE') AS enrollment_status,
				COALESCE(de.last_heartbeat_at, d.last_heartbeat_at) AS last_heartbeat_at,
				d.state AS dev_state,
				de.device_id AS de_device_id,
				d.id AS dev_id
			FROM deduped_devices d
			FULL OUTER JOIN deduped_enrollments de 
			  ON de.hostname = d.hostname OR de.device_id = d.id
		)
		SELECT 
			u.device_id,
			u.hostname,
			u.user_identifier,
			u.os,
			u.os_version,
			u.enrollment_status,
			u.last_heartbeat_at,
			CASE
				WHEN COALESCE(u.dev_state::text, u.enrollment_status) = 'REVOKED' THEN 'NON_COMPLIANT'
				WHEN c.overall_compliance IS NOT NULL THEN c.overall_compliance
				WHEN COALESCE(u.dev_state::text, u.enrollment_status) = 'PENDING' THEN 'OFFLINE'
				WHEN u.last_heartbeat_at IS NULL THEN 'OFFLINE'
				WHEN u.last_heartbeat_at < NOW() - INTERVAL '3 minutes' THEN 'OFFLINE'
				ELSE 'COMPLIANT'
			END AS overall_compliance,
			COALESCE(c.tamper_event_count_24h, 0) AS tamper_count_24h
		FROM unified u
		LEFT JOIN device_compliance_reports c 
		  ON (c.device_id = u.de_device_id OR c.device_id = u.dev_id)
		ORDER BY u.last_heartbeat_at DESC NULLS LAST
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

		// Retrieve active IDE list for this device (unified across linked device_id and hostname)
		item.ActiveIDEs = []string{}
		ideRows, ideErr := s.pool.Query(ctx, `
			SELECT DISTINCT ide_name FROM device_ide_status 
			WHERE (device_id::text = $1 OR device_id IN (SELECT de.device_id FROM device_enrollments de WHERE de.hostname = $2)) 
			  AND is_installed = true
			ORDER BY ide_name ASC
		`, item.DeviceID, item.Hostname)
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

// GetDevice retrieves complete granular device details, per-IDE configuration states, and recent tamper logs
func (s *Store) GetDevice(ctx context.Context, orgID, deviceID string) (*DeviceDetailResponse, error) {
	if s.pool == nil {
		return nil, errors.New("database pool uninitialized")
	}
	if deviceID == "" {
		return nil, errors.New("device_id is required")
	}
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}

	detail := &DeviceDetailResponse{
		IdeStatuses:        []IdeTargetStatus{},
		RecentTamperEvents: []DeviceTamperEventLog{},
	}

	// 1. Query unified device information
	var lastHeartbeat *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT 
			COALESCE(de.device_id::text, d.id::text, $1),
			COALESCE(de.organization_id::text, d.tenant_id::text, $2),
			COALESCE(de.hostname, d.stable_device_id, d.id::text, $1),
			COALESCE(
				NULLIF(de.user_identifier, 'Developer Workstation'),
				NULLIF(d.owner_subject, ''),
				NULLIF(d.display_name, ''),
				de.user_identifier,
				'Developer Workstation'
			),
			COALESCE(de.os, d.os_family, 'windows'),
			COALESCE(de.os_version, d.os_version_summary, 'v1.0.35'),
			COALESCE(de.public_key, ''),
			COALESCE(de.daemon_version, '2.1.0'),
			COALESCE(de.enrollment_status, d.state::text, 'ACTIVE'),
			COALESCE(de.last_heartbeat_at, d.last_heartbeat_at),
			COALESCE(de.created_at, d.created_at, now()),
			COALESCE(de.updated_at, d.updated_at, now())
		FROM (
			SELECT id, tenant_id, stable_device_id, display_name, owner_subject, os_family, os_version_summary, state, last_heartbeat_at, created_at, updated_at
			FROM devices
			WHERE (id::text = $1 OR stable_device_id = $1)
			  AND ($2 = '' OR tenant_id::text = $2)
			LIMIT 1
		) d
		FULL OUTER JOIN (
			SELECT device_id, organization_id, hostname, user_identifier, os, os_version, public_key, daemon_version, enrollment_status, last_heartbeat_at, created_at, updated_at
			FROM device_enrollments
			WHERE (device_id::text = $1 OR hostname = $1)
			  AND ($2 = '' OR organization_id::text = $2)
			ORDER BY CASE WHEN user_identifier != 'Developer Workstation' AND user_identifier != '' THEN 0 ELSE 1 END, last_heartbeat_at DESC NULLS LAST
			LIMIT 1
		) de ON de.hostname = d.stable_device_id OR de.device_id = d.id
	`, deviceID, orgID).Scan(
		&detail.DeviceID, &detail.OrganizationID, &detail.Hostname, &detail.UserIdentifier,
		&detail.OS, &detail.OSVersion, &detail.PublicKey, &detail.DaemonVersion,
		&detail.EnrollmentStatus, &lastHeartbeat, &detail.CreatedAt, &detail.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}
	detail.LastHeartbeatAt = lastHeartbeat

	// 2. Fetch compliance report snapshot
	var payload []byte
	compErr := s.pool.QueryRow(ctx, `
		SELECT overall_compliance, tamper_event_count_24h, report_payload::text
		FROM device_compliance_reports
		WHERE device_id::text = $1 
		   OR device_id IN (SELECT de.device_id FROM device_enrollments de WHERE de.hostname = $2 OR de.device_id::text = $1)
		ORDER BY reported_at DESC
		LIMIT 1
	`, detail.DeviceID, detail.Hostname).Scan(&detail.OverallCompliance, &detail.TamperCount24h, &payload)
	if compErr == nil {
		detail.ReportPayload = string(payload)
	}

	// Calculate overall compliance posture based on heartbeat recency
	if detail.OverallCompliance == "" {
		detail.OverallCompliance = ComplianceStateCompliant
	}
	if lastHeartbeat == nil || time.Since(*lastHeartbeat) > 3*time.Minute {
		detail.OverallCompliance = ComplianceStateOffline
	}
	if detail.EnrollmentStatus == EnrollmentStatusRevoked {
		detail.OverallCompliance = ComplianceStateNonCompliant
	}

	// 3. Fetch all IDE configuration states
	ideRows, ideErr := s.pool.Query(ctx, `
		SELECT DISTINCT ON (ide_name)
			ide_name, is_installed, config_path, proxy_configured,
			COALESCE(configured_base_url, ''), mcp_wrapped, compliance_state, last_healed_at
		FROM device_ide_status
		WHERE device_id::text = $1 
		   OR device_id IN (SELECT de.device_id FROM device_enrollments de WHERE de.hostname = $2 OR de.device_id::text = $1)
		ORDER BY ide_name ASC, updated_at DESC
	`, detail.DeviceID, detail.Hostname)
	if ideErr == nil {
		defer ideRows.Close()
		for ideRows.Next() {
			var ide IdeTargetStatus
			if err := ideRows.Scan(
				&ide.Name, &ide.Installed, &ide.ConfigPath, &ide.ProxyConfigured,
				&ide.ConfiguredBaseURL, &ide.McpWrapped, &ide.ComplianceState, &ide.LastHealedAt,
			); err == nil {
				detail.IdeStatuses = append(detail.IdeStatuses, ide)
			}
		}
	}

	// 4. Fetch recent tamper events for this device
	tamperRows, tamperErr := s.pool.Query(ctx, `
		SELECT 
			event_id, device_id::text, ide_name, event_type, tamper_details, healed_successfully, occurred_at
		FROM device_tamper_events
		WHERE device_id::text = $1 
		   OR device_id IN (SELECT de.device_id FROM device_enrollments de WHERE de.hostname = $2 OR de.device_id::text = $1)
		ORDER BY occurred_at DESC
		LIMIT 20
	`, detail.DeviceID, detail.Hostname)
	if tamperErr == nil {
		defer tamperRows.Close()
		for tamperRows.Next() {
			var te DeviceTamperEventLog
			te.Hostname = detail.Hostname
			te.UserIdentifier = detail.UserIdentifier
			if err := tamperRows.Scan(
				&te.EventID, &te.DeviceID, &te.IdeName, &te.EventType,
				&te.TamperDetails, &te.HealedSuccessfully, &te.OccurredAt,
			); err == nil {
				detail.RecentTamperEvents = append(detail.RecentTamperEvents, te)
			}
		}
	}

	return detail, nil
}
