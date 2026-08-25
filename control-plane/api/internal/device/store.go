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

	// 1. Ensure base devices table exists
	_, _ = s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS devices (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
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
			revoked_by_subject TEXT,
			revocation_reason TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
	`)

	// 2. Add columns individually to guarantee existence across existing installations
	columnAlters := []string{
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';",
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS stable_device_id TEXT NOT NULL DEFAULT '';",
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS display_name TEXT NOT NULL DEFAULT '';",
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS owner_subject TEXT;",
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_family TEXT NOT NULL DEFAULT 'windows';",
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS architecture TEXT NOT NULL DEFAULT 'x86_64';",
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_version_summary TEXT;",
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS daemon_version TEXT DEFAULT '2.1.0';",
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS public_key TEXT;",
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS state VARCHAR(32) NOT NULL DEFAULT 'PENDING';",
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS state_reason_code TEXT;",
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS state_changed_at TIMESTAMPTZ NOT NULL DEFAULT now();",
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS first_enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now();",
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now();",
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;",
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS revoked_by_subject TEXT;",
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS revocation_reason TEXT;",
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();",
		"ALTER TABLE devices ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_tenant_stable ON devices(tenant_id, stable_device_id);",
	}
	for _, q := range columnAlters {
		_, _ = s.pool.Exec(ctx, q)
	}

	// 3. Migrate from legacy device_enrollments if it exists as a base table
	_, _ = s.pool.Exec(ctx, `
		DO $$
		BEGIN
			IF EXISTS (
				SELECT 1 FROM information_schema.tables 
				WHERE table_schema = 'public' AND table_name = 'device_enrollments' AND table_type = 'BASE TABLE'
			) THEN
				INSERT INTO devices (
					id, tenant_id, stable_device_id, display_name, owner_subject,
					os_family, architecture, os_version_summary, public_key, daemon_version,
					state, first_enrolled_at, last_heartbeat_at, created_at, updated_at
				)
				SELECT 
					de.device_id,
					de.organization_id,
					de.hostname,
					de.hostname,
					de.user_identifier,
					de.os,
					'x86_64',
					de.os_version,
					de.public_key,
					de.daemon_version,
					CASE WHEN de.enrollment_status = 'REVOKED' THEN 'REVOKED' ELSE 'COMPLIANT' END,
					de.first_enrolled_at,
					de.last_heartbeat_at,
					de.created_at,
					de.updated_at
				FROM device_enrollments de
				ON CONFLICT (tenant_id, stable_device_id) DO UPDATE SET
					public_key = COALESCE(NULLIF(EXCLUDED.public_key, ''), devices.public_key),
					last_heartbeat_at = EXCLUDED.last_heartbeat_at,
					updated_at = EXCLUDED.updated_at;

				DROP TABLE device_enrollments CASCADE;
			END IF;
		END $$;
	`)

	// 4. Backward compatibility view for legacy tooling
	_, _ = s.pool.Exec(ctx, `DROP VIEW IF EXISTS device_enrollments CASCADE;`)
	_, _ = s.pool.Exec(ctx, `
		CREATE OR REPLACE VIEW device_enrollments AS
			SELECT 
				id AS device_id,
				tenant_id AS organization_id,
				COALESCE(stable_device_id, display_name) AS hostname,
				COALESCE(owner_subject, display_name, 'Developer Workstation') AS user_identifier,
				os_family AS os,
				COALESCE(os_version_summary, architecture, 'v1.0') AS os_version,
				COALESCE(public_key, '') AS public_key,
				COALESCE(daemon_version, '2.1.0') AS daemon_version,
				CASE WHEN state::text = 'REVOKED' THEN 'REVOKED' ELSE 'ACTIVE' END AS enrollment_status,
				first_enrolled_at,
				last_heartbeat_at,
				created_at,
				updated_at
			FROM devices;
	`)

	// 5. Ensure compliance, ide status, and tamper events tables exist
	childTables := []string{
		`CREATE TABLE IF NOT EXISTS device_compliance_reports (
			report_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			organization_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
			overall_compliance VARCHAR(32) NOT NULL,
			tamper_event_count_24h INT NOT NULL DEFAULT 0,
			report_payload JSONB,
			reported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT uq_device_compliance UNIQUE (device_id)
		);`,
		`CREATE TABLE IF NOT EXISTS device_ide_status (
			status_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			ide_name VARCHAR(64) NOT NULL,
			is_installed BOOLEAN NOT NULL DEFAULT false,
			config_path TEXT NOT NULL DEFAULT '',
			proxy_configured BOOLEAN NOT NULL DEFAULT false,
			configured_base_url TEXT DEFAULT '',
			mcp_wrapped BOOLEAN NOT NULL DEFAULT false,
			compliance_state VARCHAR(32) NOT NULL DEFAULT 'COMPLIANT',
			last_healed_at TIMESTAMPTZ,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT uq_device_ide UNIQUE (device_id, ide_name)
		);`,
		`CREATE TABLE IF NOT EXISTS device_tamper_events (
			event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			organization_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
			ide_name VARCHAR(64) NOT NULL,
			event_type VARCHAR(64) NOT NULL,
			tamper_details TEXT NOT NULL,
			healed_successfully BOOLEAN NOT NULL DEFAULT true,
			occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);`,
		`CREATE TABLE IF NOT EXISTS device_tamper_logs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
			device_id TEXT NOT NULL,
			target_ide TEXT NOT NULL,
			detected_diff TEXT NOT NULL,
			action_taken TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);`,
	}
	for _, ct := range childTables {
		_, _ = s.pool.Exec(ctx, ct)
	}

	return nil
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
	err := s.pool.QueryRow(ctx, `
		INSERT INTO devices (
			tenant_id, stable_device_id, display_name, owner_subject,
			os_family, architecture, os_version_summary, public_key, daemon_version, state, state_changed_at, updated_at
		) VALUES ($1, $2, $2, $3, $4, 'x86_64', $5, $6, $7, 'COMPLIANT', now(), now())
		ON CONFLICT (tenant_id, stable_device_id)
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

	// 1. Resolve authoritative device in devices table
	var canonicalDeviceID string
	var registeredOrgID string
	var devState string
	var devHostname string

	err = tx.QueryRow(ctx, `
		SELECT id::text, tenant_id::text, state::text, COALESCE(stable_device_id, display_name, id::text)
		FROM devices
		WHERE id::text = $1 
		   OR stable_device_id = $1 
		   OR LOWER(display_name) = LOWER($1)
		   OR $1 ILIKE '%-' || display_name || '-%'
		LIMIT 1
	`, req.DeviceID).Scan(&canonicalDeviceID, &registeredOrgID, &devState, &devHostname)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Auto-provision workstation in devices table if new
			if orgID == "" {
				orgID = "00000000-0000-0000-0000-000000000001"
			}
			registeredOrgID = orgID
			err = tx.QueryRow(ctx, `
				INSERT INTO devices (
					tenant_id, stable_device_id, display_name, os_family, architecture, state, last_heartbeat_at, created_at, updated_at
				) VALUES ($1, $2, $2, 'windows', 'x86_64', 'COMPLIANT', now(), now(), now())
				ON CONFLICT (tenant_id, stable_device_id) DO UPDATE SET last_heartbeat_at = now(), updated_at = now()
				RETURNING id::text, tenant_id::text, state::text, stable_device_id
			`, registeredOrgID, req.DeviceID).Scan(&canonicalDeviceID, &registeredOrgID, &devState, &devHostname)
			if err != nil {
				return nil, fmt.Errorf("device provision failed: %w", err)
			}
		} else {
			return nil, err
		}
	}

	if devState == "REVOKED" {
		return nil, errors.New("device enrollment is not active")
	}

	now := time.Now().UTC()

	// 2. Update device heartbeat and compliance state in-place
	_, err = tx.Exec(ctx, `
		UPDATE devices 
		SET last_heartbeat_at = $1, state = 'COMPLIANT', updated_at = $1 
		WHERE id::text = $2 AND state != 'REVOKED'
	`, now, canonicalDeviceID)
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
		SELECT 
			d.id::text AS device_id,
			COALESCE(d.stable_device_id, d.display_name, d.id::text) AS hostname,
			COALESCE(NULLIF(d.owner_subject, ''), NULLIF(d.display_name, ''), 'Developer Workstation') AS user_identifier,
			COALESCE(d.os_family, 'windows') AS os,
			COALESCE(d.os_version_summary, d.architecture, 'v1.0') AS os_version,
			d.state::text AS enrollment_status,
			d.last_heartbeat_at,
			CASE
				WHEN d.state::text = 'REVOKED' THEN 'NON_COMPLIANT'
				WHEN c.overall_compliance IS NOT NULL THEN c.overall_compliance
				WHEN d.state::text = 'PENDING' THEN 'OFFLINE'
				WHEN d.last_heartbeat_at IS NULL THEN 'OFFLINE'
				WHEN d.last_heartbeat_at < NOW() - INTERVAL '3 minutes' THEN 'OFFLINE'
				ELSE 'COMPLIANT'
			END AS overall_compliance,
			COALESCE(c.tamper_event_count_24h, 0) AS tamper_count_24h,
			COALESCE((
				SELECT array_agg(DISTINCT s.ide_name ORDER BY s.ide_name ASC)
				FROM device_ide_status s
				WHERE s.device_id = d.id AND s.is_installed = true
			), '{}'::text[]) AS active_ides
		FROM devices d
		LEFT JOIN device_compliance_reports c ON c.device_id = d.id
		WHERE ($1 = '' OR d.tenant_id::text = $1)
		ORDER BY d.last_heartbeat_at DESC NULLS LAST
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
			&item.ActiveIDEs,
		); err != nil {
			return nil, err
		}
		if item.ActiveIDEs == nil {
			item.ActiveIDEs = []string{}
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
			e.event_id, e.device_id, d.stable_device_id, COALESCE(d.owner_subject, d.display_name, 'Developer Workstation'),
			e.ide_name, e.event_type, e.tamper_details, e.healed_successfully, e.occurred_at
		FROM device_tamper_events e
		JOIN devices d ON e.device_id = d.id
		WHERE ($1 = '' OR d.tenant_id::text = $1)
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

	// 1. Query device information directly from devices
	var lastHeartbeat *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT 
			d.id::text,
			d.tenant_id::text,
			COALESCE(d.stable_device_id, d.display_name, d.id::text),
			COALESCE(NULLIF(d.owner_subject, ''), NULLIF(d.display_name, ''), 'Developer Workstation'),
			COALESCE(d.os_family, 'windows'),
			COALESCE(d.os_version_summary, d.architecture, 'v1.0.35'),
			COALESCE(d.public_key, ''),
			COALESCE(d.daemon_version, '2.1.0'),
			d.state::text,
			d.last_heartbeat_at,
			d.created_at,
			d.updated_at
		FROM devices d
		WHERE (d.id::text = $1 OR d.stable_device_id = $1 OR LOWER(d.display_name) = LOWER($1) OR $1 ILIKE '%-' || d.display_name || '-%')
		  AND ($2 = '' OR d.tenant_id::text = $2)
		LIMIT 1
	`, deviceID, orgID).Scan(
		&detail.DeviceID, &detail.OrganizationID, &detail.Hostname, &detail.UserIdentifier,
		&detail.OS, &detail.OSVersion, &detail.PublicKey, &detail.DaemonVersion,
		&detail.EnrollmentStatus, &lastHeartbeat, &detail.CreatedAt, &detail.UpdatedAt,
	)

	if err != nil {
		// Defensive fallback if public_key column is not present in legacy schema
		fallbackErr := s.pool.QueryRow(ctx, `
			SELECT 
				d.id::text,
				d.tenant_id::text,
				COALESCE(d.stable_device_id, d.display_name, d.id::text),
				COALESCE(NULLIF(d.owner_subject, ''), NULLIF(d.display_name, ''), 'Developer Workstation'),
				COALESCE(d.os_family, 'windows'),
				COALESCE(d.os_version_summary, d.architecture, 'v1.0.35'),
				'' AS public_key,
				COALESCE(d.daemon_version, '2.1.0'),
				d.state::text,
				d.last_heartbeat_at,
				d.created_at,
				d.updated_at
			FROM devices d
			WHERE (d.id::text = $1 OR d.stable_device_id = $1 OR LOWER(d.display_name) = LOWER($1) OR $1 ILIKE '%-' || d.display_name || '-%')
			  AND ($2 = '' OR d.tenant_id::text = $2)
			LIMIT 1
		`, deviceID, orgID).Scan(
			&detail.DeviceID, &detail.OrganizationID, &detail.Hostname, &detail.UserIdentifier,
			&detail.OS, &detail.OSVersion, &detail.PublicKey, &detail.DaemonVersion,
			&detail.EnrollmentStatus, &lastHeartbeat, &detail.CreatedAt, &detail.UpdatedAt,
		)
		if fallbackErr != nil {
			return nil, fmt.Errorf("failed to get device: %w", err)
		}
		// Attempt self-healing column addition
		_, _ = s.pool.Exec(ctx, "ALTER TABLE devices ADD COLUMN IF NOT EXISTS public_key TEXT;")
	}
	detail.LastHeartbeatAt = lastHeartbeat

	// 2. Fetch compliance report snapshot
	var payload []byte
	compErr := s.pool.QueryRow(ctx, `
		SELECT overall_compliance, tamper_event_count_24h, report_payload::text
		FROM device_compliance_reports
		WHERE device_id::text = $1
		ORDER BY reported_at DESC
		LIMIT 1
	`, detail.DeviceID).Scan(&detail.OverallCompliance, &detail.TamperCount24h, &payload)
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
		SELECT 
			ide_name, is_installed, config_path, proxy_configured,
			COALESCE(configured_base_url, ''), mcp_wrapped, compliance_state, last_healed_at
		FROM device_ide_status
		WHERE device_id::text = $1
		ORDER BY ide_name ASC, updated_at DESC
	`, detail.DeviceID)
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
		ORDER BY occurred_at DESC
		LIMIT 20
	`, detail.DeviceID)
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

