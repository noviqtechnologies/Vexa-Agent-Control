package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}

	var pingErr error
	maxRetries := 15
	for i := 1; i <= maxRetries; i++ {
		pingErr = pool.Ping(ctx)
		if pingErr == nil {
			if i > 1 {
				log.Printf("successfully connected to postgres on attempt %d", i)
			}
			return &Store{pool: pool}, nil
		}
		log.Printf("waiting for postgres to be ready (attempt %d/%d): %v", i, maxRetries, pingErr)
		select {
		case <-ctx.Done():
			pool.Close()
			return nil, ctx.Err()
		case <-time.After(1 * time.Second):
		}
	}

	pool.Close()
	return nil, fmt.Errorf("ping postgres after %d retries: %w", maxRetries, pingErr)
}

func (s *Store) Close() {
	s.pool.Close()
}

func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// UpsertAgent ensures the agent exists within a tenant, updating last_seen_at on conflict.
func (s *Store) UpsertAgent(ctx context.Context, tenantID, agentID string) error {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agents (tenant_id, agent_id, first_seen_at, last_seen_at)
		VALUES ($1, $2, now(), now())
		ON CONFLICT (agent_id) DO UPDATE SET
			tenant_id    = EXCLUDED.tenant_id,
			last_seen_at = now(),
			updated_at   = now()
	`, tenantID, agentID)
	return err
}

// CountDistinctAgents returns the total count of registered devices consuming license seats for a tenant.
func (s *Store) CountDistinctAgents(ctx context.Context, tenantID string) (int, error) {
	var count int
	var err error
	if tenantID != "" {
		err = s.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM (
				SELECT id::text FROM devices WHERE tenant_id = $1 AND state != 'REVOKED'
				UNION
				SELECT device_id::text FROM device_enrollments WHERE organization_id = $1 AND enrollment_status != 'REVOKED'
			) d
		`, tenantID).Scan(&count)
	} else {
		err = s.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM (
				SELECT id::text FROM devices WHERE state != 'REVOKED'
				UNION
				SELECT device_id::text FROM device_enrollments WHERE enrollment_status != 'REVOKED'
			) d
		`).Scan(&count)
	}
	return count, err
}

// AgentExists returns true if the specified agentID exists within a tenant.
func (s *Store) AgentExists(ctx context.Context, tenantID, agentID string) (bool, error) {
	var exists bool
	var err error
	if tenantID != "" {
		err = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = $1 AND tenant_id = $2)`, agentID, tenantID).Scan(&exists)
	} else {
		err = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = $1)`, agentID).Scan(&exists)
	}
	return exists, err
}

// ResolveTenantIDForAgent checks if an agent or device belongs to a non-default tenant.
func (s *Store) ResolveTenantIDForAgent(ctx context.Context, agentID string) string {
	if agentID == "" {
		return "00000000-0000-0000-0000-000000000001"
	}
	var tenantID string
	// 1. Check devices table
	err := s.pool.QueryRow(ctx, `
		SELECT tenant_id::text FROM devices 
		WHERE stable_device_id = $1 
		   OR id::text = $1 
		   OR LOWER(display_name) = LOWER($1)
		   OR $1 ILIKE '%' || LOWER(display_name) || '%'
		LIMIT 1
	`, agentID).Scan(&tenantID)
	if err == nil && tenantID != "" {
		return tenantID
	}
	// 2. Check agents table
	err = s.pool.QueryRow(ctx, `
		SELECT tenant_id::text FROM agents 
		WHERE agent_id = $1 
		LIMIT 1
	`, agentID).Scan(&tenantID)
	if err == nil && tenantID != "" {
		return tenantID
	}
	// 3. Check device_enrollments table
	err = s.pool.QueryRow(ctx, `
		SELECT organization_id::text FROM device_enrollments 
		WHERE hostname = $1 
		   OR device_id::text = $1 
		   OR $1 ILIKE '%' || LOWER(hostname) || '%'
		LIMIT 1
	`, agentID).Scan(&tenantID)
	if err == nil && tenantID != "" {
		return tenantID
	}
	return "00000000-0000-0000-0000-000000000001"
}

// InsertEvent persists a redacted event scoped to a tenant. Caller must UpsertAgent first.
func (s *Store) InsertEvent(ctx context.Context, tenantID string, e *model.RedactedEvent) error {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	dlp, _ := json.Marshal(e.DlpFindings)
	inj, _ := json.Marshal(e.InjectionFindings)
	sem, _ := json.Marshal(e.SemanticFindings)

	_, err := s.pool.Exec(ctx, `
		INSERT INTO telemetry_events
			(tenant_id, event_id, timestamp_ms, session_id, agent_id, tool_name,
			 decision, dlp_findings, injection_findings, semantic_findings)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, tenantID, e.EventID, e.TimestampMs, e.SessionID, e.AgentID, e.ToolName,
		e.Decision, dlp, inj, sem)
	return err
}

// InsertAlert persists an alert scoped to a tenant.
func (s *Store) InsertAlert(ctx context.Context, tenantID string, a *model.RedactedAlert) error {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO alerts (tenant_id, alert_id, severity, event_id)
		VALUES ($1, $2, $3, $4)
	`, tenantID, a.AlertID, a.Severity, a.Event.EventID)
	return err
}

// UpsertCredential persists or updates credential metadata scoped to a tenant.
func (s *Store) UpsertCredential(ctx context.Context, tenantID string, c *model.SanitizedCredentialMeta) error {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	history, _ := json.Marshal(c.RotationHistory)

	_, err := s.pool.Exec(ctx, `
		INSERT INTO identity_credentials
			(tenant_id, credential_id, agent_id, scope, ttl_seconds,
			 created_at_ms, expires_at_ms, last_rotated_at_ms, rotation_history)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (credential_id) DO UPDATE SET
			tenant_id          = EXCLUDED.tenant_id,
			scope              = EXCLUDED.scope,
			ttl_seconds        = EXCLUDED.ttl_seconds,
			expires_at_ms      = EXCLUDED.expires_at_ms,
			last_rotated_at_ms = EXCLUDED.last_rotated_at_ms,
			rotation_history   = EXCLUDED.rotation_history,
			updated_at         = now()
	`, tenantID, c.CredentialID, c.AgentID, c.Scope, c.TTLSeconds,
		c.CreatedAtMs, c.ExpiresAtMs, c.LastRotatedAtMs, history)
	return err
}

// ── Read queries (Fleet Overview + Identity Governance) ────────────────────

type AgentSummary struct {
	AgentID       string    `json:"agent_id"`
	DisplayName   *string   `json:"display_name"`
	Status        string    `json:"status"`
	PolicyVersion *string   `json:"policy_version"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	EventCount    int64     `json:"event_count"`
	AlertCount    int64     `json:"alert_count"`
}

func (s *Store) ListAgents(ctx context.Context, tenantID string, limit, offset int) ([]AgentSummary, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT
			a.agent_id,
			a.display_name,
			a.status,
			a.policy_version,
			a.last_seen_at,
			COALESCE(e.cnt, 0) AS event_count,
			COALESCE(al.cnt, 0) AS alert_count
		FROM (
			SELECT agent_id, display_name, status::text AS status, policy_version, last_seen_at, tenant_id FROM agents WHERE tenant_id = $1
			UNION ALL
			SELECT COALESCE(stable_device_id, id::text) AS agent_id, COALESCE(display_name, stable_device_id, id::text) AS display_name, state::text AS status, 'v1.0' AS policy_version, COALESCE(last_heartbeat_at, created_at) AS last_seen_at, tenant_id
			FROM devices
			WHERE tenant_id = $1 AND COALESCE(stable_device_id, id::text) NOT IN (SELECT agent_id FROM agents WHERE tenant_id = $1)
			UNION ALL
			SELECT hostname AS agent_id, user_identifier AS display_name, enrollment_status::text AS status, 'v1.0' AS policy_version, COALESCE(last_heartbeat_at, created_at) AS last_seen_at, organization_id AS tenant_id
			FROM device_enrollments
			WHERE organization_id = $1 AND hostname NOT IN (SELECT agent_id FROM agents WHERE tenant_id = $1)
		) a
		LEFT JOIN (
			SELECT agent_id, COUNT(*) AS cnt
			FROM telemetry_events
			WHERE tenant_id = $1
			GROUP BY agent_id
		) e ON e.agent_id = a.agent_id
		LEFT JOIN (
			SELECT te.agent_id, COUNT(*) AS cnt
			FROM alerts al
			JOIN telemetry_events te ON te.event_id = al.event_id
			WHERE al.tenant_id = $1
			GROUP BY te.agent_id
		) al ON al.agent_id = a.agent_id
		ORDER BY a.last_seen_at DESC
		LIMIT $2 OFFSET $3
	`, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []AgentSummary
	for rows.Next() {
		var a AgentSummary
		if err := rows.Scan(&a.AgentID, &a.DisplayName, &a.Status,
			&a.PolicyVersion, &a.LastSeenAt, &a.EventCount, &a.AlertCount); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

type FleetStats struct {
	TotalAgents   int64 `json:"total_agents"`
	ActiveAgents  int64 `json:"active_agents"`
	TotalEvents   int64 `json:"total_events"`
	DeniedEvents  int64 `json:"denied_events"`
	TotalAlerts   int64 `json:"total_alerts"`
	CriticalAlerts int64 `json:"critical_alerts"`
}

func (s *Store) GetFleetStats(ctx context.Context, tenantID string) (*FleetStats, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	var stats FleetStats
	err := s.pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM (
				SELECT id::text FROM devices WHERE tenant_id = $1 AND state != 'REVOKED'
				UNION
				SELECT device_id::text FROM device_enrollments WHERE organization_id = $1 AND enrollment_status != 'REVOKED'
			) d),
			(SELECT COUNT(*) FROM (
				SELECT id::text FROM devices WHERE tenant_id = $1 AND state != 'REVOKED' AND last_heartbeat_at >= NOW() - INTERVAL '3 minutes'
				UNION
				SELECT device_id::text FROM device_enrollments WHERE organization_id = $1 AND enrollment_status = 'ACTIVE' AND last_heartbeat_at >= NOW() - INTERVAL '3 minutes'
			) d),
			(SELECT COUNT(*) FROM telemetry_events WHERE tenant_id = $1),
			(SELECT COUNT(*) FROM telemetry_events WHERE tenant_id = $1 AND decision = 'denied'),
			(SELECT COUNT(*) FROM alerts WHERE tenant_id = $1),
			(SELECT COUNT(*) FROM alerts WHERE tenant_id = $1 AND severity = 'critical')
	`, tenantID).Scan(&stats.TotalAgents, &stats.ActiveAgents, &stats.TotalEvents,
		&stats.DeniedEvents, &stats.TotalAlerts, &stats.CriticalAlerts)
	return &stats, err
}

func (s *Store) ListRecentAlerts(ctx context.Context, tenantID string, limit int) ([]model.RedactedAlert, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT
			a.alert_id, a.severity,
			e.event_id, e.timestamp_ms, e.session_id, e.agent_id,
			e.tool_name, e.decision,
			e.dlp_findings, e.injection_findings, e.semantic_findings
		FROM alerts a
		JOIN telemetry_events e ON e.event_id = a.event_id
		WHERE a.tenant_id = $1
		ORDER BY a.created_at DESC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []model.RedactedAlert
	for rows.Next() {
		var al model.RedactedAlert
		var dlpJSON, injJSON, semJSON []byte
		if err := rows.Scan(
			&al.AlertID, &al.Severity,
			&al.Event.EventID, &al.Event.TimestampMs, &al.Event.SessionID,
			&al.Event.AgentID, &al.Event.ToolName, &al.Event.Decision,
			&dlpJSON, &injJSON, &semJSON,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(dlpJSON, &al.Event.DlpFindings)
		_ = json.Unmarshal(injJSON, &al.Event.InjectionFindings)
		_ = json.Unmarshal(semJSON, &al.Event.SemanticFindings)
		alerts = append(alerts, al)
	}
	return alerts, rows.Err()
}

type RecentEvent struct {
	model.RedactedEvent
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) ListRecentEvents(ctx context.Context, tenantID, agentID string, limit int) ([]RecentEvent, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	query := `
		SELECT event_id, timestamp_ms, session_id, agent_id, tool_name,
		       decision, dlp_findings, injection_findings, semantic_findings, created_at
		FROM telemetry_events
		WHERE tenant_id = $1
	`
	var args []any
	if agentID != "" {
		query += ` AND agent_id = $2 ORDER BY timestamp_ms DESC LIMIT $3`
		args = []any{tenantID, agentID, limit}
	} else {
		query += ` ORDER BY timestamp_ms DESC LIMIT $2`
		args = []any{tenantID, limit}
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []RecentEvent
	for rows.Next() {
		var e RecentEvent
		var dlpJSON, injJSON, semJSON []byte
		if err := rows.Scan(
			&e.EventID, &e.TimestampMs, &e.SessionID, &e.AgentID,
			&e.ToolName, &e.Decision,
			&dlpJSON, &injJSON, &semJSON, &e.CreatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(dlpJSON, &e.DlpFindings)
		_ = json.Unmarshal(injJSON, &e.InjectionFindings)
		_ = json.Unmarshal(semJSON, &e.SemanticFindings)
		events = append(events, e)
	}
	return events, rows.Err()
}

func (s *Store) ListCredentials(ctx context.Context, tenantID, agentID string) ([]model.SanitizedCredentialMeta, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	query := `
		SELECT credential_id, agent_id, scope, ttl_seconds,
		       created_at_ms, expires_at_ms, last_rotated_at_ms, rotation_history
		FROM identity_credentials
		WHERE tenant_id = $1
	`
	var args []any
	if agentID != "" {
		query += ` AND agent_id = $2 ORDER BY expires_at_ms ASC`
		args = []any{tenantID, agentID}
	} else {
		query += ` ORDER BY expires_at_ms ASC`
		args = []any{tenantID}
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []model.SanitizedCredentialMeta
	for rows.Next() {
		var c model.SanitizedCredentialMeta
		var historyJSON []byte
		if err := rows.Scan(
			&c.CredentialID, &c.AgentID, &c.Scope, &c.TTLSeconds,
			&c.CreatedAtMs, &c.ExpiresAtMs, &c.LastRotatedAtMs, &historyJSON,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(historyJSON, &c.RotationHistory)
		creds = append(creds, c)
	}
	return creds, rows.Err()
}

// DecisionBreakdown returns counts per decision type for the heatmap.
type DecisionBreakdown struct {
	Hour     string `json:"hour"`
	Allowed  int64  `json:"allowed"`
	Denied   int64  `json:"denied"`
	Warned   int64  `json:"warned"`
}

func (s *Store) GetDecisionHeatmap(ctx context.Context, tenantID string, hours int) ([]DecisionBreakdown, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT
			to_char(to_timestamp(timestamp_ms / 1000) AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:00') AS hour,
			COUNT(*) FILTER (WHERE decision = 'allowed') AS allowed,
			COUNT(*) FILTER (WHERE decision = 'denied')  AS denied,
			COUNT(*) FILTER (WHERE decision = 'warned')  AS warned
		FROM telemetry_events
		WHERE tenant_id = $1 AND timestamp_ms > (EXTRACT(EPOCH FROM now()) * 1000 - $2 * 3600000)::BIGINT
		GROUP BY hour
		ORDER BY hour
	`, tenantID, hours)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var breakdown []DecisionBreakdown
	for rows.Next() {
		var b DecisionBreakdown
		if err := rows.Scan(&b.Hour, &b.Allowed, &b.Denied, &b.Warned); err != nil {
			return nil, err
		}
		breakdown = append(breakdown, b)
	}
	return breakdown, rows.Err()
}

// ── Threat Intelligence queries ───────────────────────────────────────────────

type ThreatSummary struct {
	DlpTotal       int64 `json:"dlp_total"`
	InjectionTotal int64 `json:"injection_total"`
	SemanticTotal  int64 `json:"semantic_total"`
	EventsWithDlp  int64 `json:"events_with_dlp"`
	EventsWithInj  int64 `json:"events_with_injection"`
	EventsWithSem  int64 `json:"events_with_semantic"`
}

func (s *Store) GetThreatSummary(ctx context.Context, tenantID string, hours int) (*ThreatSummary, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	var ts ThreatSummary
	err := s.pool.QueryRow(ctx, `
		SELECT
			COALESCE(SUM(jsonb_array_length(dlp_findings)), 0),
			COALESCE(SUM(jsonb_array_length(injection_findings)), 0),
			COALESCE(SUM(jsonb_array_length(semantic_findings)), 0),
			COUNT(*) FILTER (WHERE jsonb_array_length(dlp_findings) > 0),
			COUNT(*) FILTER (WHERE jsonb_array_length(injection_findings) > 0),
			COUNT(*) FILTER (WHERE jsonb_array_length(semantic_findings) > 0)
		FROM telemetry_events
		WHERE tenant_id = $1 AND timestamp_ms > (EXTRACT(EPOCH FROM now()) * 1000 - $2 * 3600000)::BIGINT
	`, tenantID, hours).Scan(
		&ts.DlpTotal, &ts.InjectionTotal, &ts.SemanticTotal,
		&ts.EventsWithDlp, &ts.EventsWithInj, &ts.EventsWithSem,
	)
	return &ts, err
}

type ThreatTimelinePoint struct {
	Hour      string `json:"hour"`
	Dlp       int64  `json:"dlp"`
	Injection int64  `json:"injection"`
	Semantic  int64  `json:"semantic"`
}

func (s *Store) GetThreatTimeline(ctx context.Context, tenantID string, hours int) ([]ThreatTimelinePoint, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT
			to_char(to_timestamp(timestamp_ms / 1000) AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:00') AS hour,
			COALESCE(SUM(jsonb_array_length(dlp_findings)), 0),
			COALESCE(SUM(jsonb_array_length(injection_findings)), 0),
			COALESCE(SUM(jsonb_array_length(semantic_findings)), 0)
		FROM telemetry_events
		WHERE tenant_id = $1 AND timestamp_ms > (EXTRACT(EPOCH FROM now()) * 1000 - $2 * 3600000)::BIGINT
		GROUP BY hour
		ORDER BY hour
	`, tenantID, hours)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []ThreatTimelinePoint
	for rows.Next() {
		var p ThreatTimelinePoint
		if err := rows.Scan(&p.Hour, &p.Dlp, &p.Injection, &p.Semantic); err != nil {
			return nil, err
		}
		points = append(points, p)
	}
	return points, rows.Err()
}

type ThreatPattern struct {
	Type        string `json:"type"`
	PatternName string `json:"pattern_name"`
	Category    string `json:"category,omitempty"`
	TotalCount  int64  `json:"total_count"`
	EventCount  int64  `json:"event_count"`
}

func (s *Store) GetTopThreatPatterns(ctx context.Context, tenantID string, hours int, limit int) ([]ThreatPattern, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	rows, err := s.pool.Query(ctx, `
		WITH dlp AS (
			SELECT
				'dlp' AS type,
				f->>'pattern_name' AS pattern_name,
				f->>'category' AS category,
				(f->>'count')::BIGINT AS cnt
			FROM telemetry_events,
				jsonb_array_elements(dlp_findings) AS f
			WHERE tenant_id = $1 AND timestamp_ms > (EXTRACT(EPOCH FROM now()) * 1000 - $2 * 3600000)::BIGINT
		),
		injection AS (
			SELECT
				'injection' AS type,
				f->>'pattern_name' AS pattern_name,
				'' AS category,
				(f->>'count')::BIGINT AS cnt
			FROM telemetry_events,
				jsonb_array_elements(injection_findings) AS f
			WHERE tenant_id = $1 AND timestamp_ms > (EXTRACT(EPOCH FROM now()) * 1000 - $2 * 3600000)::BIGINT
		),
		semantic AS (
			SELECT
				'semantic' AS type,
				f->>'finding_type' AS pattern_name,
				'' AS category,
				1::BIGINT AS cnt
			FROM telemetry_events,
				jsonb_array_elements(semantic_findings) AS f
			WHERE tenant_id = $1 AND timestamp_ms > (EXTRACT(EPOCH FROM now()) * 1000 - $2 * 3600000)::BIGINT
		),
		combined AS (
			SELECT * FROM dlp
			UNION ALL SELECT * FROM injection
			UNION ALL SELECT * FROM semantic
		)
		SELECT type, pattern_name, category,
			SUM(cnt) AS total_count,
			COUNT(*) AS event_count
		FROM combined
		GROUP BY type, pattern_name, category
		ORDER BY total_count DESC
		LIMIT $3
	`, tenantID, hours, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var patterns []ThreatPattern
	for rows.Next() {
		var p ThreatPattern
		if err := rows.Scan(&p.Type, &p.PatternName, &p.Category, &p.TotalCount, &p.EventCount); err != nil {
			return nil, err
		}
		patterns = append(patterns, p)
	}
	return patterns, rows.Err()
}

// RunMigrations applies the SQL migration files.
func RunMigrations(ctx context.Context, pool *pgxpool.Pool, migrationSQL string) error {
	_, err := pool.Exec(ctx, migrationSQL)
	return err
}

type McpServerInventoryRow struct {
	AgentID      string `json:"agent_id"`
	IDETarget    string `json:"ide_target"`
	ServerName   string `json:"server_name"`
	Wrapped      bool   `json:"wrapped"`
	PathVerified bool   `json:"path_verified"`
	LastSeenAt   string `json:"last_seen_at"`
}

func (s *Store) UpsertMcpServer(ctx context.Context, tenantID, agentID string, m *model.SanitizedMcpServerMeta) error {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO mcp_servers
			(tenant_id, agent_id, ide_target, server_name, wrapped, path_verified, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, now())
		ON CONFLICT (agent_id, ide_target, server_name) DO UPDATE SET
			tenant_id     = EXCLUDED.tenant_id,
			wrapped       = EXCLUDED.wrapped,
			path_verified = EXCLUDED.path_verified,
			last_seen_at  = now()
	`, tenantID, agentID, m.IDETarget, m.ServerName, m.Wrapped, m.PathVerified)
	return err
}

func (s *Store) ListMcpServersByAgent(ctx context.Context, tenantID, agentID string) ([]McpServerInventoryRow, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT agent_id, ide_target, server_name, wrapped, path_verified, last_seen_at
		FROM mcp_servers
		WHERE tenant_id = $1 AND agent_id = $2
		ORDER BY last_seen_at DESC
	`, tenantID, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []McpServerInventoryRow
	for rows.Next() {
		var sr McpServerInventoryRow
		var lastSeen time.Time
		if err := rows.Scan(&sr.AgentID, &sr.IDETarget, &sr.ServerName, &sr.Wrapped, &sr.PathVerified, &lastSeen); err != nil {
			return nil, err
		}
		sr.LastSeenAt = lastSeen.Format(time.RFC3339)
		servers = append(servers, sr)
	}
	return servers, rows.Err()
}

func (s *Store) ListMcpServersFleetWide(ctx context.Context, tenantID string) ([]McpServerInventoryRow, error) {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT agent_id, ide_target, server_name, wrapped, path_verified, last_seen_at
		FROM mcp_servers
		WHERE tenant_id = $1
		ORDER BY last_seen_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []McpServerInventoryRow
	for rows.Next() {
		var sr McpServerInventoryRow
		var lastSeen time.Time
		if err := rows.Scan(&sr.AgentID, &sr.IDETarget, &sr.ServerName, &sr.Wrapped, &sr.PathVerified, &lastSeen); err != nil {
			return nil, err
		}
		sr.LastSeenAt = lastSeen.Format(time.RFC3339)
		servers = append(servers, sr)
	}
	return servers, rows.Err()
}

// Transactional helper for ingest operations.
func (s *Store) InTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
