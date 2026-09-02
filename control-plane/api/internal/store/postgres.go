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

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// InTx executes a function within a transaction.
func (s *Store) InTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	if s.pool == nil {
		return fmt.Errorf("database pool is not initialized")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// SetTenantContext is a backward-compatible no-op (Row-Level Security session variables removed).
func (s *Store) SetTenantContext(ctx context.Context, tx pgx.Tx, organizationID string, isOperator bool) error {
	return nil
}

// WithTenantTx executes a transaction for the given organization.
func (s *Store) WithTenantTx(ctx context.Context, organizationID string, isOperator bool, fn func(tx pgx.Tx) error) error {
	return s.InTx(ctx, fn)
}

// EnsureCoreSchema guarantees schema consistency for agents, telemetry, alerts, and MCP servers.
func (s *Store) EnsureCoreSchema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	q := `
		CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

		CREATE TABLE IF NOT EXISTS agents (
			agent_id TEXT PRIMARY KEY,
			organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			display_name TEXT,
			status TEXT NOT NULL DEFAULT 'active',
			policy_version TEXT,
			first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE INDEX IF NOT EXISTS idx_agents_org ON agents (organization_id, last_seen_at DESC);

		CREATE TABLE IF NOT EXISTS telemetry_events (
			event_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			timestamp_ms BIGINT NOT NULL,
			session_id TEXT NOT NULL,
			agent_id TEXT NOT NULL,
			tool_name TEXT NOT NULL,
			decision event_decision NOT NULL,
			dlp_findings JSONB NOT NULL DEFAULT '[]',
			injection_findings JSONB NOT NULL DEFAULT '[]',
			semantic_findings JSONB NOT NULL DEFAULT '[]',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE INDEX IF NOT EXISTS idx_events_org ON telemetry_events (organization_id, timestamp_ms DESC);

		CREATE TABLE IF NOT EXISTS alerts (
			alert_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			severity alert_severity NOT NULL,
			event_id UUID NOT NULL REFERENCES telemetry_events(event_id) ON DELETE CASCADE,
			pattern_name TEXT,
			description TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE INDEX IF NOT EXISTS idx_alerts_org ON alerts (organization_id, created_at DESC);

		CREATE TABLE IF NOT EXISTS identity_credentials (
			credential_id TEXT PRIMARY KEY,
			organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			agent_id TEXT NOT NULL,
			scope TEXT NOT NULL DEFAULT '',
			ttl_seconds INT NOT NULL DEFAULT 3600,
			created_at_ms BIGINT NOT NULL DEFAULT 0,
			expires_at_ms BIGINT NOT NULL DEFAULT 0,
			last_rotated_at_ms BIGINT NOT NULL DEFAULT 0,
			rotation_history JSONB NOT NULL DEFAULT '[]',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);

		CREATE TABLE IF NOT EXISTS mcp_servers (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			agent_id TEXT NOT NULL,
			ide_target TEXT NOT NULL DEFAULT 'cursor',
			server_name TEXT NOT NULL,
			wrapped BOOLEAN NOT NULL DEFAULT false,
			path_verified BOOLEAN NOT NULL DEFAULT false,
			command TEXT,
			tools_count INT NOT NULL DEFAULT 0,
			tools_list JSONB NOT NULL DEFAULT '[]',
			last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT uq_mcp_servers_agent_ide_server UNIQUE (organization_id, agent_id, ide_target, server_name)
		);
	`
	_, err := s.pool.Exec(ctx, q)
	return err
}

// UpsertAgent ensures the agent exists within an organization.
func (s *Store) UpsertAgent(ctx context.Context, organizationID, agentID string) error {
	if s.pool == nil {
		return nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agents (organization_id, agent_id, first_seen_at, last_seen_at)
		VALUES ($1, $2, now(), now())
		ON CONFLICT (agent_id) DO UPDATE SET
			organization_id = EXCLUDED.organization_id,
			last_seen_at    = now(),
			updated_at      = now()
	`, organizationID, agentID)
	return err
}

// CountDistinctAgents returns the count of non-revoked enrolled devices.
func (s *Store) CountDistinctAgents(ctx context.Context, organizationID string) (int, error) {
	return s.CountEnrolledDevices(ctx, organizationID)
}

// AgentExists returns true if the specified agentID exists.
func (s *Store) AgentExists(ctx context.Context, organizationID, agentID string) (bool, error) {
	if s.pool == nil {
		return false, nil
	}
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = $1)`, agentID).Scan(&exists)
	return exists, err
}

// ResolveTenantIDForAgent checks if an agent or device belongs to a known organization.
func (s *Store) ResolveTenantIDForAgent(ctx context.Context, agentID string) string {
	if s.pool == nil || agentID == "" {
		return DefaultOrgID
	}
	var orgID string
	err := s.pool.QueryRow(ctx, `
		SELECT organization_id::text FROM devices 
		WHERE stable_device_id = $1 OR id::text = $1 
		LIMIT 1
	`, agentID).Scan(&orgID)
	if err == nil && orgID != "" {
		return orgID
	}
	err = s.pool.QueryRow(ctx, `
		SELECT organization_id::text FROM agents 
		WHERE agent_id = $1 
		LIMIT 1
	`, agentID).Scan(&orgID)
	if err == nil && orgID != "" {
		return orgID
	}
	return DefaultOrgID
}

// InsertEvent persists a redacted event. Caller must UpsertAgent first.
func (s *Store) InsertEvent(ctx context.Context, organizationID string, e *model.RedactedEvent) error {
	if s.pool == nil {
		return nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	dlp, _ := json.Marshal(e.DlpFindings)
	inj, _ := json.Marshal(e.InjectionFindings)
	sem, _ := json.Marshal(e.SemanticFindings)

	_, err := s.pool.Exec(ctx, `
		INSERT INTO telemetry_events
			(organization_id, event_id, timestamp_ms, session_id, agent_id, tool_name,
			 decision, dlp_findings, injection_findings, semantic_findings)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, organizationID, e.EventID, e.TimestampMs, e.SessionID, e.AgentID, e.ToolName,
		e.Decision, dlp, inj, sem)
	return err
}

// InsertAlert persists an alert.
func (s *Store) InsertAlert(ctx context.Context, organizationID string, a *model.RedactedAlert) error {
	if s.pool == nil {
		return nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO alerts (organization_id, alert_id, severity, event_id)
		VALUES ($1, $2, $3, $4)
	`, organizationID, a.AlertID, a.Severity, a.Event.EventID)
	return err
}

// UpsertCredential persists or updates credential metadata.
func (s *Store) UpsertCredential(ctx context.Context, organizationID string, c *model.SanitizedCredentialMeta) error {
	if s.pool == nil {
		return nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	history, _ := json.Marshal(c.RotationHistory)

	_, err := s.pool.Exec(ctx, `
		INSERT INTO identity_credentials
			(organization_id, credential_id, agent_id, scope, ttl_seconds,
			 created_at_ms, expires_at_ms, last_rotated_at_ms, rotation_history)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (credential_id) DO UPDATE SET
			organization_id    = EXCLUDED.organization_id,
			scope              = EXCLUDED.scope,
			ttl_seconds        = EXCLUDED.ttl_seconds,
			expires_at_ms      = EXCLUDED.expires_at_ms,
			last_rotated_at_ms = EXCLUDED.last_rotated_at_ms,
			rotation_history   = EXCLUDED.rotation_history,
			updated_at         = now()
	`, organizationID, c.CredentialID, c.AgentID, c.Scope, c.TTLSeconds,
		c.CreatedAtMs, c.ExpiresAtMs, c.LastRotatedAtMs, history)
	return err
}

type AgentSummary struct {
	AgentID       string    `json:"agent_id"`
	DisplayName   *string   `json:"display_name"`
	Status        string    `json:"status"`
	PolicyVersion *string   `json:"policy_version"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	EventCount    int64     `json:"event_count"`
	AlertCount    int64     `json:"alert_count"`
}

func (s *Store) ListAgents(ctx context.Context, organizationID string, limit, offset int, hours int) ([]AgentSummary, error) {
	if s.pool == nil {
		return []AgentSummary{}, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	if limit <= 0 {
		limit = 50
	}
	if hours <= 0 {
		hours = 24
	}
	rows, err := s.pool.Query(ctx, `
		WITH paged_agents AS (
			SELECT agent_id, display_name, status, policy_version, last_seen_at
			FROM agents
			WHERE organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid
			ORDER BY last_seen_at DESC
			LIMIT $2 OFFSET $3
		)
		SELECT
			pa.agent_id,
			pa.display_name,
			pa.status,
			pa.policy_version,
			pa.last_seen_at,
			COALESCE(e.cnt, 0) AS event_count,
			COALESCE(al.cnt, 0) AS alert_count
		FROM paged_agents pa
		LEFT JOIN (
			SELECT agent_id, COUNT(*) AS cnt
			FROM telemetry_events
			WHERE (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
			  AND created_at >= NOW() - ($4 || ' hours')::interval
			  AND agent_id IN (SELECT agent_id FROM paged_agents)
			GROUP BY agent_id
		) e ON e.agent_id = pa.agent_id
		LEFT JOIN (
			SELECT te.agent_id, COUNT(*) AS cnt
			FROM alerts al
			JOIN telemetry_events te ON te.event_id = al.event_id
			WHERE (al.organization_id::text = $1 OR al.organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
			  AND al.created_at >= NOW() - ($4 || ' hours')::interval
			  AND te.agent_id IN (SELECT agent_id FROM paged_agents)
			GROUP BY te.agent_id
		) al ON al.agent_id = pa.agent_id
		ORDER BY pa.last_seen_at DESC
	`, organizationID, limit, offset, hours)
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
	TotalAgents    int64 `json:"total_agents"`
	ActiveAgents   int64 `json:"active_agents"`
	TotalEvents    int64 `json:"total_events"`
	DeniedEvents   int64 `json:"denied_events"`
	TotalAlerts    int64 `json:"total_alerts"`
	CriticalAlerts int64 `json:"critical_alerts"`
}

func (s *Store) GetFleetStats(ctx context.Context, organizationID string, hours int) (*FleetStats, error) {
	if s.pool == nil {
		return &FleetStats{}, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	if hours <= 0 {
		hours = 24
	}
	var stats FleetStats
	err := s.pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM devices WHERE state != 'REVOKED'),
			(SELECT COUNT(*) FROM devices WHERE state = 'COMPLIANT' AND last_heartbeat_at >= NOW() - INTERVAL '3 minutes'),
			(SELECT COUNT(*) FROM telemetry_events WHERE (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid) AND created_at >= NOW() - ($2 || ' hours')::interval),
			(SELECT COUNT(*) FROM telemetry_events WHERE (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid) AND decision = 'denied' AND created_at >= NOW() - ($2 || ' hours')::interval),
			(SELECT COUNT(*) FROM alerts WHERE (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid) AND created_at >= NOW() - ($2 || ' hours')::interval),
			(SELECT COUNT(*) FROM alerts WHERE (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid) AND severity = 'critical' AND created_at >= NOW() - ($2 || ' hours')::interval)
	`, organizationID, hours).Scan(&stats.TotalAgents, &stats.ActiveAgents, &stats.TotalEvents,
		&stats.DeniedEvents, &stats.TotalAlerts, &stats.CriticalAlerts)
	return &stats, err
}

func (s *Store) ListRecentAlerts(ctx context.Context, organizationID string, limit int, hours int) ([]model.RedactedAlert, error) {
	if s.pool == nil {
		return []model.RedactedAlert{}, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	if hours <= 0 {
		hours = 24
	}
	rows, err := s.pool.Query(ctx, `
		SELECT
			a.alert_id, a.severity,
			e.event_id, e.timestamp_ms, e.session_id, e.agent_id,
			e.tool_name, e.decision,
			e.dlp_findings, e.injection_findings, e.semantic_findings
		FROM alerts a
		JOIN telemetry_events e ON e.event_id = a.event_id
		WHERE (a.organization_id::text = $1 OR a.organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
		  AND a.created_at >= NOW() - ($3 || ' hours')::interval
		ORDER BY a.created_at DESC
		LIMIT $2
	`, organizationID, limit, hours)
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

func (s *Store) ListRecentEvents(ctx context.Context, organizationID, agentID string, limit int) ([]RecentEvent, error) {
	if s.pool == nil {
		return []RecentEvent{}, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	query := `
		SELECT event_id, timestamp_ms, session_id, agent_id, tool_name,
		       decision, dlp_findings, injection_findings, semantic_findings, created_at
		FROM telemetry_events
		WHERE organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid
	`
	var args []any
	if agentID != "" {
		query += ` AND agent_id = $2 ORDER BY timestamp_ms DESC LIMIT $3`
		args = []any{organizationID, agentID, limit}
	} else {
		query += ` ORDER BY timestamp_ms DESC LIMIT $2`
		args = []any{organizationID, limit}
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

func (s *Store) ListCredentials(ctx context.Context, organizationID, agentID string) ([]model.SanitizedCredentialMeta, error) {
	if s.pool == nil {
		return []model.SanitizedCredentialMeta{}, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	query := `
		SELECT credential_id, agent_id, scope, ttl_seconds,
		       created_at_ms, expires_at_ms, last_rotated_at_ms, rotation_history
		FROM identity_credentials
		WHERE organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid
	`
	var args []any
	if agentID != "" {
		query += ` AND agent_id = $2 ORDER BY expires_at_ms ASC`
		args = []any{organizationID, agentID}
	} else {
		query += ` ORDER BY expires_at_ms ASC`
		args = []any{organizationID}
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

type DecisionBreakdown struct {
	Hour    string `json:"hour"`
	Allowed int64  `json:"allowed"`
	Denied  int64  `json:"denied"`
	Warned  int64  `json:"warned"`
}

func (s *Store) GetDecisionHeatmap(ctx context.Context, organizationID string, hours int) ([]DecisionBreakdown, error) {
	if s.pool == nil {
		return []DecisionBreakdown{}, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	rows, err := s.pool.Query(ctx, `
		SELECT
			to_char(to_timestamp(timestamp_ms / 1000) AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:00') AS hour,
			COUNT(*) FILTER (WHERE decision = 'allowed') AS allowed,
			COUNT(*) FILTER (WHERE decision = 'denied')  AS denied,
			COUNT(*) FILTER (WHERE decision = 'warned')  AS warned
		FROM telemetry_events
		WHERE (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
		  AND timestamp_ms > (EXTRACT(EPOCH FROM now()) * 1000 - $2 * 3600000)::BIGINT
		GROUP BY hour
		ORDER BY hour
	`, organizationID, hours)
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

type ThreatSummary struct {
	DlpTotal       int64 `json:"dlp_total"`
	InjectionTotal int64 `json:"injection_total"`
	SemanticTotal  int64 `json:"semantic_total"`
	EventsWithDlp  int64 `json:"events_with_dlp"`
	EventsWithInj  int64 `json:"events_with_injection"`
	EventsWithSem  int64 `json:"events_with_semantic"`
}

func (s *Store) GetThreatSummary(ctx context.Context, organizationID string, hours int) (*ThreatSummary, error) {
	if s.pool == nil {
		return &ThreatSummary{}, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
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
		WHERE (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
		  AND timestamp_ms > (EXTRACT(EPOCH FROM now()) * 1000 - $2 * 3600000)::BIGINT
	`, organizationID, hours).Scan(
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

func (s *Store) GetThreatTimeline(ctx context.Context, organizationID string, hours int) ([]ThreatTimelinePoint, error) {
	if s.pool == nil {
		return []ThreatTimelinePoint{}, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	rows, err := s.pool.Query(ctx, `
		SELECT
			to_char(to_timestamp(timestamp_ms / 1000) AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:00') AS hour,
			COALESCE(SUM(jsonb_array_length(dlp_findings)), 0),
			COALESCE(SUM(jsonb_array_length(injection_findings)), 0),
			COALESCE(SUM(jsonb_array_length(semantic_findings)), 0)
		FROM telemetry_events
		WHERE (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
		  AND timestamp_ms > (EXTRACT(EPOCH FROM now()) * 1000 - $2 * 3600000)::BIGINT
		GROUP BY hour
		ORDER BY hour
	`, organizationID, hours)
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

func (s *Store) GetTopThreatPatterns(ctx context.Context, organizationID string, hours int, limit int) ([]ThreatPattern, error) {
	if s.pool == nil {
		return []ThreatPattern{}, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
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
			WHERE (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
			  AND timestamp_ms > (EXTRACT(EPOCH FROM now()) * 1000 - $2 * 3600000)::BIGINT
		),
		injection AS (
			SELECT
				'injection' AS type,
				f->>'pattern_name' AS pattern_name,
				'' AS category,
				(f->>'count')::BIGINT AS cnt
			FROM telemetry_events,
				jsonb_array_elements(injection_findings) AS f
			WHERE (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
			  AND timestamp_ms > (EXTRACT(EPOCH FROM now()) * 1000 - $2 * 3600000)::BIGINT
		),
		semantic AS (
			SELECT
				'semantic' AS type,
				f->>'finding_type' AS pattern_name,
				'' AS category,
				1::BIGINT AS cnt
			FROM telemetry_events,
				jsonb_array_elements(semantic_findings) AS f
			WHERE (organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
			  AND timestamp_ms > (EXTRACT(EPOCH FROM now()) * 1000 - $2 * 3600000)::BIGINT
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
	`, organizationID, hours, limit)
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

func RunMigrations(ctx context.Context, pool *pgxpool.Pool, migrationSQL string) error {
	_, err := pool.Exec(ctx, migrationSQL)
	return err
}

type McpServerInventoryRow struct {
	AgentID      string `json:"agent_id"`
	HostName     string `json:"hostname,omitempty"`
	IDETarget    string `json:"ide_target"`
	ServerName   string `json:"server_name"`
	Wrapped      bool   `json:"wrapped"`
	PathVerified bool   `json:"path_verified"`
	LastSeenAt   string `json:"last_seen_at"`
}

func (s *Store) UpsertMcpServer(ctx context.Context, organizationID, agentID string, m *model.SanitizedMcpServerMeta) error {
	if s.pool == nil {
		return nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO mcp_servers
			(organization_id, agent_id, ide_target, server_name, wrapped, path_verified, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, now())
		ON CONFLICT (organization_id, agent_id, ide_target, server_name) DO UPDATE SET
			wrapped       = EXCLUDED.wrapped,
			path_verified = EXCLUDED.path_verified,
			last_seen_at  = now()
	`, organizationID, agentID, m.IDETarget, m.ServerName, m.Wrapped, m.PathVerified)
	return err
}

func (s *Store) ListMcpServersByAgent(ctx context.Context, organizationID, agentID string) ([]McpServerInventoryRow, error) {
	if s.pool == nil {
		return []McpServerInventoryRow{}, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	rows, err := s.pool.Query(ctx, `
		SELECT 
			m.agent_id, 
			COALESCE(NULLIF(dev.display_name, ''), NULLIF(dev.stable_device_id, ''), m.agent_id) AS hostname,
			m.ide_target, 
			m.server_name, 
			m.wrapped, 
			m.path_verified, 
			m.last_seen_at
		FROM mcp_servers m
		LEFT JOIN devices dev ON dev.id::text = m.agent_id OR dev.stable_device_id = m.agent_id OR LOWER(dev.display_name) = LOWER(m.agent_id)
		WHERE (m.organization_id::text = $1 OR m.organization_id = '00000000-0000-0000-0000-000000000001'::uuid)
		  AND m.agent_id = $2
		ORDER BY m.last_seen_at DESC
	`, organizationID, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []McpServerInventoryRow
	for rows.Next() {
		var sr McpServerInventoryRow
		var lastSeen time.Time
		if err := rows.Scan(&sr.AgentID, &sr.HostName, &sr.IDETarget, &sr.ServerName, &sr.Wrapped, &sr.PathVerified, &lastSeen); err != nil {
			return nil, err
		}
		sr.LastSeenAt = lastSeen.Format(time.RFC3339)
		servers = append(servers, sr)
	}
	return servers, rows.Err()
}

func (s *Store) ListMcpServersFleetWide(ctx context.Context, organizationID string) ([]McpServerInventoryRow, error) {
	if s.pool == nil {
		return []McpServerInventoryRow{}, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	rows, err := s.pool.Query(ctx, `
		SELECT 
			m.agent_id, 
			COALESCE(NULLIF(dev.display_name, ''), NULLIF(dev.stable_device_id, ''), m.agent_id) AS hostname,
			m.ide_target, 
			m.server_name, 
			m.wrapped, 
			m.path_verified, 
			m.last_seen_at
		FROM mcp_servers m
		LEFT JOIN devices dev ON dev.id::text = m.agent_id OR dev.stable_device_id = m.agent_id OR LOWER(dev.display_name) = LOWER(m.agent_id)
		WHERE m.organization_id::text = $1 OR m.organization_id = '00000000-0000-0000-0000-000000000001'::uuid
		ORDER BY m.last_seen_at DESC
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []McpServerInventoryRow
	for rows.Next() {
		var sr McpServerInventoryRow
		var lastSeen time.Time
		if err := rows.Scan(&sr.AgentID, &sr.HostName, &sr.IDETarget, &sr.ServerName, &sr.Wrapped, &sr.PathVerified, &lastSeen); err != nil {
			return nil, err
		}
		sr.LastSeenAt = lastSeen.Format(time.RFC3339)
		servers = append(servers, sr)
	}
	return servers, rows.Err()
}

// EnsureAllSchemas initializes all database schemas idempotently.
func (s *Store) EnsureAllSchemas(ctx context.Context) error {
	log.Printf("Ensuring baseline PostgreSQL database schemas...")
	if err := s.EnsureOrganizationsSchema(ctx); err != nil {
		log.Printf("EnsureOrganizationsSchema warning: %v", err)
	}
	if err := s.EnsureCoreSchema(ctx); err != nil {
		log.Printf("EnsureCoreSchema warning: %v", err)
	}
	if err := s.EnsureAuthProvidersSchema(ctx); err != nil {
		log.Printf("EnsureAuthProvidersSchema warning: %v", err)
	}
	if err := s.EnsureDevicesSchema(ctx); err != nil {
		log.Printf("EnsureDevicesSchema warning: %v", err)
	}
	if err := s.EnsureEnrollmentV2Schema(ctx); err != nil {
		log.Printf("EnsureEnrollmentV2Schema warning: %v", err)
	}
	if err := s.EnsureVirtualKeysSchema(ctx); err != nil {
		log.Printf("EnsureVirtualKeysSchema warning: %v", err)
	}
	if err := s.EnsureProviderKeysSchema(ctx); err != nil {
		log.Printf("EnsureProviderKeysSchema warning: %v", err)
	}
	if err := s.EnsurePoliciesSchema(ctx); err != nil {
		log.Printf("EnsurePoliciesSchema warning: %v", err)
	}
	if err := s.EnsureGroupPoliciesSchema(ctx); err != nil {
		log.Printf("EnsureGroupPoliciesSchema warning: %v", err)
	}
	if err := s.EnsureAuditEventsSchema(ctx); err != nil {
		log.Printf("EnsureAuditEventsSchema warning: %v", err)
	}
	return nil
}
