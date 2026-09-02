package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// AuditEvent represents an administrative / management plane mutation record.
type AuditEvent struct {
	ID             string                 `json:"id"`
	OrganizationID string                 `json:"organization_id"`
	TenantID       string                 `json:"tenant_id"` // Alias
	Timestamp      time.Time              `json:"timestamp"`
	TableName      string                 `json:"table_name"`
	Action         string                 `json:"action"`
	ChangedBy      string                 `json:"changed_by"`
	ActorRole      string                 `json:"actor_role,omitempty"`
	AffectedItemID string                 `json:"affected_item_id"`
	BeforeValue    map[string]interface{} `json:"before_value,omitempty"`
	UpdatedValue   map[string]interface{} `json:"updated_value,omitempty"`
	IPAddress      string                 `json:"ip_address,omitempty"`
	Outcome        string                 `json:"outcome,omitempty"`
}

// AuditLogFilter defines search and faceted filtering options for audit logs.
type AuditLogFilter struct {
	Limit     int
	Offset    int
	ObjectID  string
	TableName string
	Action    string
	ChangedBy string
	Since     time.Time
}

// EnsureAuditEventsSchema idempotently ensures audit_events table exists.
func (s *Store) EnsureAuditEventsSchema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	query := `
	CREATE TABLE IF NOT EXISTS audit_events (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
		correlation_id UUID,
		request_id UUID,
		action TEXT NOT NULL,
		actor_type TEXT DEFAULT 'USER',
		actor_ref TEXT DEFAULT '',
		actor_subject TEXT DEFAULT '',
		actor_role TEXT DEFAULT 'admin',
		resource_type TEXT DEFAULT '',
		resource_id TEXT DEFAULT '',
		outcome TEXT DEFAULT 'SUCCESS',
		reason_code TEXT DEFAULT '',
		target_type TEXT DEFAULT '',
		target_id TEXT DEFAULT '',
		diff_json JSONB NOT NULL DEFAULT '{}',
		ip_address TEXT DEFAULT '',
		occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
	);
	CREATE INDEX IF NOT EXISTS idx_audit_events_org_time ON audit_events (organization_id, occurred_at DESC);
	`
	_, err := s.pool.Exec(ctx, query)
	return err
}

// InsertAuditEvent writes an immutable administrative audit record.
func (s *Store) InsertAuditEvent(ctx context.Context, organizationID string, e *AuditEvent) error {
	if s.pool == nil {
		return nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.Outcome == "" {
		e.Outcome = "SUCCESS"
	}

	diffPayload := map[string]interface{}{}
	if e.BeforeValue != nil {
		diffPayload["before"] = e.BeforeValue
	}
	if e.UpdatedValue != nil {
		diffPayload["updated"] = e.UpdatedValue
	}
	diffBytes, _ := json.Marshal(diffPayload)

	query := `
	INSERT INTO audit_events (
		organization_id, action, actor_subject, actor_role, resource_type, resource_id,
		diff_json, ip_address, outcome, occurred_at
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
	)`

	_, err := s.pool.Exec(ctx, query,
		organizationID, e.Action, e.ChangedBy, e.ActorRole, e.TableName, e.AffectedItemID,
		diffBytes, e.IPAddress, e.Outcome, e.Timestamp,
	)
	return err
}

// ListAuditLogs returns filtered and paginated management plane audit logs.
func (s *Store) ListAuditLogs(ctx context.Context, organizationID string, filter AuditLogFilter) ([]AuditEvent, int, error) {
	if s.pool == nil {
		return []AuditEvent{}, 0, nil
	}
	if organizationID == "" {
		organizationID = DefaultOrgID
	}

	if filter.Limit <= 0 || filter.Limit > 500 {
		filter.Limit = 50
	}

	countSQL := `SELECT COUNT(*) FROM audit_events WHERE organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid`
	querySQL := `
	SELECT id::text, organization_id::text, action, COALESCE(actor_subject, actor_ref, 'admin'),
	       COALESCE(actor_role, 'admin'), COALESCE(resource_type, target_type, 'unknown'),
	       COALESCE(resource_id, target_id, ''), diff_json, COALESCE(ip_address, ''),
	       COALESCE(outcome, 'SUCCESS'), occurred_at
	FROM audit_events
	WHERE organization_id::text = $1 OR organization_id = '00000000-0000-0000-0000-000000000001'::uuid`

	args := []interface{}{organizationID}
	argIdx := 2

	if filter.ObjectID != "" {
		clause := fmt.Sprintf(" AND (resource_id ILIKE $%d OR target_id ILIKE $%d OR id::text ILIKE $%d)", argIdx, argIdx, argIdx)
		countSQL += clause
		querySQL += clause
		args = append(args, "%"+filter.ObjectID+"%")
		argIdx++
	}
	if filter.TableName != "" && filter.TableName != "all" {
		clause := fmt.Sprintf(" AND LOWER(COALESCE(resource_type, target_type, '')) = LOWER($%d)", argIdx)
		countSQL += clause
		querySQL += clause
		args = append(args, filter.TableName)
		argIdx++
	}
	if filter.Action != "" && filter.Action != "all" {
		clause := fmt.Sprintf(" AND LOWER(action) = LOWER($%d)", argIdx)
		countSQL += clause
		querySQL += clause
		args = append(args, filter.Action)
		argIdx++
	}
	if filter.ChangedBy != "" {
		clause := fmt.Sprintf(" AND (actor_subject ILIKE $%d OR actor_ref ILIKE $%d)", argIdx, argIdx)
		countSQL += clause
		querySQL += clause
		args = append(args, "%"+filter.ChangedBy+"%")
		argIdx++
	}
	if !filter.Since.IsZero() {
		clause := fmt.Sprintf(" AND occurred_at >= $%d", argIdx)
		countSQL += clause
		querySQL += clause
		args = append(args, filter.Since)
		argIdx++
	}

	var totalCount int
	_ = s.pool.QueryRow(ctx, countSQL, args...).Scan(&totalCount)

	querySQL += fmt.Sprintf(" ORDER BY occurred_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	queryArgs := append(args, filter.Limit, filter.Offset)

	rows, err := s.pool.Query(ctx, querySQL, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()

	events := make([]AuditEvent, 0)
	for rows.Next() {
		var e AuditEvent
		var diffJSON []byte
		if err := rows.Scan(
			&e.ID, &e.OrganizationID, &e.Action, &e.ChangedBy,
			&e.ActorRole, &e.TableName, &e.AffectedItemID,
			&diffJSON, &e.IPAddress, &e.Outcome, &e.Timestamp,
		); err != nil {
			continue
		}
		e.TenantID = e.OrganizationID

		if len(diffJSON) > 0 {
			var parsed map[string]interface{}
			if err := json.Unmarshal(diffJSON, &parsed); err == nil {
				if before, ok := parsed["before"].(map[string]interface{}); ok {
					e.BeforeValue = before
				}
				if updated, ok := parsed["updated"].(map[string]interface{}); ok {
					e.UpdatedValue = updated
				} else if after, ok := parsed["after"].(map[string]interface{}); ok {
					e.UpdatedValue = after
				} else if e.BeforeValue == nil {
					e.UpdatedValue = parsed
				}
			}
		}

		events = append(events, e)
	}

	return events, totalCount, rows.Err()
}
