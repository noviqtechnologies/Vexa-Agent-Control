package store

import (
	"context"
	"errors"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

// EnsureAttributionsSchema ensures the request_attributions table exists.
func (s *Store) EnsureAttributionsSchema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	q := `
		CREATE TABLE IF NOT EXISTS request_attributions (
			id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			request_id        TEXT NOT NULL,
			organization_id   UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			device_id         TEXT NOT NULL,
			user_id           TEXT NOT NULL,
			identity_source   TEXT NOT NULL DEFAULT 'local_os',
			identity_verified BOOLEAN NOT NULL DEFAULT false,
			assignment_id     UUID REFERENCES assignments(id) ON DELETE SET NULL,
			provider          TEXT NOT NULL,
			model             TEXT NOT NULL,
			status_code       INT NOT NULL DEFAULT 200,
			input_tokens      BIGINT NOT NULL DEFAULT 0,
			output_tokens     BIGINT NOT NULL DEFAULT 0,
			created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE INDEX IF NOT EXISTS idx_attributions_org_created ON request_attributions(organization_id, created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_attributions_device ON request_attributions(device_id, created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_attributions_user ON request_attributions(organization_id, user_id, created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_attributions_assignment ON request_attributions(assignment_id);
	`
	_, err := s.pool.Exec(ctx, q)
	return err
}

// RecordRequestAttribution writes an immutable attribution log entry (REQ-VER-003).
func (s *Store) RecordRequestAttribution(ctx context.Context, attr *model.RequestAttribution) error {
	if s.pool == nil {
		return errors.New("database pool uninitialized")
	}
	if attr.OrganizationID == "" {
		attr.OrganizationID = DefaultOrgID
	}
	if attr.IdentitySource == "" {
		attr.IdentitySource = "local_os"
	}

	query := `
		INSERT INTO request_attributions (
			request_id, organization_id, device_id, user_id, identity_source, identity_verified,
			assignment_id, provider, model, status_code, input_tokens, output_tokens, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11, $12, now()
		)
		RETURNING id, created_at
	`
	return s.pool.QueryRow(ctx, query,
		attr.RequestID,
		attr.OrganizationID,
		attr.DeviceID,
		attr.UserID,
		attr.IdentitySource,
		attr.IdentityVerified,
		attr.AssignmentID,
		attr.Provider,
		attr.Model,
		attr.StatusCode,
		attr.InputTokens,
		attr.OutputTokens,
	).Scan(&attr.ID, &attr.CreatedAt)
}

// ListRequestAttributionsForDevice returns the recent attribution log for a device.
func (s *Store) ListRequestAttributionsForDevice(ctx context.Context, organizationID, deviceID string, limit int) ([]*model.RequestAttribution, error) {
	if s.pool == nil {
		return nil, errors.New("database pool uninitialized")
	}
	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT id, request_id, organization_id, device_id, user_id, identity_source, identity_verified,
		       assignment_id, provider, model, status_code, input_tokens, output_tokens, created_at
		FROM request_attributions
		WHERE organization_id = $1 AND device_id = $2
		ORDER BY created_at DESC
		LIMIT $3
	`
	rows, err := s.pool.Query(ctx, query, organizationID, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*model.RequestAttribution
	for rows.Next() {
		var attr model.RequestAttribution
		var asgnID *string
		if err := rows.Scan(
			&attr.ID,
			&attr.RequestID,
			&attr.OrganizationID,
			&attr.DeviceID,
			&attr.UserID,
			&attr.IdentitySource,
			&attr.IdentityVerified,
			&asgnID,
			&attr.Provider,
			&attr.Model,
			&attr.StatusCode,
			&attr.InputTokens,
			&attr.OutputTokens,
			&attr.CreatedAt,
		); err != nil {
			return nil, err
		}
		attr.AssignmentID = asgnID
		results = append(results, &attr)
	}

	return results, rows.Err()
}
