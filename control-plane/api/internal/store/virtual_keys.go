package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrVirtualKeyNotFound       = errors.New("virtual key not found")
	ErrVirtualKeyBudgetExceeded = errors.New("virtual key budget exceeded")
)

// VirtualKey represents a scoped, governable API key for LLM gateway access (Pillar 1).
type VirtualKey struct {
	ID                      string            `json:"id" db:"id"`
	TenantID                string            `json:"tenant_id" db:"tenant_id"`
	KeyHash                 string            `json:"-" db:"key_hash"`
	KeyPrefix               string            `json:"key_prefix" db:"key_prefix"`
	PreviousKeyHash         *string           `json:"-" db:"previous_key_hash"`
	PreviousKeyExpiresAt    *time.Time        `json:"previous_key_expires_at,omitempty" db:"previous_key_expires_at"`
	Name                    string            `json:"name" db:"name"`
	TeamID                  string            `json:"team_id" db:"team_id"`
	CreatedBy               string            `json:"created_by" db:"created_by"`
	CreatedAt               time.Time         `json:"created_at" db:"created_at"`
	ExpiresAt               *time.Time        `json:"expires_at,omitempty" db:"expires_at"`
	AllowedIPs              []string          `json:"allowed_ips" db:"allowed_ips"`
	MaxRPM                  int               `json:"max_rpm" db:"max_rpm"`
	MaxTPM                  int               `json:"max_tpm" db:"max_tpm"`
	MaxConcurrentRequests   int               `json:"max_concurrent_requests" db:"max_concurrent_requests"`
	MonthlyBudgetMicrocents int64             `json:"monthly_budget_microcents" db:"monthly_budget_microcents"`
	SpentMicrocents         int64             `json:"spent_microcents" db:"spent_microcents"`
	AllowedModels           []string          `json:"allowed_models" db:"allowed_models"`
	AllowedRoutes           []string          `json:"allowed_routes" db:"allowed_routes"`
	Status                  string            `json:"status" db:"status"` // "active", "rotating", "revoked"
	Tags                    map[string]string `json:"tags,omitempty" db:"tags"`
	OwnerType               string            `json:"owner_type" db:"owner_type"`       // "user", "service_account", "agent"
	BudgetPeriod            string            `json:"budget_period" db:"budget_period"` // "monthly", "weekly", "daily"
	DeletedAt               *time.Time        `json:"deleted_at,omitempty" db:"deleted_at"`
	DeletedBy               string            `json:"deleted_by,omitempty" db:"deleted_by"`
	DeletedReason           string            `json:"deleted_reason,omitempty" db:"deleted_reason"`
}

// EnsureVirtualKeysSchema idempotently creates the virtual_keys table in PostgreSQL.
func (s *Store) EnsureVirtualKeysSchema(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS virtual_keys (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		tenant_id UUID NOT NULL,
		key_hash TEXT NOT NULL,
		key_prefix TEXT NOT NULL,
		previous_key_hash TEXT,
		previous_key_expires_at TIMESTAMPTZ,
		name TEXT NOT NULL,
		team_id TEXT DEFAULT '',
		created_by TEXT DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		expires_at TIMESTAMPTZ,
		allowed_ips TEXT[] DEFAULT '{}',
		max_rpm INT DEFAULT 0,
		max_tpm INT DEFAULT 0,
		max_concurrent_requests INT DEFAULT 0,
		monthly_budget_microcents BIGINT NOT NULL DEFAULT 0,
		spent_microcents BIGINT NOT NULL DEFAULT 0,
		allowed_models TEXT[] DEFAULT '{}',
		allowed_routes TEXT[] DEFAULT '{}',
		status TEXT NOT NULL DEFAULT 'active',
		tags JSONB DEFAULT '{}',
		owner_type TEXT NOT NULL DEFAULT 'user',
		budget_period TEXT NOT NULL DEFAULT 'monthly',
		deleted_at TIMESTAMPTZ,
		deleted_by TEXT,
		deleted_reason TEXT,
		CONSTRAINT unique_key_hash_per_tenant UNIQUE(tenant_id, key_hash)
	);
	ALTER TABLE virtual_keys ADD COLUMN IF NOT EXISTS owner_type TEXT NOT NULL DEFAULT 'user';
	ALTER TABLE virtual_keys ADD COLUMN IF NOT EXISTS budget_period TEXT NOT NULL DEFAULT 'monthly';
	ALTER TABLE virtual_keys ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
	ALTER TABLE virtual_keys ADD COLUMN IF NOT EXISTS deleted_by TEXT;
	ALTER TABLE virtual_keys ADD COLUMN IF NOT EXISTS deleted_reason TEXT;
	CREATE INDEX IF NOT EXISTS idx_virtual_keys_tenant ON virtual_keys(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_virtual_keys_hash ON virtual_keys(key_hash);
	CREATE INDEX IF NOT EXISTS idx_virtual_keys_prev_hash ON virtual_keys(previous_key_hash);
	CREATE INDEX IF NOT EXISTS idx_virtual_keys_deleted ON virtual_keys(tenant_id, deleted_at DESC);
	`
	_, err := s.pool.Exec(ctx, query)
	return err
}

func scanVirtualKey(row pgx.Row) (*VirtualKey, error) {
	var k VirtualKey
	var allowedIPs, allowedModels, allowedRoutes []string
	var tagsJSON []byte

	err := row.Scan(
		&k.ID, &k.TenantID, &k.KeyHash, &k.KeyPrefix, &k.PreviousKeyHash, &k.PreviousKeyExpiresAt,
		&k.Name, &k.TeamID, &k.CreatedBy, &k.CreatedAt, &k.ExpiresAt,
		&allowedIPs, &k.MaxRPM, &k.MaxTPM, &k.MaxConcurrentRequests,
		&k.MonthlyBudgetMicrocents, &k.SpentMicrocents,
		&allowedModels, &allowedRoutes, &k.Status, &tagsJSON,
		&k.OwnerType, &k.BudgetPeriod,
		&k.DeletedAt, &k.DeletedBy, &k.DeletedReason,
	)
	if err != nil {
		return nil, err
	}

	if allowedIPs == nil {
		allowedIPs = []string{}
	}
	if allowedModels == nil {
		allowedModels = []string{}
	}
	if allowedRoutes == nil {
		allowedRoutes = []string{}
	}

	k.AllowedIPs = allowedIPs
	k.AllowedModels = allowedModels
	k.AllowedRoutes = allowedRoutes
	if k.OwnerType == "" {
		k.OwnerType = "user"
	}
	if k.BudgetPeriod == "" {
		k.BudgetPeriod = "monthly"
	}
	if len(tagsJSON) > 0 {
		_ = json.Unmarshal(tagsJSON, &k.Tags)
	}
	return &k, nil
}

const virtualKeySelectColumns = `id, tenant_id, key_hash, key_prefix, previous_key_hash, previous_key_expires_at,
	name, team_id, created_by, created_at, expires_at, allowed_ips, max_rpm, max_tpm,
	max_concurrent_requests, monthly_budget_microcents, spent_microcents, allowed_models,
	allowed_routes, status, tags, owner_type, budget_period,
	deleted_at, COALESCE(deleted_by, ''), COALESCE(deleted_reason, '')`


func (s *Store) CreateVirtualKey(ctx context.Context, tenantID string, k *VirtualKey) error {
	k.TenantID = tenantID
	k.CreatedAt = time.Now().UTC()
	if k.Status == "" {
		k.Status = "active"
	}
	if k.OwnerType == "" {
		k.OwnerType = "user"
	}
	if k.BudgetPeriod == "" {
		k.BudgetPeriod = "monthly"
	}
	if k.AllowedIPs == nil {
		k.AllowedIPs = []string{}
	}
	if k.AllowedModels == nil {
		k.AllowedModels = []string{}
	}
	if k.AllowedRoutes == nil {
		k.AllowedRoutes = []string{}
	}

	tagsJSON, _ := json.Marshal(k.Tags)

	var err error
	if k.ID != "" {
		query := `
		INSERT INTO virtual_keys (
			id, tenant_id, key_hash, key_prefix, previous_key_hash, previous_key_expires_at,
			name, team_id, created_by, created_at, expires_at, allowed_ips, max_rpm, max_tpm,
			max_concurrent_requests, monthly_budget_microcents, spent_microcents, allowed_models,
			allowed_routes, status, tags, owner_type, budget_period
		) VALUES (
			$1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23
		) RETURNING id::text`

		err = s.pool.QueryRow(ctx, query,
			k.ID, k.TenantID, k.KeyHash, k.KeyPrefix, k.PreviousKeyHash, k.PreviousKeyExpiresAt,
			k.Name, k.TeamID, k.CreatedBy, k.CreatedAt, k.ExpiresAt, k.AllowedIPs,
			k.MaxRPM, k.MaxTPM, k.MaxConcurrentRequests, k.MonthlyBudgetMicrocents, k.SpentMicrocents,
			k.AllowedModels, k.AllowedRoutes, k.Status, tagsJSON, k.OwnerType, k.BudgetPeriod,
		).Scan(&k.ID)
	} else {
		query := `
		INSERT INTO virtual_keys (
			tenant_id, key_hash, key_prefix, previous_key_hash, previous_key_expires_at,
			name, team_id, created_by, created_at, expires_at, allowed_ips, max_rpm, max_tpm,
			max_concurrent_requests, monthly_budget_microcents, spent_microcents, allowed_models,
			allowed_routes, status, tags, owner_type, budget_period
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
		) RETURNING id::text`

		err = s.pool.QueryRow(ctx, query,
			k.TenantID, k.KeyHash, k.KeyPrefix, k.PreviousKeyHash, k.PreviousKeyExpiresAt,
			k.Name, k.TeamID, k.CreatedBy, k.CreatedAt, k.ExpiresAt, k.AllowedIPs,
			k.MaxRPM, k.MaxTPM, k.MaxConcurrentRequests, k.MonthlyBudgetMicrocents, k.SpentMicrocents,
			k.AllowedModels, k.AllowedRoutes, k.Status, tagsJSON, k.OwnerType, k.BudgetPeriod,
		).Scan(&k.ID)
	}
	if err != nil {
		return err
	}

	_ = s.InsertAuditEvent(ctx, tenantID, &AuditEvent{
		TenantID:       tenantID,
		TableName:      "virtual_keys",
		Action:         "created",
		ChangedBy:      k.CreatedBy,
		ActorRole:      "admin",
		AffectedItemID: k.ID,
		UpdatedValue: map[string]interface{}{
			"id":                        k.ID,
			"name":                      k.Name,
			"key_prefix":                k.KeyPrefix,
			"team_id":                   k.TeamID,
			"owner_type":                k.OwnerType,
			"monthly_budget_microcents": k.MonthlyBudgetMicrocents,
			"status":                    k.Status,
			"allowed_models":            k.AllowedModels,
		},
		Outcome: "SUCCESS",
	})

	return nil
}

func (s *Store) ListVirtualKeys(ctx context.Context, tenantID string) ([]VirtualKey, error) {
	query := `SELECT ` + virtualKeySelectColumns + ` FROM virtual_keys
	WHERE tenant_id = $1 AND status != 'revoked'
	ORDER BY created_at DESC`

	rows, err := s.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list virtual keys: %w", err)
	}
	defer rows.Close()

	var keys []VirtualKey
	for rows.Next() {
		k, err := scanVirtualKey(rows)
		if err != nil {
			return nil, fmt.Errorf("scan virtual key: %w", err)
		}
		keys = append(keys, *k)
	}

	return keys, nil
}

func (s *Store) GetVirtualKeyByID(ctx context.Context, tenantID, id string) (*VirtualKey, error) {
	query := `SELECT ` + virtualKeySelectColumns + ` FROM virtual_keys
	WHERE tenant_id = $1 AND id = $2`

	k, err := scanVirtualKey(s.pool.QueryRow(ctx, query, tenantID, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrVirtualKeyNotFound
		}
		return nil, err
	}
	return k, nil
}

// GetVirtualKeyByHash resolves an active key or valid rotating previous key during grace periods.
func (s *Store) GetVirtualKeyByHash(ctx context.Context, keyHash string) (*VirtualKey, error) {
	// 1. Try active primary key_hash
	query := `SELECT ` + virtualKeySelectColumns + ` FROM virtual_keys
	WHERE key_hash = $1 AND status != 'revoked'`

	k, err := scanVirtualKey(s.pool.QueryRow(ctx, query, keyHash))
	if err == nil {
		return k, nil
	}

	// 2. Check previous_key_hash during active rotation grace period
	fallbackQuery := `SELECT ` + virtualKeySelectColumns + ` FROM virtual_keys
	WHERE previous_key_hash = $1 AND previous_key_expires_at > NOW() AND status != 'revoked'`

	k, err = scanVirtualKey(s.pool.QueryRow(ctx, fallbackQuery, keyHash))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrVirtualKeyNotFound
		}
		return nil, err
	}
	return k, nil
}

// RotateVirtualKey rotates a key with a grace period for the old key.
func (s *Store) RotateVirtualKey(ctx context.Context, tenantID, id string, newKeyHash, newKeyPrefix string, gracePeriod time.Duration) (*VirtualKey, error) {
	graceExpires := time.Now().UTC().Add(gracePeriod)
	query := `UPDATE virtual_keys
	SET previous_key_hash = key_hash,
	    previous_key_expires_at = $1,
	    key_hash = $2,
	    key_prefix = $3,
	    status = 'rotating'
	WHERE tenant_id = $4 AND id = $5
	RETURNING ` + virtualKeySelectColumns

	rotated, err := scanVirtualKey(s.pool.QueryRow(ctx, query, graceExpires, newKeyHash, newKeyPrefix, tenantID, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrVirtualKeyNotFound
		}
		return nil, err
	}

	_ = s.InsertAuditEvent(ctx, tenantID, &AuditEvent{
		TenantID:       tenantID,
		TableName:      "virtual_keys",
		Action:         "rotated",
		ChangedBy:      "admin",
		ActorRole:      "admin",
		AffectedItemID: id,
		UpdatedValue: map[string]interface{}{
			"id":                      rotated.ID,
			"name":                    rotated.Name,
			"key_prefix":              rotated.KeyPrefix,
			"status":                  rotated.Status,
			"previous_key_expires_at": rotated.PreviousKeyExpiresAt,
		},
		Outcome: "SUCCESS",
	})

	return rotated, nil
}

func (s *Store) DeleteVirtualKey(ctx context.Context, tenantID, id string) error {
	return s.DeleteVirtualKeyWithActor(ctx, tenantID, id, "system", "user_revoked")
}

// DeleteVirtualKeyWithActor marks a key as revoked and records tombstone metadata for audit & compliance.
func (s *Store) DeleteVirtualKeyWithActor(ctx context.Context, tenantID, id, actorSubject, reason string) error {
	if reason == "" {
		reason = "user_revoked"
	}
	query := `UPDATE virtual_keys
	SET status = 'revoked',
	    deleted_at = NOW(),
	    deleted_by = $3,
	    deleted_reason = $4
	WHERE tenant_id = $1 AND id = $2`
	tag, err := s.pool.Exec(ctx, query, tenantID, id, actorSubject, reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrVirtualKeyNotFound
	}

	_ = s.InsertAuditEvent(ctx, tenantID, &AuditEvent{
		TenantID:       tenantID,
		TableName:      "virtual_keys",
		Action:         "revoked",
		ChangedBy:      actorSubject,
		ActorRole:      "admin",
		AffectedItemID: id,
		UpdatedValue: map[string]interface{}{
			"id":             id,
			"status":         "revoked",
			"deleted_reason": reason,
			"deleted_by":     actorSubject,
		},
		Outcome: "SUCCESS",
	})

	return nil
}

// ListDeletedVirtualKeys returns tombstoned/revoked virtual keys for compliance auditing.
func (s *Store) ListDeletedVirtualKeys(ctx context.Context, tenantID string, limit, offset int) ([]VirtualKey, error) {
	if s == nil || s.pool == nil {
		return []VirtualKey{}, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	query := `SELECT ` + virtualKeySelectColumns + ` FROM virtual_keys
	WHERE tenant_id = $1 AND (status = 'revoked' OR deleted_at IS NOT NULL)
	ORDER BY COALESCE(deleted_at, created_at) DESC
	LIMIT $2 OFFSET $3`

	rows, err := s.pool.Query(ctx, query, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list deleted virtual keys: %w", err)
	}
	defer rows.Close()

	var keys []VirtualKey
	for rows.Next() {
		k, err := scanVirtualKey(rows)
		if err != nil {
			return nil, fmt.Errorf("scan deleted virtual key: %w", err)
		}
		keys = append(keys, *k)
	}

	return keys, nil
}


// IncrementVirtualKeySpend executes atomic Compare-And-Swap (CAS) preflight reservation check.
func (s *Store) IncrementVirtualKeySpend(ctx context.Context, tenantID, id string, deltaMicrocents int64) (int64, error) {
	query := `UPDATE virtual_keys
	SET spent_microcents = spent_microcents + $1
	WHERE tenant_id = $2
	  AND id = $3
	  AND status != 'revoked'
	  AND (monthly_budget_microcents = 0 OR (spent_microcents + $1) <= monthly_budget_microcents)
	RETURNING spent_microcents`

	var newSpent int64
	err := s.pool.QueryRow(ctx, query, deltaMicrocents, tenantID, id).Scan(&newSpent)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrVirtualKeyBudgetExceeded
		}
		return 0, err
	}
	return newSpent, nil
}

func (s *Store) ResetVirtualKeySpend(ctx context.Context, tenantID, id string) error {
	query := `UPDATE virtual_keys SET spent_microcents = 0 WHERE tenant_id = $1 AND id = $2`
	_, err := s.pool.Exec(ctx, query, tenantID, id)
	if err != nil {
		return err
	}

	_ = s.InsertAuditEvent(ctx, tenantID, &AuditEvent{
		TenantID:       tenantID,
		TableName:      "virtual_keys",
		Action:         "updated",
		ChangedBy:      "admin",
		ActorRole:      "admin",
		AffectedItemID: id,
		UpdatedValue: map[string]interface{}{
			"id":               id,
			"spent_microcents": 0,
			"action_type":      "reset_spend",
		},
		Outcome: "SUCCESS",
	})

	return nil
}
