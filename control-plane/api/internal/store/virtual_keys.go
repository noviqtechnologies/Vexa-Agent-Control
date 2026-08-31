package store

import (
	"context"
	"database/sql/driver"
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

// StringSlice handles dual PostgreSQL (TEXT[]) and JSON serialization.
type StringSlice []string

func (s StringSlice) Value() (driver.Value, error) {
	if s == nil {
		return "[]", nil
	}
	b, err := json.Marshal(s)
	return string(b), err
}

func (s *StringSlice) Scan(value interface{}) error {
	if value == nil {
		*s = []string{}
		return nil
	}
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, s)
	case string:
		return json.Unmarshal([]byte(v), s)
	case []string:
		*s = v
		return nil
	case []interface{}:
		res := make([]string, len(v))
		for i, item := range v {
			res[i] = fmt.Sprintf("%v", item)
		}
		*s = res
		return nil
	default:
		return fmt.Errorf("cannot scan type %T into StringSlice", value)
	}
}

// StringMap handles dual PostgreSQL (JSONB) and JSON serialization.
type StringMap map[string]string

func (m StringMap) Value() (driver.Value, error) {
	if m == nil {
		return "{}", nil
	}
	b, err := json.Marshal(m)
	return string(b), err
}

func (m *StringMap) Scan(value interface{}) error {
	if value == nil {
		*m = make(map[string]string)
		return nil
	}
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, m)
	case string:
		return json.Unmarshal([]byte(v), m)
	default:
		return fmt.Errorf("cannot scan type %T into StringMap", value)
	}
}

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
	AllowedIPs              StringSlice       `json:"allowed_ips" db:"allowed_ips"`
	MaxRPM                  int               `json:"max_rpm" db:"max_rpm"`
	MaxTPM                  int               `json:"max_tpm" db:"max_tpm"`
	MaxConcurrentRequests   int               `json:"max_concurrent_requests" db:"max_concurrent_requests"`
	MonthlyBudgetMicrocents int64             `json:"monthly_budget_microcents" db:"monthly_budget_microcents"`
	SpentMicrocents         int64             `json:"spent_microcents" db:"spent_microcents"`
	AllowedModels           StringSlice       `json:"allowed_models" db:"allowed_models"`
	AllowedRoutes           StringSlice       `json:"allowed_routes" db:"allowed_routes"`
	Status                  string            `json:"status" db:"status"` // "active", "rotating", "revoked"
	Tags                    map[string]string `json:"tags,omitempty" db:"tags"`
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
		CONSTRAINT unique_key_hash_per_tenant UNIQUE(tenant_id, key_hash)
	);
	CREATE INDEX IF NOT EXISTS idx_virtual_keys_tenant ON virtual_keys(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_virtual_keys_hash ON virtual_keys(key_hash);
	CREATE INDEX IF NOT EXISTS idx_virtual_keys_prev_hash ON virtual_keys(previous_key_hash);
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
	)
	if err != nil {
		return nil, err
	}

	k.AllowedIPs = allowedIPs
	k.AllowedModels = allowedModels
	k.AllowedRoutes = allowedRoutes
	if len(tagsJSON) > 0 {
		_ = json.Unmarshal(tagsJSON, &k.Tags)
	}
	return &k, nil
}

const virtualKeySelectColumns = `id, tenant_id, key_hash, key_prefix, previous_key_hash, previous_key_expires_at,
	name, team_id, created_by, created_at, expires_at, allowed_ips, max_rpm, max_tpm,
	max_concurrent_requests, monthly_budget_microcents, spent_microcents, allowed_models,
	allowed_routes, status, tags`

func (s *Store) CreateVirtualKey(ctx context.Context, tenantID string, k *VirtualKey) error {
	if k.ID == "" {
		k.ID = fmt.Sprintf("vk-%d", time.Now().UnixNano())
	}
	k.TenantID = tenantID
	k.CreatedAt = time.Now().UTC()
	if k.Status == "" {
		k.Status = "active"
	}

	tagsJSON, _ := json.Marshal(k.Tags)

	query := `
	INSERT INTO virtual_keys (
		id, tenant_id, key_hash, key_prefix, previous_key_hash, previous_key_expires_at,
		name, team_id, created_by, created_at, expires_at, allowed_ips, max_rpm, max_tpm,
		max_concurrent_requests, monthly_budget_microcents, spent_microcents, allowed_models,
		allowed_routes, status, tags
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
	)`

	_, err := s.pool.Exec(ctx, query,
		k.ID, k.TenantID, k.KeyHash, k.KeyPrefix, k.PreviousKeyHash, k.PreviousKeyExpiresAt,
		k.Name, k.TeamID, k.CreatedBy, k.CreatedAt, k.ExpiresAt, k.AllowedIPs,
		k.MaxRPM, k.MaxTPM, k.MaxConcurrentRequests, k.MonthlyBudgetMicrocents, k.SpentMicrocents,
		k.AllowedModels, k.AllowedRoutes, k.Status, tagsJSON,
	)
	return err
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
		var k VirtualKey
		var allowedIPs, allowedModels, allowedRoutes []string
		var tagsJSON []byte

		err := rows.Scan(
			&k.ID, &k.TenantID, &k.KeyHash, &k.KeyPrefix, &k.PreviousKeyHash, &k.PreviousKeyExpiresAt,
			&k.Name, &k.TeamID, &k.CreatedBy, &k.CreatedAt, &k.ExpiresAt,
			&allowedIPs, &k.MaxRPM, &k.MaxTPM, &k.MaxConcurrentRequests,
			&k.MonthlyBudgetMicrocents, &k.SpentMicrocents,
			&allowedModels, &allowedRoutes, &k.Status, &tagsJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("scan virtual key: %w", err)
		}
		k.AllowedIPs = allowedIPs
		k.AllowedModels = allowedModels
		k.AllowedRoutes = allowedRoutes
		if len(tagsJSON) > 0 {
			_ = json.Unmarshal(tagsJSON, &k.Tags)
		}
		keys = append(keys, k)
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

	k, err := scanVirtualKey(s.pool.QueryRow(ctx, query, graceExpires, newKeyHash, newKeyPrefix, tenantID, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrVirtualKeyNotFound
		}
		return nil, err
	}
	return k, nil
}

func (s *Store) DeleteVirtualKey(ctx context.Context, tenantID, id string) error {
	query := `UPDATE virtual_keys SET status = 'revoked' WHERE tenant_id = $1 AND id = $2`
	tag, err := s.pool.Exec(ctx, query, tenantID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrVirtualKeyNotFound
	}
	return nil
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
	return err
}
