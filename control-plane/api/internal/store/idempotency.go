package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrIdempotencyConflict = errors.New("idempotency key already used with different request body")
)

type IdempotencyRecord struct {
	TenantID           string
	PrincipalRef       string
	Route              string
	IdempotencyKey     string
	CanonicalBodySHA   string
	ResponseStatus     int
	ResponseReference  string
	ExpiresAt          time.Time
}

// EnsureIdempotencySchema guarantees schema consistency for the idempotency_records table.
func (s *Store) EnsureIdempotencySchema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	q := `
		CREATE TABLE IF NOT EXISTS idempotency_records (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			principal_ref TEXT NOT NULL,
			route TEXT NOT NULL,
			idempotency_key TEXT NOT NULL,
			canonical_body_sha256 TEXT NOT NULL,
			response_status INT NOT NULL,
			response_reference TEXT,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (tenant_id, principal_ref, route, idempotency_key)
		);
		CREATE INDEX IF NOT EXISTS idx_idempotency_records_exp ON idempotency_records(expires_at);
	`
	_, err := s.pool.Exec(ctx, q)
	return err
}

// CheckOrSaveIdempotency checks if a mutation has already executed. If so, returns cached response.
func (s *Store) CheckOrSaveIdempotency(
	ctx context.Context,
	tenantID, principalRef, route, idempotencyKey string,
	rawBody []byte,
	ttl time.Duration,
) (*IdempotencyRecord, error) {
	bodySum := sha256.Sum256(rawBody)
	bodySHA := hex.EncodeToString(bodySum[:])

	query := `
		SELECT canonical_body_sha256, response_status, response_reference, expires_at
		FROM idempotency_records
		WHERE tenant_id = $1 AND principal_ref = $2 AND route = $3 AND idempotency_key = $4;
	`

	var existingSHA, respRef string
	var status int
	var expiresAt time.Time

	err := s.pool.QueryRow(ctx, query, tenantID, principalRef, route, idempotencyKey).Scan(
		&existingSHA, &status, &respRef, &expiresAt,
	)

	if err == nil {
		if existingSHA != bodySHA {
			return nil, ErrIdempotencyConflict
		}
		return &IdempotencyRecord{
			TenantID:          tenantID,
			PrincipalRef:      principalRef,
			Route:             route,
			IdempotencyKey:    idempotencyKey,
			CanonicalBodySHA:  existingSHA,
			ResponseStatus:    status,
			ResponseReference: respRef,
			ExpiresAt:         expiresAt,
		}, nil
	}

	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("check idempotency: %w", err)
	}

	return nil, nil // First time seeing this idempotency key
}

// RecordIdempotencyResult commits the successful mutation outcome to the idempotency table.
func (s *Store) RecordIdempotencyResult(
	ctx context.Context,
	tenantID, principalRef, route, idempotencyKey string,
	rawBody []byte,
	status int,
	respRef string,
	ttl time.Duration,
) error {
	bodySum := sha256.Sum256(rawBody)
	bodySHA := hex.EncodeToString(bodySum[:])
	expiresAt := time.Now().UTC().Add(ttl)

	insertQuery := `
		INSERT INTO idempotency_records (
			tenant_id, principal_ref, route, idempotency_key,
			canonical_body_sha256, response_status, response_reference, expires_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		)
		ON CONFLICT (tenant_id, principal_ref, route, idempotency_key) DO NOTHING;
	`

	_, err := s.pool.Exec(ctx, insertQuery,
		tenantID, principalRef, route, idempotencyKey,
		bodySHA, status, respRef, expiresAt,
	)
	return err
}
