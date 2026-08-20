package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

var (
	ErrTokenInvalidV2  = errors.New("enrollment token is invalid, expired, or consumed")
	ErrTokenConsumedV2 = errors.New("enrollment token has already been consumed")
	ErrTxExpiredV2     = errors.New("enrollment transaction has expired")
	ErrTxNotFoundV2    = errors.New("enrollment transaction not found")
	ErrDeviceConflictV2= errors.New("device creation conflict")
)

// CreateEnrollmentTokenV2 inserts a new OTET for a tenant.
func (s *Store) CreateEnrollmentTokenV2(ctx context.Context, tenantID, rawToken, hint, deviceLabel, ownerSubject, reason, createdBy string, expiresInMinutes int) (*model.EnrollmentTokenRecord, error) {
	// Auto-seed default tenant for testing/local development if not present
	_, _ = s.pool.Exec(ctx, `
		INSERT INTO tenants (id, slug, status)
		VALUES ($1, 'default-smb-tenant', 'ACTIVE')
		ON CONFLICT (id) DO NOTHING;
	`, tenantID)

	tokSum := sha256.Sum256([]byte(rawToken))
	expiresAt := time.Now().UTC().Add(time.Duration(expiresInMinutes) * time.Minute)

	query := `
		INSERT INTO enrollment_tokens (
			tenant_id, token_hash, token_hint, status, max_uses, current_uses,
			expected_device_label, target_owner_subject, reason, expires_at, created_by_subject
		) VALUES (
			$1, $2, $3, 'ACTIVE', 1, 0,
			NULLIF($4, ''), NULLIF($5, ''), $6, $7, $8
		)
		RETURNING id, tenant_id, token_hint, status, max_uses, current_uses, expires_at, created_at;
	`

	var rec model.EnrollmentTokenRecord
	err := s.pool.QueryRow(ctx, query,
		tenantID, tokSum[:], hint, deviceLabel, ownerSubject, reason, expiresAt, createdBy,
	).Scan(
		&rec.ID, &rec.TenantID, &rec.TokenHint, &rec.Status, &rec.MaxUses, &rec.CurrentUses,
		&rec.ExpiresAt, &rec.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert enrollment token: %w", err)
	}

	return &rec, nil
}

// AtomicallyConsumeOTET consumes the OTET within an atomic transaction with row locking.
func (s *Store) AtomicallyConsumeOTET(
	ctx context.Context,
	rawToken string,
	stableDeviceID, displayName, ownerSubject string,
	ed25519PubKey []byte,
	ed25519FP, csrSHA256, csrPEM, osFamily, osVer, arch string,
	challengeHash []byte,
	txExpiry time.Duration,
) (txID string, challengeID string, tenantID string, err error) {
	tokSum := sha256.Sum256([]byte(rawToken))
	hexStr := hex.EncodeToString(tokSum[:])

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", "", "", fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// 1. Lock and validate token row (matching both raw 32-byte and 64-byte hex string encodings)
	tokenQuery := `
		SELECT id, tenant_id, status, current_uses, max_uses, expires_at
		FROM enrollment_tokens
		WHERE token_hash = $1 OR token_hash = $2
		FOR UPDATE;
	`
	var tID, tenID string
	var status model.TokenStatus
	var currentUses, maxUses int
	var tokenExpiresAt time.Time

	err = tx.QueryRow(ctx, tokenQuery, tokSum[:], []byte(hexStr)).Scan(
		&tID, &tenID, &status, &currentUses, &maxUses, &tokenExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", "", ErrTokenInvalidV2
		}
		return "", "", "", fmt.Errorf("select token for update: %w", err)
	}

	if status != model.TokenStatusActive || currentUses >= maxUses || time.Now().UTC().After(tokenExpiresAt) {
		return "", "", "", ErrTokenInvalidV2
	}

	// 2. Mark token consumed
	updateTokQuery := `
		UPDATE enrollment_tokens
		SET status = 'CONSUMED', current_uses = 1, consumed_at = now()
		WHERE id = $1 AND status = 'ACTIVE' AND current_uses = 0;
	`
	tag, err := tx.Exec(ctx, updateTokQuery, tID)
	if err != nil || tag.RowsAffected() == 0 {
		return "", "", "", ErrTokenConsumedV2
	}

	// 3. Create Enrollment Transaction
	expiryTime := time.Now().UTC().Add(txExpiry)
	insertTxQuery := `
		INSERT INTO enrollment_transactions (
			tenant_id, enrollment_token_id, stable_device_id, display_name,
			owner_subject, enrollment_ed25519_public_key, enrollment_key_fingerprint,
			mtls_csr_sha256, mtls_csr_pem, os_family, os_version_summary, architecture,
			status, expires_at
		) VALUES (
			$1, $2, $3, NULLIF($4, ''),
			NULLIF($5, ''), $6, $7,
			$8, $9, $10, NULLIF($11, ''), $12,
			'CHALLENGE_ISSUED', $13
		)
		ON CONFLICT (tenant_id, stable_device_id, enrollment_key_fingerprint) DO UPDATE SET
			enrollment_token_id = EXCLUDED.enrollment_token_id,
			status = 'CHALLENGE_ISSUED',
			expires_at = EXCLUDED.expires_at,
			completed_at = NULL,
			failure_code = NULL
		RETURNING id;
	`
	err = tx.QueryRow(ctx, insertTxQuery,
		tenID, tID, stableDeviceID, displayName,
		ownerSubject, ed25519PubKey, ed25519FP,
		csrSHA256, csrPEM, osFamily, osVer, arch,
		expiryTime,
	).Scan(&txID)
	if err != nil {
		return "", "", "", fmt.Errorf("insert enrollment transaction: %w", err)
	}

	// 4. Delete any stale challenge for this transaction and insert fresh challenge
	_, _ = tx.Exec(ctx, `DELETE FROM enrollment_challenges WHERE transaction_id = $1`, txID)
	insertChallengeQuery := `
		INSERT INTO enrollment_challenges (
			tenant_id, transaction_id, challenge_hash, transcript_sha256, expires_at
		) VALUES ($1, $2, $3, '', $4)
		RETURNING id;
	`
	err = tx.QueryRow(ctx, insertChallengeQuery, tenID, txID, challengeHash, expiryTime).Scan(&challengeID)
	if err != nil {
		return "", "", "", fmt.Errorf("insert enrollment challenge: %w", err)
	}

	// 5. Emit Outbox & Audit Events
	outboxQuery := `
		INSERT INTO outbox_events (
			tenant_id, aggregate_type, aggregate_id, event_type, payload_version, redacted_payload
		) VALUES ($1, 'enrollment_transaction', $2, 'enrollment.started', '2.0', '{}'::jsonb);
	`
	_, _ = tx.Exec(ctx, outboxQuery, tenID, txID)

	if err := tx.Commit(ctx); err != nil {
		return "", "", "", fmt.Errorf("commit enrollment start: %w", err)
	}

	return txID, challengeID, tenID, nil
}

// CompleteEnrollmentTransaction finalizes enrollment by persisting the device, public key, and issued certificate.
func (s *Store) CompleteEnrollmentTransaction(
	ctx context.Context,
	txID, challengeID string,
	caResource, serialNumber string,
	certChainPEM []byte,
	notBefore, notAfter, renewAfter time.Time,
) (deviceID string, state string, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", "", fmt.Errorf("begin complete tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// 1. Fetch transaction record
	var tenantID, stableDevID, osFam, arch, ed25519FP, csrSHA256 string
	var dispName, ownerSub, osVer *string
	var edPubBytes []byte

	txQuery := `
		SELECT 
			tenant_id, stable_device_id, display_name, owner_subject,
			enrollment_ed25519_public_key, enrollment_key_fingerprint,
			mtls_csr_sha256, os_family, os_version_summary, architecture
		FROM enrollment_transactions
		WHERE id = $1 AND status = 'CHALLENGE_ISSUED'
		FOR UPDATE;
	`
	err = tx.QueryRow(ctx, txQuery, txID).Scan(
		&tenantID, &stableDevID, &dispName, &ownerSub,
		&edPubBytes, &ed25519FP,
		&csrSHA256, &osFam, &osVer, &arch,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrTxNotFoundV2
		}
		return "", "", fmt.Errorf("query transaction: %w", err)
	}

	// 2. Insert or update device record
	devQuery := `
		INSERT INTO devices (
			tenant_id, stable_device_id, display_name, owner_subject,
			os_family, os_version_summary, architecture, state, state_changed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 'PENDING', now())
		ON CONFLICT (tenant_id, stable_device_id) DO UPDATE SET
			state = 'PENDING', updated_at = now()
		RETURNING id, state;
	`
	err = tx.QueryRow(ctx, devQuery,
		tenantID, stableDevID, dispName, ownerSub,
		osFam, osVer, arch,
	).Scan(&deviceID, &state)
	if err != nil {
		return "", "", fmt.Errorf("insert device: %w", err)
	}

	// 3. Insert enrollment key record
	keyQuery := `
		INSERT INTO device_enrollment_keys (
			tenant_id, device_id, algorithm, public_key, fingerprint, status
		) VALUES ($1, $2, 'Ed25519', $3, $4, 'ACTIVE')
		ON CONFLICT (tenant_id, fingerprint) DO NOTHING;
	`
	_, _ = tx.Exec(ctx, keyQuery, tenantID, deviceID, edPubBytes, ed25519FP)

	// 4. Insert certificate record
	certFP := "sha256:" + hex.EncodeToString(sha256.New().Sum(certChainPEM))
	certQuery := `
		INSERT INTO device_certificates (
			tenant_id, device_id, ca_resource_name, serial_number, certificate_fingerprint,
			csr_sha256, public_key_fingerprint, status, issued_at, not_before, not_after, renew_after
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, 'ACTIVE', now(), $8, $9, $10
		)
		ON CONFLICT (tenant_id, serial_number) DO UPDATE SET
			status = 'ACTIVE', not_after = $9, renew_after = $10;
	`
	_, err = tx.Exec(ctx, certQuery,
		tenantID, deviceID, caResource, serialNumber, certFP,
		csrSHA256, ed25519FP, notBefore, notAfter, renewAfter,
	)
	if err != nil {
		return "", "", fmt.Errorf("insert cert: %w", err)
	}

	// 5. Grant default provider capability
	capQuery := `
		INSERT INTO device_provider_capabilities (
			tenant_id, device_id, provider, project_ref, model_family, action, status, issued_by_subject, expires_at, reason
		) VALUES (
			$1, $2, 'openai', 'proj_alpha', 'gpt-4.1-mini', 'INVOKE', 'ACTIVE', 'system', now() + interval '90 days', 'Initial capability'
		);
	`
	_, _ = tx.Exec(ctx, capQuery, tenantID, deviceID)

	// 6. Mark transaction completed
	updateTx := `UPDATE enrollment_transactions SET status = 'COMPLETED', completed_at = now() WHERE id = $1;`
	_, _ = tx.Exec(ctx, updateTx, txID)

	if err := tx.Commit(ctx); err != nil {
		return "", "", fmt.Errorf("commit complete tx: %w", err)
	}

	return deviceID, state, nil
}
