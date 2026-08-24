package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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

// EnsureEnrollmentV2Schema guarantees schema consistency for enrollment, device state, outbox, and audit tables.
func (s *Store) EnsureEnrollmentV2Schema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	q := `
		-- 1. Enrollment tokens extension columns
		ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS expected_device_label TEXT;
		ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS target_owner_subject TEXT;
		ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ;

		-- 2. Enrollment transactions
		CREATE TABLE IF NOT EXISTS enrollment_transactions (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			enrollment_token_id UUID REFERENCES enrollment_tokens(id) ON DELETE SET NULL,
			stable_device_id TEXT NOT NULL,
			display_name TEXT,
			owner_subject TEXT,
			enrollment_ed25519_public_key BYTEA,
			enrollment_key_fingerprint TEXT,
			mtls_csr_sha256 TEXT,
			mtls_csr_pem TEXT,
			os_family TEXT,
			os_version_summary TEXT,
			architecture TEXT,
			status TEXT NOT NULL DEFAULT 'CHALLENGE_ISSUED',
			expires_at TIMESTAMPTZ NOT NULL,
			completed_at TIMESTAMPTZ,
			failure_code TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (tenant_id, stable_device_id, enrollment_key_fingerprint)
		);

		-- 3. Enrollment challenges
		CREATE TABLE IF NOT EXISTS enrollment_challenges (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			transaction_id UUID NOT NULL REFERENCES enrollment_transactions(id) ON DELETE CASCADE,
			challenge_hash BYTEA NOT NULL,
			transcript_sha256 TEXT NOT NULL DEFAULT '',
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);

		-- 4. Device certificates
		CREATE TABLE IF NOT EXISTS device_certificates (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			ca_resource_name TEXT,
			serial_number TEXT NOT NULL,
			certificate_fingerprint TEXT,
			sha256_fingerprint TEXT,
			csr_sha256 TEXT,
			public_key_fingerprint TEXT,
			certificate_pem TEXT,
			status credential_status NOT NULL DEFAULT 'ACTIVE',
			not_before TIMESTAMPTZ NOT NULL,
			not_after TIMESTAMPTZ NOT NULL,
			renew_after TIMESTAMPTZ,
			revoked_at TIMESTAMPTZ,
			revocation_reason TEXT,
			issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (serial_number)
		);
		ALTER TABLE device_certificates ADD COLUMN IF NOT EXISTS ca_resource_name TEXT;
		ALTER TABLE device_certificates ADD COLUMN IF NOT EXISTS certificate_fingerprint TEXT;
		ALTER TABLE device_certificates ADD COLUMN IF NOT EXISTS sha256_fingerprint TEXT;
		ALTER TABLE device_certificates ADD COLUMN IF NOT EXISTS csr_sha256 TEXT;
		ALTER TABLE device_certificates ADD COLUMN IF NOT EXISTS public_key_fingerprint TEXT;
		ALTER TABLE device_certificates ADD COLUMN IF NOT EXISTS certificate_pem TEXT;
		ALTER TABLE device_certificates ADD COLUMN IF NOT EXISTS renew_after TIMESTAMPTZ;
		ALTER TABLE device_certificates ADD COLUMN IF NOT EXISTS revocation_reason TEXT;

		-- 5. Device enrollment keys
		ALTER TABLE device_enrollment_keys ADD COLUMN IF NOT EXISTS public_key BYTEA;

		-- 6. Device provider capabilities
		ALTER TABLE device_provider_capabilities ADD COLUMN IF NOT EXISTS project_ref TEXT;
		ALTER TABLE device_provider_capabilities ADD COLUMN IF NOT EXISTS model_family TEXT;
		ALTER TABLE device_provider_capabilities ADD COLUMN IF NOT EXISTS action TEXT;
		ALTER TABLE device_provider_capabilities ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'ACTIVE';
		ALTER TABLE device_provider_capabilities ADD COLUMN IF NOT EXISTS issued_by_subject TEXT;
		ALTER TABLE device_provider_capabilities ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
		ALTER TABLE device_provider_capabilities ADD COLUMN IF NOT EXISTS reason TEXT;

		-- 7. Device state history
		ALTER TABLE device_state_history ADD COLUMN IF NOT EXISTS prior_state device_state;
		ALTER TABLE device_state_history ADD COLUMN IF NOT EXISTS from_state device_state;
		ALTER TABLE device_state_history ADD COLUMN IF NOT EXISTS new_state device_state;
		ALTER TABLE device_state_history ADD COLUMN IF NOT EXISTS to_state device_state;
		ALTER TABLE device_state_history ADD COLUMN IF NOT EXISTS correlation_id UUID;
		ALTER TABLE device_state_history ADD COLUMN IF NOT EXISTS actor_type actor_type NOT NULL DEFAULT 'USER';
		ALTER TABLE device_state_history ADD COLUMN IF NOT EXISTS actor_subject TEXT;

		-- 8. Audit events
		ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS correlation_id UUID;
		ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS request_id UUID;
		ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS actor_type TEXT;
		ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS actor_ref TEXT;
		ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS resource_type TEXT;
		ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS resource_id TEXT;
		ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS outcome TEXT;
		ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS reason_code TEXT;

		-- 9. Outbox events
		CREATE TABLE IF NOT EXISTS outbox_events (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			aggregate_type TEXT NOT NULL,
			aggregate_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			payload_version TEXT NOT NULL DEFAULT '2.0',
			redacted_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
	`
	_, err := s.pool.Exec(ctx, q)
	return err
}

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
			display_name = COALESCE(NULLIF(EXCLUDED.display_name, ''), devices.display_name),
			owner_subject = COALESCE(NULLIF(EXCLUDED.owner_subject, ''), devices.owner_subject),
			os_family = EXCLUDED.os_family,
			os_version_summary = EXCLUDED.os_version_summary,
			architecture = EXCLUDED.architecture,
			state = CASE WHEN devices.state = 'REVOKED' THEN 'REVOKED'::device_state ELSE 'PENDING'::device_state END,
			updated_at = now()
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
	keyPem := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n", base64.StdEncoding.EncodeToString(edPubBytes))
	keyQuery := `
		INSERT INTO device_enrollment_keys (
			tenant_id, device_id, algorithm, public_key, public_key_pem, fingerprint, status
		) VALUES ($1, $2, 'Ed25519', $3, $4, $5, 'ACTIVE')
		ON CONFLICT (tenant_id, fingerprint) DO NOTHING;
	`
	if _, err = tx.Exec(ctx, keyQuery, tenantID, deviceID, edPubBytes, keyPem, ed25519FP); err != nil {
		return "", "", fmt.Errorf("insert enrollment key: %w", err)
	}

	// 4. Insert certificate record
	certHash := sha256.Sum256(certChainPEM)
	sha256FP := hex.EncodeToString(certHash[:])
	certFP := "sha256:" + sha256FP
	certQuery := `
		INSERT INTO device_certificates (
			tenant_id, device_id, ca_resource_name, serial_number, certificate_fingerprint, sha256_fingerprint, certificate_pem,
			csr_sha256, public_key_fingerprint, status, issued_at, not_before, not_after, renew_after
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, 'ACTIVE', now(), $10, $11, $12
		)
		ON CONFLICT (serial_number) DO UPDATE SET
			status = 'ACTIVE', not_after = $11, renew_after = $12;
	`
	_, err = tx.Exec(ctx, certQuery,
		tenantID, deviceID, caResource, serialNumber, certFP, sha256FP, string(certChainPEM),
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
		)
		ON CONFLICT (tenant_id, device_id, provider) DO NOTHING;
	`
	if _, err = tx.Exec(ctx, capQuery, tenantID, deviceID); err != nil {
		return "", "", fmt.Errorf("insert capability: %w", err)
	}

	// 6. Mark transaction completed
	updateTx := `UPDATE enrollment_transactions SET status = 'COMPLETED', completed_at = now() WHERE id = $1;`
	if _, err = tx.Exec(ctx, updateTx, txID); err != nil {
		return "", "", fmt.Errorf("update tx status: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", "", fmt.Errorf("commit complete tx: %w", err)
	}

	return deviceID, state, nil
}
