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
	ErrTokenInvalidV2        = errors.New("enrollment token is invalid, expired, or consumed")
	ErrTokenConsumedV2       = errors.New("enrollment token has already been consumed")
	ErrTxExpiredV2           = errors.New("enrollment transaction has expired")
	ErrTxNotFoundV2          = errors.New("enrollment transaction not found")
	ErrChallengeNotFoundV2   = errors.New("enrollment challenge not found or does not belong to transaction")
	ErrChallengeExpiredV2    = errors.New("enrollment challenge has expired")
	ErrDeviceConflictV2      = errors.New("device creation conflict")
	ErrDeviceAlreadyEnrolledV2 = errors.New("device is already enrolled with this identity key")
)

type EnrollmentTxRecord struct {
	TransactionID        string
	ChallengeID          string
	TenantID             string
	StableDeviceID       string
	DisplayName          string
	OwnerSubject         string
	Ed25519PublicKey     []byte
	Ed25519Fingerprint   string
	MTLSCSRSHA256        string
	MTLSCSRPEM           string
	OSFamily             string
	OSVersionSummary     string
	Architecture         string
	Status               string
	ExpiresAt            time.Time
	ChallengeExpiresAt   time.Time
	IsCompleted          bool
	ExistingDeviceID     string
	ExistingCertSerial   string
	ExistingCertPEMChain string
}

// EnsureEnrollmentV2Schema guarantees schema consistency for enrollment, device state, outbox, and audit tables.
func (s *Store) EnsureEnrollmentV2Schema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	q := `
		-- 0. Required extensions
		CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
		CREATE EXTENSION IF NOT EXISTS "pgcrypto";

		-- 0b. Required ENUM types
		DO $$ BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'device_state') THEN
				CREATE TYPE device_state AS ENUM ('PENDING', 'COMPLIANT', 'NON_COMPLIANT', 'REVOKED');
			ELSE
				BEGIN
					ALTER TYPE device_state ADD VALUE IF NOT EXISTS 'PENDING';
				EXCEPTION
					WHEN duplicate_object THEN NULL;
				END;
			END IF;
		END $$;

		DO $$ BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'credential_status') THEN
				CREATE TYPE credential_status AS ENUM ('ACTIVE', 'EXPIRED', 'REVOKED', 'SUSPENDED');
			END IF;
		END $$;

		DO $$ BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'actor_type') THEN
				CREATE TYPE actor_type AS ENUM ('USER', 'SYSTEM', 'DEVICE', 'INTEGRATION', 'POLICY');
			END IF;
		END $$;

		-- 0c. Tenants table
		CREATE TABLE IF NOT EXISTS tenants (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			slug TEXT UNIQUE NOT NULL,
			status TEXT NOT NULL DEFAULT 'ACTIVE',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);

		-- 0d. Devices table
		CREATE TABLE IF NOT EXISTS devices (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			stable_device_id TEXT NOT NULL DEFAULT '',
			display_name TEXT NOT NULL DEFAULT '',
			owner_subject TEXT,
			os_family TEXT NOT NULL DEFAULT 'linux',
			architecture TEXT NOT NULL DEFAULT 'x86_64',
			os_version_summary TEXT,
			daemon_version TEXT DEFAULT '2.1.0',
			public_key TEXT,
			state device_state NOT NULL DEFAULT 'PENDING',
			state_reason_code TEXT,
			state_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			first_enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			revoked_at TIMESTAMPTZ,
			revoked_by_subject TEXT,
			revocation_reason TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (tenant_id, stable_device_id)
		);
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS stable_device_id TEXT DEFAULT '';
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS display_name TEXT DEFAULT '';
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS owner_subject TEXT;
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_family TEXT DEFAULT 'linux';
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS architecture TEXT DEFAULT 'x86_64';
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_version_summary TEXT;
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS daemon_version TEXT DEFAULT '2.1.0';
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS public_key TEXT;
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS state device_state DEFAULT 'PENDING';
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS state_reason_code TEXT;
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS state_changed_at TIMESTAMPTZ DEFAULT now();
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS first_enrolled_at TIMESTAMPTZ DEFAULT now();
		ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_heartbeat_at TIMESTAMPTZ DEFAULT now();

		-- 1. Enrollment tokens extension columns
		CREATE TABLE IF NOT EXISTS enrollment_tokens (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			token_hash BYTEA NOT NULL,
			token_hint TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'ACTIVE',
			max_uses INT NOT NULL DEFAULT 1,
			current_uses INT NOT NULL DEFAULT 0,
			expected_device_label TEXT,
			target_owner_subject TEXT,
			reason TEXT,
			expires_at TIMESTAMPTZ NOT NULL,
			created_by_subject TEXT NOT NULL,
			consumed_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
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
			certificate_pem TEXT NOT NULL DEFAULT '',
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
		ALTER TABLE device_certificates ADD COLUMN IF NOT EXISTS certificate_pem TEXT DEFAULT '';
		ALTER TABLE device_certificates ADD COLUMN IF NOT EXISTS renew_after TIMESTAMPTZ;
		ALTER TABLE device_certificates ADD COLUMN IF NOT EXISTS revocation_reason TEXT;

		-- 5. Device enrollment keys (no inline UNIQUE — use named index only)
		CREATE TABLE IF NOT EXISTS device_enrollment_keys (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			public_key_pem TEXT NOT NULL DEFAULT '',
			public_key BYTEA,
			fingerprint TEXT NOT NULL DEFAULT '',
			algorithm TEXT NOT NULL DEFAULT 'ED25519',
			status TEXT NOT NULL DEFAULT 'ACTIVE',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		ALTER TABLE device_enrollment_keys ADD COLUMN IF NOT EXISTS public_key BYTEA;
		ALTER TABLE device_enrollment_keys ADD COLUMN IF NOT EXISTS public_key_pem TEXT DEFAULT '';
		ALTER TABLE device_enrollment_keys ADD COLUMN IF NOT EXISTS fingerprint TEXT DEFAULT '';
		ALTER TABLE device_enrollment_keys ADD COLUMN IF NOT EXISTS algorithm TEXT DEFAULT 'ED25519';
		-- Drop all legacy check and inline unique constraints before dedup
		ALTER TABLE device_enrollment_keys DROP CONSTRAINT IF EXISTS device_enrollment_keys_algorithm_check;
		ALTER TABLE device_enrollment_keys DROP CONSTRAINT IF EXISTS device_enrollment_keys_status_check;
		ALTER TABLE device_enrollment_keys DROP CONSTRAINT IF EXISTS device_enrollment_keys_tenant_id_fingerprint_key;
		-- Deduplicate rows before creating the named unique index
		DELETE FROM device_enrollment_keys a USING device_enrollment_keys b
		WHERE a.ctid < b.ctid AND a.tenant_id = b.tenant_id AND a.fingerprint = b.fingerprint;
		CREATE UNIQUE INDEX IF NOT EXISTS uq_device_enrollment_keys_tenant_fingerprint ON device_enrollment_keys (tenant_id, fingerprint);

		-- 6. Device provider capabilities (no inline UNIQUE — use named index only)
		CREATE TABLE IF NOT EXISTS device_provider_capabilities (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			provider TEXT NOT NULL,
			project_ref TEXT,
			model_family TEXT,
			action TEXT,
			status TEXT NOT NULL DEFAULT 'ACTIVE',
			enabled BOOLEAN NOT NULL DEFAULT true,
			rate_limit_rpm INT NOT NULL DEFAULT 60,
			issued_by_subject TEXT,
			expires_at TIMESTAMPTZ,
			reason TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		ALTER TABLE device_provider_capabilities ADD COLUMN IF NOT EXISTS project_ref TEXT;
		ALTER TABLE device_provider_capabilities ADD COLUMN IF NOT EXISTS model_family TEXT;
		ALTER TABLE device_provider_capabilities ADD COLUMN IF NOT EXISTS action TEXT;
		ALTER TABLE device_provider_capabilities ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'ACTIVE';
		ALTER TABLE device_provider_capabilities ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT true;
		ALTER TABLE device_provider_capabilities ADD COLUMN IF NOT EXISTS rate_limit_rpm INT DEFAULT 60;
		ALTER TABLE device_provider_capabilities ADD COLUMN IF NOT EXISTS issued_by_subject TEXT;
		ALTER TABLE device_provider_capabilities ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
		ALTER TABLE device_provider_capabilities ADD COLUMN IF NOT EXISTS reason TEXT;
		-- Drop inline unique constraint before dedup
		ALTER TABLE device_provider_capabilities DROP CONSTRAINT IF EXISTS device_provider_capabilities_tenant_id_device_id_provider_key;
		-- Deduplicate rows before creating the named unique index
		DELETE FROM device_provider_capabilities a USING device_provider_capabilities b
		WHERE a.ctid < b.ctid AND a.tenant_id = b.tenant_id AND a.device_id = b.device_id AND a.provider = b.provider;
		CREATE UNIQUE INDEX IF NOT EXISTS uq_device_provider_capabilities_tenant_device_provider ON device_provider_capabilities (tenant_id, device_id, provider);

		-- Drop inline unique constraints on device_certificates before dedup
		ALTER TABLE device_certificates DROP CONSTRAINT IF EXISTS device_certificates_serial_number_key;
		ALTER TABLE device_certificates DROP CONSTRAINT IF EXISTS device_certificates_tenant_id_serial_number_key;
		-- Deduplicate rows before creating the named unique index
		DELETE FROM device_certificates a USING device_certificates b
		WHERE a.ctid < b.ctid AND a.serial_number = b.serial_number;
		CREATE UNIQUE INDEX IF NOT EXISTS uq_device_certificates_serial_number ON device_certificates (serial_number);

		-- 7. Device state history
		CREATE TABLE IF NOT EXISTS device_state_history (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			prior_state device_state,
			from_state device_state,
			new_state device_state NOT NULL DEFAULT 'PENDING',
			to_state device_state,
			reason_code TEXT,
			correlation_id UUID,
			actor_type actor_type NOT NULL DEFAULT 'USER',
			actor_subject TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		ALTER TABLE device_state_history ADD COLUMN IF NOT EXISTS prior_state device_state;
		ALTER TABLE device_state_history ADD COLUMN IF NOT EXISTS from_state device_state;
		ALTER TABLE device_state_history ADD COLUMN IF NOT EXISTS new_state device_state;
		ALTER TABLE device_state_history ADD COLUMN IF NOT EXISTS to_state device_state;
		ALTER TABLE device_state_history ADD COLUMN IF NOT EXISTS correlation_id UUID;
		ALTER TABLE device_state_history ADD COLUMN IF NOT EXISTS actor_type actor_type NOT NULL DEFAULT 'USER';
		ALTER TABLE device_state_history ADD COLUMN IF NOT EXISTS actor_subject TEXT;

		-- 8. Audit events
		CREATE TABLE IF NOT EXISTS audit_events (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			correlation_id UUID,
			request_id UUID,
			actor_type TEXT,
			actor_ref TEXT,
			resource_type TEXT,
			resource_id TEXT,
			action TEXT,
			outcome TEXT,
			reason_code TEXT,
			metadata JSONB,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
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
			display_name = COALESCE(NULLIF(EXCLUDED.display_name, ''), enrollment_transactions.display_name),
			owner_subject = COALESCE(NULLIF(EXCLUDED.owner_subject, ''), enrollment_transactions.owner_subject),
			enrollment_ed25519_public_key = EXCLUDED.enrollment_ed25519_public_key,
			mtls_csr_sha256 = EXCLUDED.mtls_csr_sha256,
			mtls_csr_pem = EXCLUDED.mtls_csr_pem,
			os_family = EXCLUDED.os_family,
			os_version_summary = COALESCE(NULLIF(EXCLUDED.os_version_summary, ''), enrollment_transactions.os_version_summary),
			architecture = EXCLUDED.architecture,
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

// GetEnrollmentTransactionForValidation retrieves and locks the transaction and challenge for proof verification.
func (s *Store) GetEnrollmentTransactionForValidation(ctx context.Context, txID, challengeID string) (*EnrollmentTxRecord, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is not initialized")
	}

	var rec EnrollmentTxRecord
	rec.TransactionID = txID
	rec.ChallengeID = challengeID

	var dispName, ownerSub, osVer *string
	var edPubBytes []byte

	txQuery := `
		SELECT 
			t.tenant_id, t.stable_device_id, t.display_name, t.owner_subject,
			t.enrollment_ed25519_public_key, t.enrollment_key_fingerprint,
			t.mtls_csr_sha256, t.mtls_csr_pem, t.os_family, t.os_version_summary, t.architecture,
			t.status, t.expires_at
		FROM enrollment_transactions t
		WHERE t.id = $1;
	`
	err := s.pool.QueryRow(ctx, txQuery, txID).Scan(
		&rec.TenantID, &rec.StableDeviceID, &dispName, &ownerSub,
		&edPubBytes, &rec.Ed25519Fingerprint,
		&rec.MTLSCSRSHA256, &rec.MTLSCSRPEM, &rec.OSFamily, &osVer, &rec.Architecture,
		&rec.Status, &rec.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTxNotFoundV2
		}
		return nil, fmt.Errorf("query transaction: %w", err)
	}

	if dispName != nil {
		rec.DisplayName = *dispName
	}
	if ownerSub != nil {
		rec.OwnerSubject = *ownerSub
	}
	if osVer != nil {
		rec.OSVersionSummary = *osVer
	}
	rec.Ed25519PublicKey = edPubBytes

	// If transaction is already completed (idempotency check)
	if rec.Status == "COMPLETED" {
		rec.IsCompleted = true
		// Fetch existing device & active cert for idempotent response
		var devID string
		var certSerial, certPEM string
		_ = s.pool.QueryRow(ctx, `SELECT id FROM devices WHERE tenant_id = $1 AND stable_device_id = $2;`, rec.TenantID, rec.StableDeviceID).Scan(&devID)
		_ = s.pool.QueryRow(ctx, `SELECT serial_number, certificate_pem FROM device_certificates WHERE tenant_id = $1 AND device_id = $2 AND status = 'ACTIVE' ORDER BY issued_at DESC LIMIT 1;`, rec.TenantID, devID).Scan(&certSerial, &certPEM)
		rec.ExistingDeviceID = devID
		rec.ExistingCertSerial = certSerial
		rec.ExistingCertPEMChain = certPEM
		return &rec, nil
	}

	if time.Now().UTC().After(rec.ExpiresAt) {
		return nil, ErrTxExpiredV2
	}

	// Validate challenge belongs to transaction and is not expired
	var chalTenantID string
	var chalExpiresAt time.Time
	chalQuery := `
		SELECT tenant_id, expires_at
		FROM enrollment_challenges
		WHERE id = $1 AND transaction_id = $2;
	`
	err = s.pool.QueryRow(ctx, chalQuery, challengeID, txID).Scan(&chalTenantID, &chalExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrChallengeNotFoundV2
		}
		return nil, fmt.Errorf("query challenge: %w", err)
	}

	if time.Now().UTC().After(chalExpiresAt) {
		return nil, ErrChallengeExpiredV2
	}
	rec.ChallengeExpiresAt = chalExpiresAt

	return &rec, nil
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
	var txStatus string
	var txExpiresAt time.Time

	txQuery := `
		SELECT 
			tenant_id, stable_device_id, display_name, owner_subject,
			enrollment_ed25519_public_key, enrollment_key_fingerprint,
			mtls_csr_sha256, os_family, os_version_summary, architecture,
			status, expires_at
		FROM enrollment_transactions
		WHERE id = $1
		FOR UPDATE;
	`
	err = tx.QueryRow(ctx, txQuery, txID).Scan(
		&tenantID, &stableDevID, &dispName, &ownerSub,
		&edPubBytes, &ed25519FP,
		&csrSHA256, &osFam, &osVer, &arch,
		&txStatus, &txExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrTxNotFoundV2
		}
		return "", "", fmt.Errorf("query transaction: %w", err)
	}

	if txStatus == "COMPLETED" {
		// Already completed - return device ID
		var devID, devState string
		err = tx.QueryRow(ctx, `SELECT id, state FROM devices WHERE tenant_id = $1 AND stable_device_id = $2;`, tenantID, stableDevID).Scan(&devID, &devState)
		if err == nil {
			return devID, devState, nil
		}
	}

	if time.Now().UTC().After(txExpiresAt) {
		return "", "", ErrTxExpiredV2
	}

	// 1b. Validate challenge belongs to transaction and is not expired
	var chalCount int
	err = tx.QueryRow(ctx, `SELECT count(*) FROM enrollment_challenges WHERE id = $1 AND transaction_id = $2 AND tenant_id = $3 AND expires_at > now();`, challengeID, txID, tenantID).Scan(&chalCount)
	if err != nil || chalCount == 0 {
		return "", "", ErrChallengeNotFoundV2
	}

	// 2. Safe defaults for NOT NULL columns on devices table
	finalDispName := stableDevID
	if dispName != nil && *dispName != "" {
		finalDispName = *dispName
	}
	finalOSFam := "linux"
	if osFam != "" {
		finalOSFam = osFam
	}
	finalArch := "x86_64"
	if arch != "" {
		finalArch = arch
	}

	// 3. Insert or update device record
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
			state = 'PENDING'::device_state,
			state_reason_code = 'REENROLLED_VIA_OTET',
			revoked_at = NULL,
			revoked_by_subject = NULL,
			revocation_reason = NULL,
			state_changed_at = now(),
			updated_at = now()
		RETURNING id, state;
	`
	err = tx.QueryRow(ctx, devQuery,
		tenantID, stableDevID, finalDispName, ownerSub,
		finalOSFam, osVer, finalArch,
	).Scan(&deviceID, &state)
	if err != nil {
		return "", "", fmt.Errorf("insert device: %w", err)
	}

	// 4. Insert enrollment key record
	keyPem := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n", base64.StdEncoding.EncodeToString(edPubBytes))
	keyQuery := `
		INSERT INTO device_enrollment_keys (
			tenant_id, device_id, algorithm, public_key, public_key_pem, fingerprint, status
		) VALUES ($1, $2, 'ED25519', $3, $4, $5, 'ACTIVE')
		ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
			device_id = EXCLUDED.device_id,
			public_key = EXCLUDED.public_key,
			public_key_pem = EXCLUDED.public_key_pem,
			status = 'ACTIVE';
	`
	if _, err = tx.Exec(ctx, keyQuery, tenantID, deviceID, edPubBytes, keyPem, ed25519FP); err != nil {
		return "", "", fmt.Errorf("insert enrollment key: %w", err)
	}

	// 5. Insert certificate record
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

	// 6. Grant default provider capability
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

	// 7. Delete consumed challenge
	_, _ = tx.Exec(ctx, `DELETE FROM enrollment_challenges WHERE id = $1;`, challengeID)

	// 8. Mark transaction completed
	updateTx := `UPDATE enrollment_transactions SET status = 'COMPLETED', completed_at = now() WHERE id = $1;`
	if _, err = tx.Exec(ctx, updateTx, txID); err != nil {
		return "", "", fmt.Errorf("update tx status: %w", err)
	}

	// 9. Emit outbox event
	outboxQuery := `
		INSERT INTO outbox_events (
			tenant_id, aggregate_type, aggregate_id, event_type, payload_version, redacted_payload
		) VALUES ($1, 'enrollment_transaction', $2, 'enrollment.completed', '2.0', '{}'::jsonb);
	`
	_, _ = tx.Exec(ctx, outboxQuery, tenantID, txID)

	if err := tx.Commit(ctx); err != nil {
		return "", "", fmt.Errorf("commit complete tx: %w", err)
	}

	return deviceID, state, nil
}
