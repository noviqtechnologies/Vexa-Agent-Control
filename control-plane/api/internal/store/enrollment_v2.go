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
	ErrTokenInvalidV2          = errors.New("enrollment token is invalid, expired, or consumed")
	ErrTokenConsumedV2         = errors.New("enrollment token has already been consumed")
	ErrTxExpiredV2             = errors.New("enrollment transaction has expired")
	ErrTxNotFoundV2            = errors.New("enrollment transaction not found")
	ErrChallengeNotFoundV2     = errors.New("enrollment challenge not found or does not belong to transaction")
	ErrChallengeExpiredV2      = errors.New("enrollment challenge has expired")
	ErrDeviceConflictV2        = errors.New("device creation conflict")
	ErrDeviceAlreadyEnrolledV2 = errors.New("device is already enrolled with this identity key")
)

type EnrollmentTxRecord struct {
	TransactionID        string
	ChallengeID          string
	OrganizationID       string
	TenantID             string // Alias
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

// EnsureEnrollmentV2Schema guarantees schema consistency for enrollment.
func (s *Store) EnsureEnrollmentV2Schema(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	q := `
		CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
		CREATE EXTENSION IF NOT EXISTS "pgcrypto";

		CREATE TABLE IF NOT EXISTS enrollment_tokens (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			team_id TEXT NOT NULL DEFAULT 'default' REFERENCES teams(id) ON DELETE CASCADE,
			token_hash BYTEA NOT NULL,
			token_hint TEXT NOT NULL,
			status token_status NOT NULL DEFAULT 'ACTIVE',
			max_uses INT NOT NULL DEFAULT 1,
			current_uses INT NOT NULL DEFAULT 0,
			expected_device_label TEXT,
			target_owner_subject TEXT,
			reason TEXT NOT NULL DEFAULT 'Device enrollment',
			created_by_subject TEXT NOT NULL DEFAULT 'admin',
			expires_at TIMESTAMPTZ NOT NULL,
			consumed_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);

		CREATE TABLE IF NOT EXISTS enrollment_transactions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			enrollment_token_id UUID REFERENCES enrollment_tokens(id) ON DELETE SET NULL,
			stable_device_id TEXT NOT NULL,
			display_name TEXT,
			owner_subject TEXT,
			enrollment_ed25519_public_key BYTEA,
			enrollment_key_fingerprint TEXT NOT NULL,
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
			CONSTRAINT uq_enrollment_tx UNIQUE (organization_id, stable_device_id, enrollment_key_fingerprint)
		);

		CREATE TABLE IF NOT EXISTS enrollment_challenges (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			transaction_id UUID NOT NULL REFERENCES enrollment_transactions(id) ON DELETE CASCADE,
			challenge_hash BYTEA NOT NULL,
			transcript_sha256 TEXT NOT NULL DEFAULT '',
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);

		CREATE TABLE IF NOT EXISTS device_certificates (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			ca_resource_name TEXT,
			serial_number TEXT NOT NULL UNIQUE,
			certificate_fingerprint TEXT,
			sha256_fingerprint TEXT,
			csr_sha256 TEXT,
			public_key_fingerprint TEXT,
			certificate_pem TEXT NOT NULL,
			status credential_status NOT NULL DEFAULT 'ACTIVE',
			not_before TIMESTAMPTZ NOT NULL,
			not_after TIMESTAMPTZ NOT NULL,
			renew_after TIMESTAMPTZ,
			issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			revoked_at TIMESTAMPTZ,
			revocation_reason TEXT
		);

		-- Idempotent schema migrations for existing tables
		ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS expected_device_label TEXT;
		ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS target_owner_subject TEXT;

		ALTER TABLE enrollment_transactions ADD COLUMN IF NOT EXISTS os_version_summary TEXT;
		ALTER TABLE enrollment_transactions ADD COLUMN IF NOT EXISTS display_name TEXT;
		ALTER TABLE enrollment_transactions ADD COLUMN IF NOT EXISTS owner_subject TEXT;
		ALTER TABLE enrollment_transactions ADD COLUMN IF NOT EXISTS enrollment_ed25519_public_key BYTEA;
		ALTER TABLE enrollment_transactions ADD COLUMN IF NOT EXISTS mtls_csr_sha256 TEXT;
		ALTER TABLE enrollment_transactions ADD COLUMN IF NOT EXISTS mtls_csr_pem TEXT;
		ALTER TABLE enrollment_transactions ADD COLUMN IF NOT EXISTS os_family TEXT;
		ALTER TABLE enrollment_transactions ADD COLUMN IF NOT EXISTS architecture TEXT;
		ALTER TABLE enrollment_transactions ADD COLUMN IF NOT EXISTS failure_code TEXT;

		ALTER TABLE device_certificates ADD COLUMN IF NOT EXISTS ca_resource_name TEXT;
		ALTER TABLE device_certificates ADD COLUMN IF NOT EXISTS certificate_fingerprint TEXT;
		ALTER TABLE device_certificates ADD COLUMN IF NOT EXISTS sha256_fingerprint TEXT;
		ALTER TABLE device_certificates ADD COLUMN IF NOT EXISTS csr_sha256 TEXT;
		ALTER TABLE device_certificates ADD COLUMN IF NOT EXISTS public_key_fingerprint TEXT;
		ALTER TABLE device_certificates ADD COLUMN IF NOT EXISTS renew_after TIMESTAMPTZ;
	`
	_, err := s.pool.Exec(ctx, q)
	return err
}

// CreateEnrollmentTokenV2 inserts a new OTET for an organization.
func (s *Store) CreateEnrollmentTokenV2(ctx context.Context, organizationID, rawToken, hint, deviceLabel, ownerSubject, reason, createdBy string, expiresInMinutes int) (*model.EnrollmentTokenRecord, error) {
	if organizationID == "" {
		organizationID = DefaultOrgID
	}

	tokSum := sha256.Sum256([]byte(rawToken))
	expiresAt := time.Now().UTC().Add(time.Duration(expiresInMinutes) * time.Minute)

	query := `
		INSERT INTO enrollment_tokens (
			organization_id, token_hash, token_hint, status, max_uses, current_uses,
			expected_device_label, target_owner_subject, reason, expires_at, created_by_subject
		) VALUES (
			$1, $2, $3, 'ACTIVE', 1, 0,
			NULLIF($4, ''), NULLIF($5, ''), $6, $7, $8
		)
		RETURNING id, organization_id, token_hint, status, max_uses, current_uses, expires_at, created_at;
	`

	var rec model.EnrollmentTokenRecord
	err := s.pool.QueryRow(ctx, query,
		organizationID, tokSum[:], hint, deviceLabel, ownerSubject, reason, expiresAt, createdBy,
	).Scan(
		&rec.ID, &rec.OrganizationID, &rec.TokenHint, &rec.Status, &rec.MaxUses, &rec.CurrentUses,
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
) (txID string, challengeID string, organizationID string, err error) {
	tokSum := sha256.Sum256([]byte(rawToken))
	hexStr := hex.EncodeToString(tokSum[:])

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", "", "", fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// 1. Lock and validate token row
	tokenQuery := `
		SELECT id, organization_id, status, current_uses, max_uses, expires_at
		FROM enrollment_tokens
		WHERE token_hash = $1 OR token_hash = $2
		FOR UPDATE;
	`
	var tID, orgID string
	var status model.TokenStatus
	var currentUses, maxUses int
	var tokenExpiresAt time.Time

	err = tx.QueryRow(ctx, tokenQuery, tokSum[:], []byte(hexStr)).Scan(
		&tID, &orgID, &status, &currentUses, &maxUses, &tokenExpiresAt,
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
			organization_id, enrollment_token_id, stable_device_id, display_name,
			owner_subject, enrollment_ed25519_public_key, enrollment_key_fingerprint,
			mtls_csr_sha256, mtls_csr_pem, os_family, os_version_summary, architecture,
			status, expires_at
		) VALUES (
			$1, $2, $3, NULLIF($4, ''),
			NULLIF($5, ''), $6, $7,
			$8, $9, $10, NULLIF($11, ''), $12,
			'CHALLENGE_ISSUED', $13
		)
		ON CONFLICT (organization_id, stable_device_id, enrollment_key_fingerprint) DO UPDATE SET
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
		orgID, tID, stableDeviceID, displayName,
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
			organization_id, transaction_id, challenge_hash, transcript_sha256, expires_at
		) VALUES ($1, $2, $3, '', $4)
		RETURNING id;
	`
	err = tx.QueryRow(ctx, insertChallengeQuery, orgID, txID, challengeHash, expiryTime).Scan(&challengeID)
	if err != nil {
		return "", "", "", fmt.Errorf("insert enrollment challenge: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", "", "", fmt.Errorf("commit enrollment start: %w", err)
	}

	return txID, challengeID, orgID, nil
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
			t.organization_id, t.stable_device_id, t.display_name, t.owner_subject,
			t.enrollment_ed25519_public_key, t.enrollment_key_fingerprint,
			t.mtls_csr_sha256, t.mtls_csr_pem, t.os_family, t.os_version_summary, t.architecture,
			t.status, t.expires_at
		FROM enrollment_transactions t
		WHERE t.id = $1;
	`
	err := s.pool.QueryRow(ctx, txQuery, txID).Scan(
		&rec.OrganizationID, &rec.StableDeviceID, &dispName, &ownerSub,
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
	rec.TenantID = rec.OrganizationID

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
		var devID string
		var certSerial, certPEM string
		_ = s.pool.QueryRow(ctx, `SELECT id FROM devices WHERE organization_id = $1 AND stable_device_id = $2;`, rec.OrganizationID, rec.StableDeviceID).Scan(&devID)
		_ = s.pool.QueryRow(ctx, `SELECT serial_number, certificate_pem FROM device_certificates WHERE organization_id = $1 AND device_id = $2 AND status = 'ACTIVE' ORDER BY issued_at DESC LIMIT 1;`, rec.OrganizationID, devID).Scan(&certSerial, &certPEM)
		rec.ExistingDeviceID = devID
		rec.ExistingCertSerial = certSerial
		rec.ExistingCertPEMChain = certPEM
		return &rec, nil
	}

	if time.Now().UTC().After(rec.ExpiresAt) {
		return nil, ErrTxExpiredV2
	}

	// Validate challenge belongs to transaction and is not expired
	var chalOrgID string
	var chalExpiresAt time.Time
	chalQuery := `
		SELECT organization_id, expires_at
		FROM enrollment_challenges
		WHERE id = $1 AND transaction_id = $2;
	`
	err = s.pool.QueryRow(ctx, chalQuery, challengeID, txID).Scan(&chalOrgID, &chalExpiresAt)
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
	var orgID, stableDevID, osFam, arch, ed25519FP, csrSHA256 string
	var dispName, ownerSub, osVer *string
	var edPubBytes []byte
	var txStatus string
	var txExpiresAt time.Time

	txQuery := `
		SELECT 
			organization_id, stable_device_id, display_name, owner_subject,
			enrollment_ed25519_public_key, enrollment_key_fingerprint,
			mtls_csr_sha256, os_family, os_version_summary, architecture,
			status, expires_at
		FROM enrollment_transactions
		WHERE id = $1
		FOR UPDATE;
	`
	err = tx.QueryRow(ctx, txQuery, txID).Scan(
		&orgID, &stableDevID, &dispName, &ownerSub,
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
		var devID, devState string
		err = tx.QueryRow(ctx, `SELECT id, state FROM devices WHERE organization_id = $1 AND stable_device_id = $2;`, orgID, stableDevID).Scan(&devID, &devState)
		if err == nil {
			return devID, devState, nil
		}
	}

	if time.Now().UTC().After(txExpiresAt) {
		return "", "", ErrTxExpiredV2
	}

	// Validate challenge
	var chalCount int
	err = tx.QueryRow(ctx, `SELECT count(*) FROM enrollment_challenges WHERE id = $1 AND transaction_id = $2 AND organization_id = $3 AND expires_at > now();`, challengeID, txID, orgID).Scan(&chalCount)
	if err != nil || chalCount == 0 {
		return "", "", ErrChallengeNotFoundV2
	}

	finalDispName := stableDevID
	if dispName != nil && *dispName != "" {
		finalDispName = *dispName
	}
	finalOSFam := "windows"
	if osFam != "" {
		finalOSFam = osFam
	}
	finalArch := "x86_64"
	if arch != "" {
		finalArch = arch
	}

	// Insert or update device record
	devQuery := `
		INSERT INTO devices (
			organization_id, stable_device_id, display_name, owner_subject,
			os_family, os_version_summary, architecture, state, state_changed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 'PENDING', now())
		ON CONFLICT (stable_device_id) DO UPDATE SET
			organization_id = EXCLUDED.organization_id,
			display_name = COALESCE(NULLIF(EXCLUDED.display_name, ''), devices.display_name),
			owner_subject = COALESCE(NULLIF(EXCLUDED.owner_subject, ''), devices.owner_subject),
			os_family = EXCLUDED.os_family,
			os_version_summary = EXCLUDED.os_version_summary,
			architecture = EXCLUDED.architecture,
			state = 'PENDING'::device_state,
			state_reason_code = 'REENROLLED_VIA_OTET',
			revoked_at = NULL,
			revocation_reason = NULL,
			state_changed_at = now(),
			updated_at = now()
		RETURNING id, state;
	`
	err = tx.QueryRow(ctx, devQuery,
		orgID, stableDevID, finalDispName, ownerSub,
		finalOSFam, osVer, finalArch,
	).Scan(&deviceID, &state)
	if err != nil {
		return "", "", fmt.Errorf("insert device: %w", err)
	}

	// Insert certificate record
	certHash := sha256.Sum256(certChainPEM)
	sha256FP := hex.EncodeToString(certHash[:])
	certFP := "sha256:" + sha256FP
	certQuery := `
		INSERT INTO device_certificates (
			organization_id, device_id, ca_resource_name, serial_number, certificate_fingerprint, sha256_fingerprint, certificate_pem,
			csr_sha256, public_key_fingerprint, status, issued_at, not_before, not_after, renew_after
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, 'ACTIVE', now(), $10, $11, $12
		)
		ON CONFLICT (serial_number) DO UPDATE SET
			status = 'ACTIVE', not_after = $11, renew_after = $12;
	`
	_, err = tx.Exec(ctx, certQuery,
		orgID, deviceID, caResource, serialNumber, certFP, sha256FP, string(certChainPEM),
		csrSHA256, ed25519FP, notBefore, notAfter, renewAfter,
	)
	if err != nil {
		return "", "", fmt.Errorf("insert cert: %w", err)
	}

	// Delete consumed challenge
	_, _ = tx.Exec(ctx, `DELETE FROM enrollment_challenges WHERE id = $1;`, challengeID)

	// Mark transaction completed
	updateTx := `UPDATE enrollment_transactions SET status = 'COMPLETED', completed_at = now() WHERE id = $1;`
	if _, err = tx.Exec(ctx, updateTx, txID); err != nil {
		return "", "", fmt.Errorf("update tx status: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", "", fmt.Errorf("commit complete tx: %w", err)
	}

	return deviceID, state, nil
}
