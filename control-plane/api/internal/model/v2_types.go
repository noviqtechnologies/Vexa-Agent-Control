package model

import (
	"encoding/json"
	"time"
)

// DeviceState represents the authoritative compliance state of an enrolled endpoint.
type DeviceState string

const (
	DeviceStatePending       DeviceState = "PENDING"
	DeviceStateCompliant     DeviceState = "COMPLIANT"
	DeviceStateNonCompliant  DeviceState = "NON_COMPLIANT"
	DeviceStateUnreachable   DeviceState = "UNREACHABLE"
	DeviceStateRevoked       DeviceState = "REVOKED"
	DeviceStateLegacyAuth    DeviceState = "LEGACY_AUTH"
)

// CredentialStatus represents the status of an mTLS certificate or enrollment key.
type CredentialStatus string

const (
	CredentialStatusActive     CredentialStatus = "ACTIVE"
	CredentialStatusSuperseded CredentialStatus = "SUPERSEDED"
	CredentialStatusRevoked    CredentialStatus = "REVOKED"
	CredentialStatusExpired    CredentialStatus = "EXPIRED"
)

// TokenStatus represents the status of an OTET bootstrap token.
type TokenStatus string

const (
	TokenStatusActive   TokenStatus = "ACTIVE"
	TokenStatusConsumed TokenStatus = "CONSUMED"
	TokenStatusExpired  TokenStatus = "EXPIRED"
	TokenStatusRevoked  TokenStatus = "REVOKED"
)

// StandardErrorEnvelope matches RFC-7807 problem details
type StandardErrorEnvelope struct {
	Error struct {
		Code            string `json:"code"`
		Message         string `json:"message"`
		RequestID       string `json:"request_id,omitempty"`
		Retryable       bool   `json:"retryable,omitempty"`
		RemediationCode string `json:"remediation_code,omitempty"`
	} `json:"error"`
}

// DevicePrincipal is the authenticated identity resolved by edge mTLS + PostgreSQL.
type DevicePrincipal struct {
	OrganizationID         string           `json:"organization_id"`
	DeviceID               string           `json:"device_id"`
	CertificateID          string           `json:"certificate_id"`
	CertificateSerial      string           `json:"certificate_serial"`
	CertificateFingerprint string           `json:"certificate_fingerprint"`
	CredentialStatus       CredentialStatus `json:"credential_status"`
	DeviceState            DeviceState      `json:"device_state"`
	Capabilities           []string         `json:"capabilities"`
	RequestID              string           `json:"request_id"`
}

// EnrollmentTokenRecord represents persisted OTET metadata.
type EnrollmentTokenRecord struct {
	ID                  string      `json:"id"`
	OrganizationID      string      `json:"organization_id"`
	TeamID              string      `json:"team_id"`
	TokenHash           []byte      `json:"-"`
	TokenHint           string      `json:"token_hint"`
	HashAlgorithm       string      `json:"hash_algorithm"`
	Status              TokenStatus `json:"status"`
	MaxUses             int         `json:"max_uses"`
	CurrentUses         int         `json:"current_uses"`
	ExpectedDeviceLabel string      `json:"expected_device_label,omitempty"`
	TargetOwnerSubject  string      `json:"target_owner_subject,omitempty"`
	Reason              string      `json:"reason"`
	ExpiresAt           time.Time   `json:"expires_at"`
	ConsumedAt          *time.Time  `json:"consumed_at,omitempty"`
	ConsumedDeviceID    *string     `json:"consumed_device_id,omitempty"`
	RevokedAt           *time.Time  `json:"revoked_at,omitempty"`
	CreatedBySubject    string      `json:"created_by_subject"`
	CreatedAt           time.Time   `json:"created_at"`
}

// EnrollmentTransactionRecord represents a 2-key enrollment handshake transaction.
type EnrollmentTransactionRecord struct {
	ID                        string     `json:"id"`
	OrganizationID            string     `json:"organization_id"`
	EnrollmentTokenID         string     `json:"enrollment_token_id"`
	StableDeviceID            string     `json:"stable_device_id"`
	DisplayName               string     `json:"display_name,omitempty"`
	OwnerSubject              string     `json:"owner_subject,omitempty"`
	EnrollmentEd25519PubKey   []byte     `json:"-"`
	EnrollmentKeyFingerprint  string     `json:"enrollment_key_fingerprint"`
	MTLSCSRSHA256             string     `json:"mtls_csr_sha256"`
	MTLSCSRPEM                string     `json:"mtls_csr_pem"`
	OSFamily                  string     `json:"os_family"`
	OSVersionSummary          string     `json:"os_version_summary,omitempty"`
	Architecture              string     `json:"architecture"`
	Status                    string     `json:"status"`
	FailureCode               string     `json:"failure_code,omitempty"`
	ExpiresAt                 time.Time  `json:"expires_at"`
	CompletedAt               *time.Time `json:"completed_at,omitempty"`
	CreatedAt                 time.Time  `json:"created_at"`
}

// DeviceRecord represents the operational projection of an enrolled device.
type DeviceRecord struct {
	ID                string      `json:"id"`
	OrganizationID    string      `json:"organization_id"`
	TeamID            string      `json:"team_id"`
	StableDeviceID    string      `json:"stable_device_id"`
	DisplayName       string      `json:"display_name,omitempty"`
	OwnerSubject      string      `json:"owner_subject,omitempty"`
	OSFamily          string      `json:"os_family"`
	OSVersionSummary  string      `json:"os_version_summary,omitempty"`
	Architecture      string      `json:"architecture"`
	State             DeviceState `json:"state"`
	StateReasonCode   string      `json:"state_reason_code,omitempty"`
	StateChangedAt    time.Time   `json:"state_changed_at"`
	FirstEnrolledAt   time.Time   `json:"first_enrolled_at"`
	LastAuthAt        *time.Time  `json:"last_authenticated_at,omitempty"`
	LastHeartbeatAt   *time.Time  `json:"last_heartbeat_at,omitempty"`
	RevokedAt         *time.Time  `json:"revoked_at,omitempty"`
	RevocationReason  string      `json:"revocation_reason,omitempty"`
	CreatedAt         time.Time   `json:"created_at"`
	UpdatedAt         time.Time   `json:"updated_at"`
}

// PolicyEnvelope represents an immutable signed Team policy payload.
type PolicyEnvelope struct {
	ID        string          `json:"id"`
	Version   int             `json:"version"`
	Mode      string          `json:"mode"`
	Content   string          `json:"content"`
	SHA256    string          `json:"sha256"`
	Signature PolicySignature `json:"signature"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
}

type PolicySignature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"` // base64url encoded
}

// HeartbeatPayload represents self-reported Sentry operational telemetry.
type HeartbeatPayload struct {
	SchemaVersion string `json:"schema_version"`
	Sequence      int64  `json:"sequence"`
	ObservedAt    string `json:"observed_at"`
	Service       struct {
		Version       string `json:"version"`
		State         string `json:"state"`
		ListenerScope string `json:"listener_scope"`
	} `json:"service"`
	Credential struct {
		Serial    string `json:"serial"`
		ExpiresAt string `json:"expires_at"`
	} `json:"credential"`
	Policy struct {
		CurrentVersion int    `json:"current_version"`
		CurrentSHA256  string `json:"current_sha256"`
		Mode           string `json:"mode"`
	} `json:"policy"`
	Fleet struct {
		TargetsTotal      int `json:"targets_total"`
		TargetsSecured    int `json:"targets_secured"`
		TargetsTampered   int `json:"targets_tampered"`
		TamperEventsTotal int `json:"tamper_events_total"`
	} `json:"fleet"`
	Environment struct {
		OSFamily         string `json:"os_family"`
		OSVersionSummary string `json:"os_version_summary"`
		Architecture     string `json:"architecture"`
	} `json:"environment"`
	Metrics struct {
		UptimeSeconds   int64 `json:"uptime_seconds"`
		ResidentMemoryB int64 `json:"resident_memory_bytes"`
		Goroutines      int   `json:"goroutines"`
	} `json:"metrics"`
}

// AuditEventRecord represents structured compliance audit trails.
type AuditEventRecord struct {
	ID             string          `json:"id"`
	OrganizationID string          `json:"organization_id"`
	CorrelationID  *string         `json:"correlation_id,omitempty"`
	RequestID      *string         `json:"request_id,omitempty"`
	Action         string          `json:"action"`
	ActorType      string          `json:"actor_type"`
	ActorRef       string          `json:"actor_ref"`
	ActorSubject   string          `json:"actor_subject"`
	ActorRole      string          `json:"actor_role"`
	ResourceType   string          `json:"resource_type"`
	ResourceID     string          `json:"resource_id"`
	Outcome        string          `json:"outcome"`
	ReasonCode     string          `json:"reason_code"`
	TargetType     string          `json:"target_type"`
	TargetID       string          `json:"target_id"`
	DiffJSON       json.RawMessage `json:"diff_json"`
	IPAddress      string          `json:"ip_address,omitempty"`
	OccurredAt     time.Time       `json:"occurred_at"`
}
