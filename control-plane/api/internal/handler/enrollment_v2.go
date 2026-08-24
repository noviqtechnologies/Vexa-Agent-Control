package handler

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/crypto"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type EnrollmentV2Handler struct {
	Store     *store.Store
	CASClient crypto.CASIssuer
}

func NewEnrollmentV2Handler(st *store.Store, cas crypto.CASIssuer) *EnrollmentV2Handler {
	return &EnrollmentV2Handler{
		Store:     st,
		CASClient: cas,
	}
}

type StartEnrollmentRequest struct {
	SchemaVersion   string `json:"schema_version"`
	EnrollmentToken string `json:"enrollment_token"`
	StableDeviceID  string `json:"stable_device_id"`
	DisplayName     string `json:"display_name"`
	OwnerSubject    string `json:"owner_subject"`
	IdentityPublicKey struct {
		Algorithm string `json:"algorithm"`
		Value     string `json:"value"` // base64url 32-byte Ed25519 public key
	} `json:"identity_public_key"`
	MTLSCSR struct {
		Algorithm string `json:"algorithm"`
		PEM       string `json:"pem"`
	} `json:"mtls_csr"`
	Platform struct {
		OSFamily          string `json:"os_family"`
		OSVersionSummary string `json:"os_version_summary"`
		Architecture      string `json:"architecture"`
	} `json:"platform"`
	Release struct {
		Version    string `json:"version"`
		ManifestID string `json:"manifest_id"`
	} `json:"release"`
}

type StartEnrollmentResponse struct {
	TransactionID string `json:"transaction_id"`
	TenantID      string `json:"tenant_id"`
	Challenge     struct {
		ID        string    `json:"id"`
		Nonce     string    `json:"nonce"`
		ExpiresAt time.Time `json:"expires_at"`
		Context   string    `json:"context"`
	} `json:"challenge"`
	Next string `json:"next"`
}

// StartEnrollment handles POST /api/v2/enrollment/start
func (h *EnrollmentV2Handler) StartEnrollment(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	if reqID == "" {
		reqID = "req_enroll_start"
	}
	w.Header().Set("X-Request-ID", reqID)

	if r.ContentLength > 65536 {
		http.Error(w, `{"error":{"code":"payload_too_large"}}`, http.StatusRequestEntityTooLarge)
		return
	}

	var req StartEnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":{"code":"invalid_schema"}}`, http.StatusBadRequest)
		return
	}

	if req.SchemaVersion != "2.0" || req.EnrollmentToken == "" || req.StableDeviceID == "" {
		http.Error(w, `{"error":{"code":"invalid_schema"}}`, http.StatusBadRequest)
		return
	}

	// 1. Validate Ed25519 Public Key
	rawEdPub, err := base64.RawURLEncoding.DecodeString(req.IdentityPublicKey.Value)
	if err != nil {
		rawEdPub, err = base64.StdEncoding.DecodeString(req.IdentityPublicKey.Value)
	}
	if err != nil {
		rawEdPub, err = hex.DecodeString(req.IdentityPublicKey.Value)
	}
	if err != nil || len(rawEdPub) != 32 || req.IdentityPublicKey.Algorithm != "Ed25519" {
		http.Error(w, `{"error":{"code":"invalid_identity_public_key"}}`, http.StatusBadRequest)
		return
	}
	edSum := sha256.Sum256(rawEdPub)
	ed25519FP := hex.EncodeToString(edSum[:])

	// 2. Compute CSR SHA256
	csrSum := sha256.Sum256([]byte(req.MTLSCSR.PEM))
	csrSHA256Hex := hex.EncodeToString(csrSum[:])

	// 3. Generate Nonce
	rawNonce := make([]byte, 32)
	if _, err := rand.Read(rawNonce); err != nil {
		http.Error(w, `{"error":{"code":"internal_error"}}`, http.StatusInternalServerError)
		return
	}
	nonceBase64URL := base64.RawURLEncoding.EncodeToString(rawNonce)
	nonceHash := sha256.Sum256(rawNonce)

	// 4. Atomically Consume Token in DB
	txID, challengeID, tenantID, err := h.Store.AtomicallyConsumeOTET(
		r.Context(),
		req.EnrollmentToken,
		req.StableDeviceID,
		req.DisplayName,
		req.OwnerSubject,
		rawEdPub,
		ed25519FP,
		csrSHA256Hex,
		req.MTLSCSR.PEM,
		req.Platform.OSFamily,
		req.Platform.OSVersionSummary,
		req.Platform.Architecture,
		nonceHash[:],
		10*time.Minute,
	)

	if err != nil {
		log.Printf("StartEnrollment consume error: %v", err)
		if errors.Is(err, store.ErrDeviceAlreadyEnrolledV2) {
			http.Error(w, `{"error":{"code":"device_already_enrolled","message":"Device is already enrolled with this identity key"}}`, http.StatusConflict)
			return
		}
		http.Error(w, `{"error":{"code":"enrollment_token_invalid","message":"Token invalid or expired"}}`, http.StatusUnauthorized)
		return
	}

	var resp StartEnrollmentResponse
	resp.TransactionID = txID
	resp.TenantID = tenantID
	resp.Challenge.ID = challengeID
	resp.Challenge.Nonce = nonceBase64URL
	resp.Challenge.ExpiresAt = time.Now().UTC().Add(10 * time.Minute)
	resp.Challenge.Context = "vexa-agentwall-enrollment-v2"
	resp.Next = "POST /api/v2/enrollment/complete"

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

type CompleteEnrollmentRequest struct {
	SchemaVersion        string `json:"schema_version"`
	TransactionID        string `json:"transaction_id"`
	ChallengeID          string `json:"challenge_id"`
	EnrollmentSignature struct {
		Algorithm string `json:"algorithm"`
		Value     string `json:"value"` // base64url 64-byte Ed25519 signature
	} `json:"enrollment_signature"`
	SignedPayloadSHA256 string `json:"signed_payload_sha256"`
}

type CompleteEnrollmentResponse struct {
	Device struct {
		ID    string `json:"id"`
		State string `json:"state"`
	} `json:"device"`
	MTLSCertificate struct {
		Serial     string    `json:"serial"`
		PEMChain   string    `json:"pem_chain"`
		NotAfter   time.Time `json:"not_after"`
		RenewAfter time.Time `json:"renew_after"`
	} `json:"mtls_certificate"`
	Trust struct {
		BundleID  string `json:"bundle_id"`
		BundleURL string `json:"bundle_url"`
	} `json:"trust"`
	DeviceAPIBase string `json:"device_api_base"`
}

// CompleteEnrollment handles POST /api/v2/enrollment/complete
func (h *EnrollmentV2Handler) CompleteEnrollment(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	if reqID == "" {
		reqID = "req_enroll_complete"
	}
	w.Header().Set("X-Request-ID", reqID)

	var req CompleteEnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":{"code":"invalid_schema","message":"Invalid JSON payload"}}`, http.StatusBadRequest)
		return
	}

	if req.TransactionID == "" || req.ChallengeID == "" {
		http.Error(w, `{"error":{"code":"invalid_schema","message":"transaction_id and challenge_id are required"}}`, http.StatusBadRequest)
		return
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(req.EnrollmentSignature.Value)
	if err != nil {
		sigBytes, err = base64.StdEncoding.DecodeString(req.EnrollmentSignature.Value)
	}
	if err != nil {
		sigBytes, err = hex.DecodeString(req.EnrollmentSignature.Value)
	}
	if err != nil || len(sigBytes) != 64 || req.EnrollmentSignature.Algorithm != "Ed25519" {
		http.Error(w, `{"error":{"code":"invalid_signature","message":"Signature must be 64-byte Ed25519"}}`, http.StatusBadRequest)
		return
	}

	// 1. Fetch transaction record and challenge for verification
	rec, err := h.Store.GetEnrollmentTransactionForValidation(r.Context(), req.TransactionID, req.ChallengeID)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrTxNotFoundV2):
			http.Error(w, `{"error":{"code":"transaction_not_found","message":"Enrollment transaction does not exist"}}`, http.StatusNotFound)
		case errors.Is(err, store.ErrTxExpiredV2):
			http.Error(w, `{"error":{"code":"transaction_expired","message":"Enrollment transaction has expired"}}`, http.StatusGone)
		case errors.Is(err, store.ErrChallengeNotFoundV2):
			http.Error(w, `{"error":{"code":"challenge_not_found","message":"Enrollment challenge not found or mismatched"}}`, http.StatusBadRequest)
		case errors.Is(err, store.ErrChallengeExpiredV2):
			http.Error(w, `{"error":{"code":"challenge_expired","message":"Enrollment challenge has expired"}}`, http.StatusGone)
		default:
			log.Printf("CompleteEnrollment lookup error: %v", err)
			http.Error(w, `{"error":{"code":"internal_error","message":"Failed to validate enrollment record"}}`, http.StatusInternalServerError)
		}
		return
	}

	// Idempotent return if already completed
	now := time.Now().UTC()
	notAfter := now.Add(90 * 24 * time.Hour)
	renewAfter := now.Add(60 * 24 * time.Hour)

	if rec.IsCompleted {
		var resp CompleteEnrollmentResponse
		resp.Device.ID = rec.ExistingDeviceID
		resp.Device.State = "PENDING"
		resp.MTLSCertificate.Serial = rec.ExistingCertSerial
		resp.MTLSCertificate.PEMChain = rec.ExistingCertPEMChain
		resp.MTLSCertificate.NotAfter = notAfter
		resp.MTLSCertificate.RenewAfter = renewAfter
		resp.Trust.BundleID = "vexa-device-ca-2026-01"
		resp.Trust.BundleURL = "https://device.vexasec.io/v1/trust-bundles/vexa-device-ca-2026-01"
		resp.DeviceAPIBase = "https://device.vexasec.io/api/v2/device"

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	// 2. Reconstruct Canonical Transcript Server-side
	tenantID := rec.TenantID
	if tenantID == "" {
		tenantID = "default-tenant"
	}
	canonical := FormatCanonicalTranscript(
		rec.TransactionID,
		req.ChallengeID,
		"enroll.vexasec.io",
		tenantID,
		rec.Ed25519Fingerprint,
		rec.MTLSCSRSHA256,
		"2.0",
	)

	// 3. Verify Transcript Hash
	sum := sha256.Sum256([]byte(canonical))
	expectedHashHex := hex.EncodeToString(sum[:])
	if req.SignedPayloadSHA256 == "" || req.SignedPayloadSHA256 != expectedHashHex {
		http.Error(w, `{"error":{"code":"transcript_hash_mismatch","message":"Signed payload hash does not match canonical transcript"}}`, http.StatusBadRequest)
		return
	}

	// 4. Verify Cryptographic Proof-of-Possession Signature
	if !VerifySignatureHelper(rec.Ed25519PublicKey, canonical, sigBytes) {
		http.Error(w, `{"error":{"code":"invalid_signature","message":"Ed25519 cryptographic signature verification failed"}}`, http.StatusUnauthorized)
		return
	}

	// 5. Sign the actual device CSR via CAS Issuer
	csrBytes := []byte(rec.MTLSCSRPEM)
	if len(csrBytes) == 0 {
		http.Error(w, `{"error":{"code":"invalid_csr","message":"No valid CSR recorded for transaction"}}`, http.StatusBadRequest)
		return
	}
	certChainPEM, serialNumber, caResource, err := h.CASClient.SignCertificateRequest(r.Context(), csrBytes, 90*24*time.Hour)
	if err != nil {
		log.Printf("CompleteEnrollment CA signing error: %v", err)
		if errors.Is(err, crypto.ErrEmptyCSR) ||
			errors.Is(err, crypto.ErrInvalidPEMBlock) ||
			errors.Is(err, crypto.ErrParseCSR) ||
			errors.Is(err, crypto.ErrCSRSignature) ||
			errors.Is(err, crypto.ErrInvalidKeyAlg) ||
			errors.Is(err, crypto.ErrInvalidCurve) {
			http.Error(w, fmt.Sprintf(`{"error":{"code":"invalid_csr","message":"Invalid client certificate signing request: %s"}}`, err.Error()), http.StatusBadRequest)
			return
		}
		http.Error(w, fmt.Sprintf(`{"error":{"code":"ca_unavailable","message":"Certificate authority failed to sign device CSR: %s"}}`, err.Error()), http.StatusServiceUnavailable)
		return
	}

	// 6. Complete Enrollment Transaction in Store
	deviceID, devState, err := h.Store.CompleteEnrollmentTransaction(
		r.Context(),
		req.TransactionID,
		req.ChallengeID,
		caResource,
		serialNumber,
		certChainPEM,
		now,
		notAfter,
		renewAfter,
	)
	if err != nil {
		log.Printf("CompleteEnrollment store transaction error [req_id=%s]: %v", reqID, err)
		switch {
		case errors.Is(err, store.ErrTxNotFoundV2):
			http.Error(w, fmt.Sprintf(`{"error":{"code":"transaction_not_found","message":"Enrollment transaction does not exist","request_id":%q}}`, reqID), http.StatusNotFound)
		case errors.Is(err, store.ErrTxExpiredV2):
			http.Error(w, fmt.Sprintf(`{"error":{"code":"transaction_expired","message":"Enrollment transaction has expired","request_id":%q}}`, reqID), http.StatusGone)
		case errors.Is(err, store.ErrChallengeNotFoundV2), errors.Is(err, store.ErrChallengeExpiredV2):
			http.Error(w, fmt.Sprintf(`{"error":{"code":"challenge_invalid","message":"Enrollment challenge is invalid or expired","request_id":%q}}`, reqID), http.StatusBadRequest)
		default:
			http.Error(w, fmt.Sprintf(`{"error":{"code":"internal_error","message":"Failed to finalize device enrollment in database","request_id":%q}}`, reqID), http.StatusInternalServerError)
		}
		return
	}

	var resp CompleteEnrollmentResponse
	resp.Device.ID = deviceID
	resp.Device.State = devState
	resp.MTLSCertificate.Serial = serialNumber
	resp.MTLSCertificate.PEMChain = string(certChainPEM)
	resp.MTLSCertificate.NotAfter = notAfter
	resp.MTLSCertificate.RenewAfter = renewAfter
	resp.Trust.BundleID = "vexa-device-ca-2026-01"
	resp.Trust.BundleURL = "https://device.vexasec.io/v1/trust-bundles/vexa-device-ca-2026-01"
	resp.DeviceAPIBase = "https://device.vexasec.io/api/v2/device"

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// VerifySignatureHelper provides pure crypto verification for unit tests and complete flow.
func VerifySignatureHelper(pubKey []byte, transcript string, signature []byte) bool {
	if len(pubKey) != 32 || len(signature) != 64 {
		return false
	}
	return ed25519.Verify(pubKey, []byte(transcript), signature)
}

// FormatCanonicalTranscript formats the deterministic pipe-delimited transcript.
func FormatCanonicalTranscript(txID, chID, audience, tenantID, ed25519FP, csrSHA256, schemaVer string) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", txID, chID, audience, tenantID, ed25519FP, csrSHA256, schemaVer)
}
