package middleware

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

const (
	DevicePrincipalKey contextKey = "device_principal"
	RequestIDKey       contextKey = "request_id"
)

func writeJSONError(w http.ResponseWriter, status int, code, msg, reqID string, retryable bool, remediation string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	var env model.StandardErrorEnvelope
	env.Error.Code = code
	env.Error.Message = msg
	env.Error.RequestID = reqID
	env.Error.Retryable = retryable
	env.Error.RemediationCode = remediation
	_ = json.NewEncoder(w).Encode(env)
}

// StrictDeviceMTLS resolves the device principal from GCP ALB mTLS headers and enforces state gates.
func StrictDeviceMTLS(st *store.Store, trustedVPCHeaderSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID := r.Header.Get("X-Request-ID")
			if reqID == "" {
				reqID = "req_" + strings.ReplaceAll(strings.ToLower(r.RemoteAddr), ":", "_")
			}
			w.Header().Set("X-Request-ID", reqID)
			ctx := context.WithValue(r.Context(), RequestIDKey, reqID)

			// 1. Ingress spoofing verification
			if r.TLS == nil && os.Getenv("DIRECT_TLS_ENABLED") != "true" && !strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
				if trustedVPCHeaderSecret == "" {
					writeJSONError(w, http.StatusUnauthorized, "invalid_ingress_boundary", "Ingress authentication secret not configured on HTTP boundary", reqID, false, "CONFIGURE_INGRESS_SECRET")
					return
				}
				vpcToken := r.Header.Get("X-VPC-Ingress-Auth")
				if subtle.ConstantTimeCompare([]byte(vpcToken), []byte(trustedVPCHeaderSecret)) != 1 {
					writeJSONError(w, http.StatusUnauthorized, "invalid_ingress_boundary", "Direct or untrusted ingress rejected", reqID, false, "USE_TRUSTED_LB")
					return
				}
			}

			// Reject client-supplied identity overrides
			if r.Header.Get("X-Device-ID") != "" || r.Header.Get("X-Internal-Principal") != "" {
				writeJSONError(w, http.StatusBadRequest, "invalid_identity_headers", "Client-supplied identity headers prohibited", reqID, false, "STRIP_CUSTOM_HEADERS")
				return
			}

			var certSerial, certFingerprint string

			// Direct TLS client certificate extraction
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				peerCert := r.TLS.PeerCertificates[0]
				certSerial = peerCert.SerialNumber.String()
				h := sha256.Sum256(peerCert.Raw)
				certFingerprint = "sha256:" + hex.EncodeToString(h[:])
			} else {
				certPresent := strings.TrimSpace(r.Header.Get("X-Client-Cert-Present"))
				certSerial = strings.TrimSpace(r.Header.Get("X-Client-Cert-Serial"))
				certFingerprint = strings.TrimSpace(r.Header.Get("X-Client-Cert-SHA256"))

				// Validate certificate presence from headers
				if (certSerial == "" || certFingerprint == "") && (certPresent == "" || certPresent == "false" || certPresent == "0") {
					writeJSONError(w, http.StatusUnauthorized, "device_auth_required", "Mutual TLS client certificate missing or invalid", reqID, false, "PROVISION_MTLS_CERT")
					return
				}

				if certSerial == "" || certFingerprint == "" {
					writeJSONError(w, http.StatusUnauthorized, "invalid_device_credential", "Client certificate metadata incomplete", reqID, false, "RENEGOTIATE_MTLS")
					return
				}

				if !strings.HasPrefix(certFingerprint, "sha256:") {
					certFingerprint = "sha256:" + certFingerprint
				}
			}

			// 3. Database lookup for device principal & state
			principal, err := st.ResolvePrincipalFromCert(ctx, certSerial, certFingerprint)
			if err != nil {
				if errors.Is(err, store.ErrDeviceNotFoundV2) {
					writeJSONError(w, http.StatusUnauthorized, "invalid_device_credential", "Device certificate not recognized or tenant mismatch", reqID, false, "RE_ENROLL_DEVICE")
					return
				}
				writeJSONError(w, http.StatusInternalServerError, "internal_error", "Database authorization error", reqID, true, "")
				return
			}

			// Check credential validity
			if principal.CredentialStatus == model.CredentialStatusExpired {
				writeJSONError(w, http.StatusForbidden, "credential_expired", "Device certificate has expired", reqID, false, "DEVICE_RECOVERY_REQUIRED")
				return
			}
			if principal.CredentialStatus != model.CredentialStatusActive {
				writeJSONError(w, http.StatusForbidden, "invalid_device_credential", "Device credential is "+string(principal.CredentialStatus), reqID, false, "DEVICE_RECOVERY_REQUIRED")
				return
			}

			reqPrincipal := &RequestPrincipal{
				TenantID:     principal.TenantID,
				DeviceID:     principal.DeviceID,
				AuthnType:    AuthnTypeMTLS,
				Capabilities: principal.Capabilities,
			}

			// 4. Authoritative State Gates
			// Gate 1: REVOKED devices denied everywhere except status endpoint
			if principal.DeviceState == model.DeviceStateRevoked {
				if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/api/v2/device/status") {
					principal.Capabilities = []string{"device.status.read"}
					principal.RequestID = reqID
					reqPrincipal.Capabilities = principal.Capabilities
					ctx = context.WithValue(ctx, DevicePrincipalKey, principal)
					ctx = context.WithValue(ctx, RequestPrincipalKey, reqPrincipal)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				writeJSONError(w, http.StatusForbidden, "device_revoked", "Device is revoked and unauthorized for operations", reqID, false, "DEVICE_RECOVERY_REQUIRED")
				return
			}

			// Gate 2: PENDING & NON_COMPLIANT devices restricted from Provider Broker
			isBrokerPath := strings.HasPrefix(r.URL.Path, "/api/v2/broker")
			if (principal.DeviceState == model.DeviceStatePending || principal.DeviceState == model.DeviceStateNonCompliant) && isBrokerPath {
				writeJSONError(w, http.StatusForbidden, "device_state_denied", "Device compliance state ("+string(principal.DeviceState)+") prohibits LLM broker execution", reqID, false, "RUN_STATUS_REMEDIATION")
				return
			}

			principal.RequestID = reqID
			ctx = context.WithValue(ctx, DevicePrincipalKey, principal)
			ctx = context.WithValue(ctx, RequestPrincipalKey, reqPrincipal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetDevicePrincipal retrieves the principal from the context.
func GetDevicePrincipal(ctx context.Context) (*model.DevicePrincipal, bool) {
	p, ok := ctx.Value(DevicePrincipalKey).(*model.DevicePrincipal)
	return p, ok
}
