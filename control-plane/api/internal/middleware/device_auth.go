package middleware

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

// DeviceAssertionClaims defines the expected claims in a workstation device assertion JWT.
type DeviceAssertionClaims struct {
	TenantID     string `json:"tenant_id"`
	WorkspaceID  string `json:"workspace_id"`
	UserID       string `json:"user_id"`
	AgentVersion string `json:"agent_version,omitempty"`
	jwt.RegisteredClaims
}

// NonceReplayCache tracks recently observed jti values to prevent token replay attacks (5m TTL).
type NonceReplayCache struct {
	mu     sync.Mutex
	nonces map[string]time.Time
}

var globalNonceCache = &NonceReplayCache{
	nonces: make(map[string]time.Time),
}

func (c *NonceReplayCache) CheckAndRecord(jti string, ttl time.Duration) bool {
	if jti == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	// Prune expired nonces
	for k, exp := range c.nonces {
		if now.After(exp) {
			delete(c.nonces, k)
		}
	}

	if _, exists := c.nonces[jti]; exists {
		return false // Replay detected
	}
	c.nonces[jti] = now.Add(ttl)
	return true
}

// DeviceAssertionAuth validates Ed25519-signed device assertion JWTs on gateway/broker routes.
func DeviceAssertionAuth(db *store.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract assertion token from X-Device-Authorization or Authorization header
			authHeader := r.Header.Get("X-Device-Authorization")
			if authHeader == "" {
				authHeader = r.Header.Get("Authorization")
			}

			if authHeader == "" {
				http.Error(w, `{"error":{"code":"device_auth_required","message":"X-Device-Authorization bearer token required"}}`, http.StatusUnauthorized)
				return
			}

			rawToken := strings.TrimPrefix(authHeader, "Bearer ")
			rawToken = strings.TrimSpace(rawToken)

			// Parse token unverified first to extract sub (deviceID)
			parser := jwt.NewParser(jwt.WithoutClaimsValidation())
			var unverifiedClaims DeviceAssertionClaims
			_, _, err := parser.ParseUnverified(rawToken, &unverifiedClaims)
			if err != nil {
				// Fallback: allow direct device token / ID authentication for enrolled devices
				if principal, ok := db.ResolveDevicePrincipal(r.Context(), rawToken); ok && principal != nil {
					ctx := context.WithValue(r.Context(), DevicePrincipalKey, principal)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				http.Error(w, `{"error":{"code":"invalid_assertion_token","message":"Malformed assertion JWT payload"}}`, http.StatusUnauthorized)
				return
			}

			// Clean subject string: may be "urn:vexa:device:<id>" or just "<id>"
			deviceID := unverifiedClaims.Subject
			if strings.HasPrefix(deviceID, "urn:vexa:device:") {
				deviceID = strings.TrimPrefix(deviceID, "urn:vexa:device:")
			}
			if deviceID == "" {
				http.Error(w, `{"error":{"code":"invalid_assertion_token","message":"Subject (device_id) missing from assertion"}}`, http.StatusUnauthorized)
				return
			}

			// Fetch registered active public key for device
			devKey, err := db.GetActiveDeviceKey(r.Context(), deviceID)
			if err != nil || devKey == nil || devKey.PublicKeyBytes == "" {
				http.Error(w, `{"error":{"code":"device_unregistered","message":"Device is not enrolled or public key is missing"}}`, http.StatusUnauthorized)
				return
			}

			// Decode Ed25519 public key bytes
			var pubKeyBytes []byte
			pubKeyBytes, err = base64.StdEncoding.DecodeString(devKey.PublicKeyBytes)
			if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
				pubKeyBytes, err = base64.RawURLEncoding.DecodeString(devKey.PublicKeyBytes)
			}
			if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
				if len(devKey.PublicKeyBytes) == ed25519.PublicKeySize {
					pubKeyBytes = []byte(devKey.PublicKeyBytes)
				} else {
					http.Error(w, `{"error":{"code":"invalid_public_key","message":"Registered public key format is invalid"}}`, http.StatusInternalServerError)
					return
				}
			}

			pubKey := ed25519.PublicKey(pubKeyBytes)

			// Validate signature and standard claims
			var verifiedClaims DeviceAssertionClaims
			token, err := jwt.ParseWithClaims(rawToken, &verifiedClaims, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return pubKey, nil
			})

			if err != nil || token == nil || !token.Valid {
				http.Error(w, `{"error":{"code":"assertion_signature_invalid","message":"Device assertion signature verification failed"}}`, http.StatusUnauthorized)
				return
			}

			// Enforce expiration and clock skew bounds (max 300s window, ±60s clock skew)
			now := time.Now()
			if verifiedClaims.IssuedAt != nil && verifiedClaims.ExpiresAt != nil {
				lifetime := verifiedClaims.ExpiresAt.Time.Sub(verifiedClaims.IssuedAt.Time)
				if lifetime > 360*time.Second {
					http.Error(w, `{"error":{"code":"assertion_lifetime_exceeded","message":"Assertion token lifetime must not exceed 300 seconds"}}`, http.StatusUnauthorized)
					return
				}
				if now.After(verifiedClaims.ExpiresAt.Time.Add(60 * time.Second)) {
					http.Error(w, `{"error":{"code":"assertion_expired","message":"Device assertion token expired"}}`, http.StatusUnauthorized)
					return
				}
			}

			// Check and record nonce (jti) for replay protection
			if verifiedClaims.ID != "" {
				if !globalNonceCache.CheckAndRecord(verifiedClaims.ID, 5*time.Minute) {
					http.Error(w, `{"error":{"code":"assertion_replay_detected","message":"Duplicate assertion jti detected (replay attack blocked)"}}`, http.StatusUnauthorized)
					return
				}
			}

			// Check device status
			if devKey.Status != "ACTIVE" {
				http.Error(w, `{"error":{"code":"device_revoked","message":"Device public key is no longer active"}}`, http.StatusForbidden)
				return
			}

			orgID := verifiedClaims.TenantID
			if orgID == "" {
				orgID = devKey.OrganizationID
			}

			var userIDPtr *string
			var confidence = "unknown"
			if verifiedClaims.UserID != "" {
				userIDPtr = &verifiedClaims.UserID
				confidence = "observed"
			}

			principal := &model.DevicePrincipal{
				DeviceID:              deviceID,
				OrganizationID:        orgID,
				UserID:                userIDPtr,
				IdentitySource:        "ed25519_assertion",
				DeviceVerified:        true,
				HumanIdentityVerified: false, // Ed25519 assertion proves device key possession, not IdP-authenticated human
				IdentityConfidence:    confidence,
				IdentityVerified:      true, // legacy compat
				DeviceState:           model.DeviceStateCompliant,
				RequestID:             r.Header.Get("X-Request-ID"),
			}

			ctx := context.WithValue(r.Context(), DevicePrincipalKey, principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// StrictDeviceOrAssertionAuth supports either X-Device-Authorization (Ed25519 signed JWT)
// or mTLS client certificate authentication.
func StrictDeviceOrAssertionAuth(st *store.Store, trustedVPCHeaderSecret string) func(http.Handler) http.Handler {
	assertionMW := DeviceAssertionAuth(st)
	mtlsMW := StrictDeviceMTLS(st, trustedVPCHeaderSecret)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Device-Authorization") != "" {
				assertionMW(next).ServeHTTP(w, r)
				return
			}
			// If Authorization header is provided and not an mTLS request, check if it's a device assertion token
			authHdr := r.Header.Get("Authorization")
			if strings.HasPrefix(authHdr, "Bearer ") && r.TLS == nil && r.Header.Get("X-Client-Cert-Serial") == "" {
				assertionMW(next).ServeHTTP(w, r)
				return
			}
			mtlsMW(next).ServeHTTP(w, r)
		})
	}
}

