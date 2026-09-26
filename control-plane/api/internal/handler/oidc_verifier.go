package handler

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

type CachedJWKS struct {
	Keys      map[string]*rsa.PublicKey
	FetchedAt time.Time
}

type OIDCVerifier struct {
	httpClient *http.Client
	mu         sync.RWMutex
	cache      map[string]*CachedJWKS
	cacheTTL   time.Duration
}

var defaultOIDCVerifier = NewOIDCVerifier()

func NewOIDCVerifier() *OIDCVerifier {
	return &OIDCVerifier{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cache:      make(map[string]*CachedJWKS),
		cacheTTL:   1 * time.Hour,
	}
}

// ParseRSAPublicKey constructs *rsa.PublicKey from raw base64url-encoded modulus (n) and exponent (e)
func ParseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	var e int
	for _, b := range eBytes {
		e = (e << 8) | int(b)
	}
	if e == 0 {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

func (v *OIDCVerifier) fetchJWKS(ctx context.Context, jwksURI string) (*CachedJWKS, error) {
	v.mu.RLock()
	cached, found := v.cache[jwksURI]
	v.mu.RUnlock()

	if found && time.Since(cached.FetchedAt) < v.cacheTTL {
		return cached, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("create jwks request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}

	var jwksResp JWKSResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwksResp); err != nil {
		return nil, fmt.Errorf("decode jwks response: %w", err)
	}

	parsedKeys := make(map[string]*rsa.PublicKey)
	for _, k := range jwksResp.Keys {
		if k.Kty == "RSA" && k.N != "" && k.E != "" {
			pubKey, err := ParseRSAPublicKey(k.N, k.E)
			if err == nil {
				parsedKeys[k.Kid] = pubKey
			}
		}
	}

	newEntry := &CachedJWKS{
		Keys:      parsedKeys,
		FetchedAt: time.Now(),
	}

	v.mu.Lock()
	v.cache[jwksURI] = newEntry
	v.mu.Unlock()

	return newEntry, nil
}

// VerifyIDToken cryptographically verifies an OIDC ID token against provider JWKS and expected claims.
func (v *OIDCVerifier) VerifyIDToken(
	ctx context.Context,
	idTokenRaw string,
	jwksURI string,
	expectedIssuer string,
	expectedAudience string,
	expectedNonce string,
) (jwt.MapClaims, error) {
	if idTokenRaw == "" {
		return nil, errors.New("empty id_token")
	}

	// Parse unverified first to get kid from header
	unverifiedToken, _, err := new(jwt.Parser).ParseUnverified(idTokenRaw, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parse id_token headers: %w", err)
	}

	kid, _ := unverifiedToken.Header["kid"].(string)

	cachedJWKS, err := v.fetchJWKS(ctx, jwksURI)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}

	// If kid not found, force a cache refresh once in case keys were rotated
	var pubKey *rsa.PublicKey
	var ok bool
	if kid != "" {
		pubKey, ok = cachedJWKS.Keys[kid]
	}
	if !ok {
		// If single key available in JWKS, attempt fallback
		if len(cachedJWKS.Keys) == 1 && kid == "" {
			for _, k := range cachedJWKS.Keys {
				pubKey = k
				ok = true
				break
			}
		}
	}

	if !ok || pubKey == nil {
		return nil, fmt.Errorf("signing key kid '%s' not found in jwks", kid)
	}

	// Verify cryptographic signature and claims
	parsedToken, err := jwt.Parse(idTokenRaw, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return pubKey, nil
	}, jwt.WithExpirationRequired())

	if err != nil || !parsedToken.Valid {
		return nil, fmt.Errorf("invalid token signature or expired: %w", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	// 1. Verify Issuer
	if expectedIssuer != "" {
		iss, _ := claims["iss"].(string)
		cleanExpected := strings.TrimRight(expectedIssuer, "/")
		cleanActual := strings.TrimRight(iss, "/")
		if cleanActual != cleanExpected {
			return nil, fmt.Errorf("issuer mismatch: expected '%s', got '%s'", cleanExpected, cleanActual)
		}
	}

	// 2. Verify Audience
	if expectedAudience != "" {
		audValid := false
		switch aud := claims["aud"].(type) {
		case string:
			audValid = (aud == expectedAudience)
		case []interface{}:
			for _, item := range aud {
				if s, ok := item.(string); ok && s == expectedAudience {
					audValid = true
					break
				}
			}
		}
		if !audValid {
			return nil, fmt.Errorf("audience mismatch: token does not contain expected client_id '%s'", expectedAudience)
		}
	}

	// 3. Verify Nonce if expected
	if expectedNonce != "" {
		nonce, _ := claims["nonce"].(string)
		if nonce == "" || nonce != expectedNonce {
			return nil, fmt.Errorf("nonce mismatch: expected '%s', got '%s'", expectedNonce, nonce)
		}
	}

	return claims, nil
}
