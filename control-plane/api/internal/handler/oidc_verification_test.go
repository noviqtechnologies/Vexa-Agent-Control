package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func generateTestRSAKey(t *testing.T) (*rsa.PrivateKey, string, string) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	nStr := base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())
	eBytes := big.NewInt(int64(privKey.E)).Bytes()
	eStr := base64.RawURLEncoding.EncodeToString(eBytes)
	return privKey, nStr, eStr
}

func TestOIDCVerifier_VerifyIDToken(t *testing.T) {
	privKey, nStr, eStr := generateTestRSAKey(t)
	kid := "test-key-id-1"

	// Mock JWKS HTTP server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := JWKSResponse{
			Keys: []JWK{
				{
					Kty: "RSA",
					Kid: kid,
					Alg: "RS256",
					Use: "sig",
					N:   nStr,
					E:   eStr,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer jwksServer.Close()

	verifier := NewOIDCVerifier()
	ctx := context.Background()

	issuer := "https://accounts.google.com"
	audience := "agentcontrol-client-id"
	nonce := "random-nonce-123"

	// Helper to mint a signed test ID token
	mintToken := func(claims jwt.MapClaims, key *rsa.PrivateKey, tokenKid string) string {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		if tokenKid != "" {
			token.Header["kid"] = tokenKid
		}
		signed, err := token.SignedString(key)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}
		return signed
	}

	validClaims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   "google-sub-998877",
		"aud":   audience,
		"email": "developer@yourcompany.com",
		"nonce": nonce,
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}

	// 1. Happy Path: Valid signature and all claims matching
	validToken := mintToken(validClaims, privKey, kid)
	claims, err := verifier.VerifyIDToken(ctx, validToken, jwksServer.URL, issuer, audience, nonce)
	if err != nil {
		t.Fatalf("expected valid token to pass verification, got error: %v", err)
	}
	if claims["sub"] != "google-sub-998877" || claims["email"] != "developer@yourcompany.com" {
		t.Errorf("unexpected claims returned: %v", claims)
	}

	// 2. Forged Signature: Signed with another RSA private key
	otherKey, _, _ := generateTestRSAKey(t)
	forgedToken := mintToken(validClaims, otherKey, kid)
	if _, err := verifier.VerifyIDToken(ctx, forgedToken, jwksServer.URL, issuer, audience, nonce); err == nil {
		t.Fatal("expected forged token with wrong private key to fail verification, but it succeeded")
	}

	// 3. Expired Token
	expiredClaims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   "google-sub-998877",
		"aud":   audience,
		"email": "developer@yourcompany.com",
		"nonce": nonce,
		"exp":   time.Now().Add(-10 * time.Minute).Unix(),
	}
	expiredToken := mintToken(expiredClaims, privKey, kid)
	if _, err := verifier.VerifyIDToken(ctx, expiredToken, jwksServer.URL, issuer, audience, nonce); err == nil {
		t.Fatal("expected expired token to fail verification, but it succeeded")
	}

	// 4. Wrong Issuer
	if _, err := verifier.VerifyIDToken(ctx, validToken, jwksServer.URL, "https://login.microsoftonline.com/wrong", audience, nonce); err == nil {
		t.Fatal("expected token with wrong issuer to fail verification, but it succeeded")
	}

	// 5. Wrong Audience / Client ID
	if _, err := verifier.VerifyIDToken(ctx, validToken, jwksServer.URL, issuer, "malicious-client-id", nonce); err == nil {
		t.Fatal("expected token with wrong audience to fail verification, but it succeeded")
	}

	// 6. Mismatched Nonce
	if _, err := verifier.VerifyIDToken(ctx, validToken, jwksServer.URL, issuer, audience, "different-nonce-999"); err == nil {
		t.Fatal("expected token with mismatched nonce to fail verification, but it succeeded")
	}
}
