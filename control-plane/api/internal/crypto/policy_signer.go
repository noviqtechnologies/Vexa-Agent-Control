package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

// CanonicalSignPayload produces the exact length-prefixed, domain-separated binary payload
// matching Rust's `canonical_sign_payload` in src/policy/signed.rs.
func CanonicalSignPayload(
	schemaVersion string,
	policyID string,
	revision uint64,
	yamlPolicy string,
	issuedAt string,
	expiresAt *string,
) []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("vexa-policy-bundle-v1\x00")

	writeLengthPrefixed(buf, []byte(schemaVersion))
	writeLengthPrefixed(buf, []byte(policyID))

	revBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(revBytes, revision)
	buf.Write(revBytes)

	writeLengthPrefixed(buf, []byte(yamlPolicy))
	writeLengthPrefixed(buf, []byte(issuedAt))

	if expiresAt != nil {
		buf.WriteByte(1)
		writeLengthPrefixed(buf, []byte(*expiresAt))
	} else {
		buf.WriteByte(0)
	}

	return buf.Bytes()
}

func writeLengthPrefixed(buf *bytes.Buffer, data []byte) {
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(data)))
	buf.Write(lenBytes)
	buf.Write(data)
}

// SignPolicyBundle signs policy YAML using an Ed25519 private key.
func SignPolicyBundle(
	privKey ed25519.PrivateKey,
	policyID string,
	revision uint64,
	yamlPolicy string,
	expiresAt *string,
) (*model.SignedPolicyBundle, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size: expected %d, got %d", ed25519.PrivateKeySize, len(privKey))
	}

	pubKey := privKey.Public().(ed25519.PublicKey)
	pubKeyHex := hex.EncodeToString(pubKey)

	schemaVersion := "2.0"
	issuedAt := time.Now().UTC().Format(time.RFC3339)

	payload := CanonicalSignPayload(schemaVersion, policyID, revision, yamlPolicy, issuedAt, expiresAt)
	sig := ed25519.Sign(privKey, payload)
	sigHex := hex.EncodeToString(sig)

	return &model.SignedPolicyBundle{
		SchemaVersion:  schemaVersion,
		PolicyID:       policyID,
		PolicyRevision: revision,
		PolicyYaml:     yamlPolicy,
		Signature:      sigHex,
		PublicKey:      pubKeyHex,
		IssuedAt:       issuedAt,
		ExpiresAt:      expiresAt,
	}, nil
}

// VerifyPolicyBundle cryptographically verifies a signed policy bundle.
func VerifyPolicyBundle(bundle *model.SignedPolicyBundle, trustedKeys []string) error {
	if bundle == nil {
		return errors.New("policy bundle is nil")
	}

	// 1. Verify key trust if a trusted keyring is provided
	if len(trustedKeys) > 0 {
		trusted := false
		for _, tk := range trustedKeys {
			if strings.EqualFold(strings.TrimSpace(tk), strings.TrimSpace(bundle.PublicKey)) {
				trusted = true
				break
			}
		}
		if !trusted {
			return fmt.Errorf("public key '%s' is not in trusted keyring", bundle.PublicKey)
		}
	}

	// 2. Decode public key
	pubKeyBytes, err := hex.DecodeString(bundle.PublicKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key hex: %v", err)
	}

	// 3. Decode signature
	sigBytes, err := hex.DecodeString(bundle.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature hex: %v", err)
	}

	// 4. Reconstruct canonical binary payload
	payload := CanonicalSignPayload(
		bundle.SchemaVersion,
		bundle.PolicyID,
		bundle.PolicyRevision,
		bundle.PolicyYaml,
		bundle.IssuedAt,
		bundle.ExpiresAt,
	)

	// 5. Verify Ed25519 signature
	if !ed25519.Verify(pubKeyBytes, payload, sigBytes) {
		return errors.New("cryptographic signature verification failed")
	}

	// 6. Check expiration
	if bundle.ExpiresAt != nil {
		exp, err := time.Parse(time.RFC3339, *bundle.ExpiresAt)
		if err != nil {
			return fmt.Errorf("invalid expires_at timestamp: %w", err)
		}
		if time.Now().UTC().After(exp) {
			return fmt.Errorf("policy bundle expired at %s", *bundle.ExpiresAt)
		}
	}

	return nil
}
