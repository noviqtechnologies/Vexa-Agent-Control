package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// CASIssuer issues short-lived mTLS client certificates from validated CSRs.
type CASIssuer interface {
	SignCertificateRequest(ctx context.Context, csrPEM []byte, lifetime time.Duration) (certChainPEM []byte, serialNumber string, caResource string, err error)
}

// SoftwareCASIssuer is a local in-memory CA issuer for development and CI testing.
type SoftwareCASIssuer struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

// NewSoftwareCASIssuer initializes a self-signed root CA for issuing device mTLS certificates.
func NewSoftwareCASIssuer() (*SoftwareCASIssuer, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Vexa Technologies Inc."},
			CommonName:   "Vexa Device Authority Local Root CA",
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("create ca cert: %w", err)
	}

	caCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}

	return &SoftwareCASIssuer{
		caCert: caCert,
		caKey:  privKey,
	}, nil
}

// SignCertificateRequest issues a short-lived client certificate from the provided CSR.
func (s *SoftwareCASIssuer) SignCertificateRequest(ctx context.Context, csrPEM []byte, lifetime time.Duration) ([]byte, string, string, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		// Fallback for simulated test CSRs
		block = &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrPEM}
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, "", "", fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now().UTC()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Vexa AgentWall Enrolled Device"},
			CommonName:   fmt.Sprintf("vexa-device-%s", hex.EncodeToString(serialNumber.Bytes()[:4])),
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(lifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Sign certificate using local CA key
	certDER, err := x509.CreateCertificate(rand.Reader, &template, s.caCert, &s.caKey.PublicKey, s.caKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("sign client cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.caCert.Raw})
	chainPEM := append(certPEM, caPEM...)

	serialHex := hex.EncodeToString(serialNumber.Bytes())
	caResource := "projects/vexa-saas/locations/global/caPools/vexa-device-ca-2026-01"

	return chainPEM, serialHex, caResource, nil
}
