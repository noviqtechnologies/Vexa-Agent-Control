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
	"errors"
	"fmt"
	"math/big"
	"time"
)

// CASIssuer issues short-lived mTLS client certificates from validated CSRs.
type CASIssuer interface {
	SignCertificateRequest(ctx context.Context, csrPEM []byte, lifetime time.Duration) (certChainPEM []byte, serialNumber string, caResource string, err error)
	CheckHealth(ctx context.Context) error
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

// CheckHealth verifies that the CA certificate and private key are loaded and healthy.
func (s *SoftwareCASIssuer) CheckHealth(ctx context.Context) error {
	if s.caCert == nil || s.caKey == nil {
		return fmt.Errorf("CA signer not initialized")
	}
	if time.Now().After(s.caCert.NotAfter) {
		return fmt.Errorf("CA certificate expired at %s", s.caCert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

var (
	ErrEmptyCSR        = errors.New("empty CSR payload")
	ErrInvalidPEMBlock = errors.New("invalid PEM block type for CSR: expected CERTIFICATE REQUEST")
	ErrParseCSR        = errors.New("failed to parse CSR ASN.1 DER structure")
	ErrCSRSignature    = errors.New("invalid CSR signature")
	ErrInvalidKeyAlg   = errors.New("unsupported CSR public key algorithm: expected ECDSA P-256")
	ErrInvalidCurve    = errors.New("unsupported elliptic curve: expected P-256")
)

// SignCertificateRequest issues a short-lived client certificate from the provided validated CSR.
func (s *SoftwareCASIssuer) SignCertificateRequest(ctx context.Context, csrPEM []byte, lifetime time.Duration) ([]byte, string, string, error) {
	if len(csrPEM) == 0 {
		return nil, "", "", ErrEmptyCSR
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return nil, "", "", fmt.Errorf("%w: invalid or missing PEM block", ErrInvalidPEMBlock)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, "", "", fmt.Errorf("%w: %v", ErrParseCSR, err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, "", "", fmt.Errorf("%w: %v", ErrCSRSignature, err)
	}

	// Verify device public key algorithm
	clientPubKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", "", ErrInvalidKeyAlg
	}
	if clientPubKey.Curve != elliptic.P256() {
		return nil, "", "", ErrInvalidCurve
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, "", "", fmt.Errorf("generate serial: %w", err)
	}

	subject := pkix.Name{
		Organization: []string{"Vexa Agent Control Enrolled Device"},
		CommonName:   fmt.Sprintf("vexa-device-%s", hex.EncodeToString(serialNumber.Bytes()[:4])),
	}
	if csr.Subject.CommonName != "" {
		subject.CommonName = csr.Subject.CommonName
	}
	if len(csr.Subject.Organization) > 0 {
		subject.Organization = csr.Subject.Organization
	}

	now := time.Now().UTC()
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(lifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Sign certificate using local CA private key, binding to the client device public key from the CSR
	certDER, err := x509.CreateCertificate(rand.Reader, &template, s.caCert, clientPubKey, s.caKey)
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
