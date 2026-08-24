package crypto_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/crypto"
)

func TestSoftwareCASIssuer_SignCertificateRequest_BindsClientPublicKey(t *testing.T) {
	issuer, err := crypto.NewSoftwareCASIssuer()
	if err != nil {
		t.Fatalf("failed to create software CAS issuer: %v", err)
	}

	// 1. Generate client ECDSA keypair
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	// 2. Create Certificate Signing Request (CSR)
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "vexa-device-test-01",
			Organization: []string{"Vexa Test Org"},
		},
		DNSNames: []string{"device.vexasec.local"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, clientKey)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// 3. Issue certificate from CSR
	certChainPEM, serialHex, caResource, err := issuer.SignCertificateRequest(context.Background(), csrPEM, 90*24*time.Hour)
	if err != nil {
		t.Fatalf("failed to sign certificate: %v", err)
	}

	if serialHex == "" || caResource == "" {
		t.Fatal("expected non-empty serialHex and caResource")
	}

	// 4. Parse the issued client certificate
	block, _ := pem.Decode(certChainPEM)
	if block == nil {
		t.Fatal("failed to decode issued certificate PEM")
	}

	issuedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse issued cert: %v", err)
	}

	// 5. Assert that the issued cert contains the client's public key, NOT the CA's public key
	clientECDSA, ok := issuedCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("issued cert public key is not ECDSA: %T", issuedCert.PublicKey)
	}

	if clientECDSA.X.Cmp(clientKey.PublicKey.X) != 0 || clientECDSA.Y.Cmp(clientKey.PublicKey.Y) != 0 {
		t.Fatal("issued certificate does not bind to the client's CSR public key!")
	}

	if issuedCert.Subject.CommonName != "vexa-device-test-01" {
		t.Errorf("expected CN 'vexa-device-test-01', got '%s'", issuedCert.Subject.CommonName)
	}
}
