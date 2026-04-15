package mtls

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateCA(t *testing.T) {
	certPEM, keyPEM, signer, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}

	// Verify the cert is valid PEM
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("cert PEM is not a CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	if !cert.IsCA {
		t.Error("CA cert IsCA should be true")
	}
	if cert.Subject.CommonName != "identree mTLS CA" {
		t.Errorf("unexpected CN: %q", cert.Subject.CommonName)
	}

	// Verify key is valid PEM
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		t.Fatal("key PEM is not an EC PRIVATE KEY block")
	}

	// Verify they form a valid pair
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	// Verify the returned signer implements crypto.Signer
	var _ crypto.Signer = signer
}

func TestLoadOrGenerateCA_Generate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	pair, signer, err := LoadOrGenerateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	if pair.Leaf == nil {
		t.Fatal("expected parsed leaf cert")
	}
	if !pair.Leaf.IsCA {
		t.Error("generated cert should be a CA")
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}

	// Files should exist on disk
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("cert file not written: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("key file not written: %v", err)
	}

	// Key file should be 0600
	info, _ := os.Stat(keyPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("key file permissions: got %o, want 0600", info.Mode().Perm())
	}
}

func TestLoadOrGenerateCA_Load(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	// Generate first
	pair1, signer1, err := LoadOrGenerateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("first LoadOrGenerateCA: %v", err)
	}
	if signer1 == nil {
		t.Fatal("expected non-nil signer from generate")
	}

	// Load existing
	pair2, signer2, err := LoadOrGenerateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("second LoadOrGenerateCA: %v", err)
	}
	if signer2 == nil {
		t.Fatal("expected non-nil signer from load")
	}

	// Should be the same cert
	if pair1.Leaf.SerialNumber.Cmp(pair2.Leaf.SerialNumber) != 0 {
		t.Error("loaded cert has different serial than generated cert")
	}
}

func TestIssueCert(t *testing.T) {
	certPEM, _, signer, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	clientCertPEM, clientKeyPEM, err := IssueCert(caCert, signer, "test-host.example.com", 24*time.Hour)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// Parse and verify the client cert
	block, _ = pem.Decode(clientCertPEM)
	if block == nil {
		t.Fatal("no PEM block in client cert")
	}
	clientCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}

	if clientCert.Subject.CommonName != "test-host.example.com" {
		t.Errorf("unexpected CN: %q", clientCert.Subject.CommonName)
	}
	if len(clientCert.DNSNames) != 1 || clientCert.DNSNames[0] != "test-host.example.com" {
		t.Errorf("unexpected SANs: %v", clientCert.DNSNames)
	}
	if clientCert.IsCA {
		t.Error("client cert should not be a CA")
	}

	// Verify it chains to the CA
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := clientCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("client cert does not chain to CA: %v", err)
	}

	// Verify the key matches the cert
	if _, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM); err != nil {
		t.Fatalf("client X509KeyPair: %v", err)
	}
}

func TestIssueCert_EmptyHostname(t *testing.T) {
	certPEM, _, signer, _ := GenerateCA()
	block, _ := pem.Decode(certPEM)
	caCert, _ := x509.ParseCertificate(block.Bytes)

	_, _, err := IssueCert(caCert, signer, "", time.Hour)
	if err == nil {
		t.Fatal("expected error for empty hostname")
	}
}

func TestVerifyClientCert_Valid(t *testing.T) {
	certPEM, _, signer, _ := GenerateCA()
	block, _ := pem.Decode(certPEM)
	caCert, _ := x509.ParseCertificate(block.Bytes)

	clientCertPEM, _, err := IssueCert(caCert, signer, "myhost.local", 24*time.Hour)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	block, _ = pem.Decode(clientCertPEM)
	clientCert, _ := x509.ParseCertificate(block.Bytes)

	hostname, err := VerifyClientCert(caCert, []*x509.Certificate{clientCert})
	if err != nil {
		t.Fatalf("VerifyClientCert: %v", err)
	}
	if hostname != "myhost.local" {
		t.Errorf("hostname: got %q, want %q", hostname, "myhost.local")
	}
}

func TestVerifyClientCert_WrongCA(t *testing.T) {
	// Generate two separate CAs
	certPEM1, _, signer1, _ := GenerateCA()
	block1, _ := pem.Decode(certPEM1)
	caCert1, _ := x509.ParseCertificate(block1.Bytes)

	certPEM2, _, _, _ := GenerateCA()
	block2, _ := pem.Decode(certPEM2)
	caCert2, _ := x509.ParseCertificate(block2.Bytes)

	// Issue cert with CA1
	clientCertPEM, _, _ := IssueCert(caCert1, signer1, "host1.local", 24*time.Hour)
	block, _ := pem.Decode(clientCertPEM)
	clientCert, _ := x509.ParseCertificate(block.Bytes)

	// Verify against CA2 -- should fail
	_, err := VerifyClientCert(caCert2, []*x509.Certificate{clientCert})
	if err == nil {
		t.Fatal("expected error when verifying cert against wrong CA")
	}
}

func TestVerifyClientCert_Expired(t *testing.T) {
	certPEM, _, signer, _ := GenerateCA()
	block, _ := pem.Decode(certPEM)
	caCert, _ := x509.ParseCertificate(block.Bytes)

	// Issue a cert with 1ns TTL -- it will be expired by the time we verify
	clientCertPEM, _, err := IssueCert(caCert, signer, "expired.local", time.Nanosecond)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// Wait for it to expire (the NotBefore is 5 minutes in the past, but
	// NotAfter is now+1ns, so it's already expired).
	time.Sleep(time.Millisecond)

	block, _ = pem.Decode(clientCertPEM)
	clientCert, _ := x509.ParseCertificate(block.Bytes)

	_, err = VerifyClientCert(caCert, []*x509.Certificate{clientCert})
	if err == nil {
		t.Fatal("expected error for expired cert")
	}
}

func TestVerifyClientCert_NoCerts(t *testing.T) {
	certPEM, _, _, _ := GenerateCA()
	block, _ := pem.Decode(certPEM)
	caCert, _ := x509.ParseCertificate(block.Bytes)

	_, err := VerifyClientCert(caCert, nil)
	if err == nil {
		t.Fatal("expected error for empty peer certs")
	}
}
