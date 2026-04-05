package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"time"
)

// defaultSAMLCertPath / defaultSAMLKeyPath are the default locations for
// auto-generated SAML SP certificate and key files.
const (
	defaultSAMLCertPath = "/config/saml-sp.crt"
	defaultSAMLKeyPath  = "/config/saml-sp.key"
)

// loadOrGenerateSAMLCert loads the SP certificate and private key from the given
// paths, or auto-generates a self-signed certificate if both paths are empty.
// Returns PEM-encoded certificate and key bytes.
func loadOrGenerateSAMLCert(certFile, keyFile string) (certPEM, keyPEM []byte, err error) {
	if certFile != "" && keyFile != "" {
		certPEM, err = os.ReadFile(certFile)
		if err != nil {
			return nil, nil, fmt.Errorf("reading SAML cert %s: %w", certFile, err)
		}
		keyPEM, err = os.ReadFile(keyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("reading SAML key %s: %w", keyFile, err)
		}
		slog.Info("SAML SP certificate loaded from disk", "cert", certFile, "key", keyFile)
		return certPEM, keyPEM, nil
	}

	// Try to load from default paths first (persisted from a previous run).
	certPEM, certErr := os.ReadFile(defaultSAMLCertPath)
	keyPEM, keyErr := os.ReadFile(defaultSAMLKeyPath)
	if certErr == nil && keyErr == nil {
		slog.Info("SAML SP certificate loaded from default paths", "cert", defaultSAMLCertPath, "key", defaultSAMLKeyPath)
		return certPEM, keyPEM, nil
	}

	// Generate a new self-signed certificate.
	slog.Info("SAML SP certificate not found, generating self-signed certificate")
	return generateSAMLSelfSignedCert()
}

// generateSAMLSelfSignedCert generates a self-signed ECDSA P-256 certificate
// valid for 10 years and writes it to the default paths. Returns PEM-encoded
// certificate and key bytes.
func generateSAMLSelfSignedCert() (certPEM, keyPEM []byte, err error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating ECDSA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generating serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "identree SAML SP",
			Organization: []string{"identree"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("creating certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Try to persist the generated cert/key for reuse across restarts.
	if err := os.WriteFile(defaultSAMLCertPath, certPEM, 0644); err != nil {
		slog.Warn("SAML SP: could not persist certificate", "path", defaultSAMLCertPath, "err", err)
	}
	if err := os.WriteFile(defaultSAMLKeyPath, keyPEM, 0600); err != nil {
		slog.Warn("SAML SP: could not persist private key", "path", defaultSAMLKeyPath, "err", err)
	}

	slog.Info("SAML SP self-signed certificate generated",
		"cert", defaultSAMLCertPath, "key", defaultSAMLKeyPath,
		"not_after", template.NotAfter.Format("2006-01-02"))
	return certPEM, keyPEM, nil
}
