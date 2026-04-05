// Package mtls provides mutual TLS client certificate authentication for
// identree's PAM client endpoints. identree generates a self-signed CA and
// issues client certificates at provision time.
package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// GenerateCA creates a new self-signed ECDSA P-256 CA certificate and private
// key. The CA is valid for 10 years and is constrained to signing client
// certificates (IsCA=true, KeyUsageCertSign|CRLSign).
func GenerateCA() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"identree"},
			CommonName:   "identree mTLS CA",
		},
		NotBefore:             now.Add(-5 * time.Minute), // clock-skew tolerance
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal CA key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// LoadOrGenerateCA loads an existing CA certificate+key from disk, or generates
// a new one and writes it to the provided paths. The returned tls.Certificate
// contains both the parsed x509 certificate and the private key.
func LoadOrGenerateCA(certPath, keyPath string) (tls.Certificate, error) {
	// Try loading existing files first.
	if certPath != "" && keyPath != "" {
		certData, certErr := os.ReadFile(certPath)
		keyData, keyErr := os.ReadFile(keyPath)
		if certErr == nil && keyErr == nil {
			pair, err := tls.X509KeyPair(certData, keyData)
			if err != nil {
				return tls.Certificate{}, fmt.Errorf("parse existing CA cert+key: %w", err)
			}
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				return tls.Certificate{}, fmt.Errorf("parse CA leaf: %w", err)
			}
			pair.Leaf = leaf
			return pair, nil
		}
	}

	// Generate new CA.
	certPEM, keyPEM, err := GenerateCA()
	if err != nil {
		return tls.Certificate{}, err
	}

	// Write to disk if paths are provided.
	if certPath != "" {
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			return tls.Certificate{}, fmt.Errorf("write CA cert: %w", err)
		}
	}
	if keyPath != "" {
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			return tls.Certificate{}, fmt.Errorf("write CA key: %w", err)
		}
	}

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse generated CA: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse generated CA leaf: %w", err)
	}
	pair.Leaf = leaf
	return pair, nil
}

// IssueCert signs a client certificate for the given hostname using the
// provided CA. The cert's CN and DNS SAN are set to hostname. The certificate
// is an ECDSA P-256 key with ExtKeyUsageClientAuth.
func IssueCert(ca tls.Certificate, hostname string, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	if hostname == "" {
		return nil, nil, fmt.Errorf("hostname must not be empty")
	}
	if ttl <= 0 {
		ttl = 365 * 24 * time.Hour
	}

	caCert := ca.Leaf
	if caCert == nil {
		var parseErr error
		caCert, parseErr = x509.ParseCertificate(ca.Certificate[0])
		if parseErr != nil {
			return nil, nil, fmt.Errorf("parse CA cert: %w", parseErr)
		}
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate client key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		DNSNames:    []string{hostname},
		NotBefore:   now.Add(-5 * time.Minute), // clock-skew tolerance
		NotAfter:    now.Add(ttl),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &clientKey.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sign client certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal client key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// VerifyClientCert verifies the peer certificate chain against a CA certificate
// and extracts the hostname from the leaf certificate's CN or first DNS SAN.
// Returns the verified hostname or an error.
func VerifyClientCert(caCert *x509.Certificate, peerCerts []*x509.Certificate) (string, error) {
	if len(peerCerts) == 0 {
		return "", fmt.Errorf("no client certificate presented")
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	leaf := peerCerts[0]
	intermediates := x509.NewCertPool()
	for _, c := range peerCerts[1:] {
		intermediates.AddCert(c)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime:   time.Now(),
	}

	if _, err := leaf.Verify(opts); err != nil {
		return "", fmt.Errorf("certificate verification failed: %w", err)
	}

	// Extract hostname: prefer DNS SAN, fall back to CN.
	hostname := ""
	if len(leaf.DNSNames) > 0 {
		hostname = leaf.DNSNames[0]
	}
	if hostname == "" {
		hostname = leaf.Subject.CommonName
	}
	if hostname == "" {
		return "", fmt.Errorf("certificate has no hostname in CN or SAN")
	}

	return hostname, nil
}

// randomSerial generates a random 128-bit serial number for X.509 certificates.
func randomSerial() (*big.Int, error) {
	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serial, nil
}
