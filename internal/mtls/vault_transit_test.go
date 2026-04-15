package mtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockVaultTransit creates an httptest server that simulates Vault's Transit
// secrets engine for an ECDSA P-256 key.
func mockVaultTransit(t *testing.T, key *ecdsa.PrivateKey) *httptest.Server {
	t.Helper()

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check auth token
		if r.Header.Get("X-Vault-Token") != "test-token" {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			return
		}

		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/v1/transit/keys/"):
			// Return key info with public key
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"keys": map[string]interface{}{
						"1": map[string]interface{}{
							"public_key": string(pubPEM),
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case r.Method == "POST" && strings.Contains(r.URL.Path, "/v1/transit/sign/"):
			var req struct {
				Input            string `json:"input"`
				HashAlgorithm    string `json:"hash_algorithm"`
				Prehashed        bool   `json:"prehashed"`
				MarshalingAlgo   string `json:"marshaling_algorithm"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, `{"errors":["bad request"]}`, http.StatusBadRequest)
				return
			}

			digest, err := base64.StdEncoding.DecodeString(req.Input)
			if err != nil {
				http.Error(w, `{"errors":["bad base64"]}`, http.StatusBadRequest)
				return
			}

			// Sign with the private key
			r_, s_, err := ecdsa.Sign(rand.Reader, key, digest)
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"errors":["%s"]}`, err), http.StatusInternalServerError)
				return
			}

			// Marshal as ASN.1 DER (matching marshaling_algorithm: asn1)
			sigBytes, err := asn1.Marshal(struct{ R, S *big.Int }{r_, s_})
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"errors":["%s"]}`, err), http.StatusInternalServerError)
				return
			}

			sig64 := base64.StdEncoding.EncodeToString(sigBytes)
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"signature": "vault:v1:" + sig64,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		default:
			http.Error(w, `{"errors":["not found"]}`, http.StatusNotFound)
		}
	}))
}

func TestNewVaultTransitSigner(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	srv := mockVaultTransit(t, key)
	defer srv.Close()

	signer, err := NewVaultTransitSignerWithClient(srv.URL, "test-token", "identree-ca", srv.Client())
	if err != nil {
		t.Fatalf("NewVaultTransitSignerWithClient: %v", err)
	}

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("expected *ecdsa.PublicKey")
	}
	if !pub.Equal(&key.PublicKey) {
		t.Error("public key mismatch")
	}
}

func TestNewVaultTransitSigner_BadToken(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := mockVaultTransit(t, key)
	defer srv.Close()

	_, err := NewVaultTransitSignerWithClient(srv.URL, "wrong-token", "identree-ca", srv.Client())
	if err == nil {
		t.Fatal("expected error with wrong token")
	}
}

func TestVaultTransitSigner_Sign(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	srv := mockVaultTransit(t, key)
	defer srv.Close()

	signer, err := NewVaultTransitSignerWithClient(srv.URL, "test-token", "identree-ca", srv.Client())
	if err != nil {
		t.Fatalf("NewVaultTransitSignerWithClient: %v", err)
	}

	// Sign a digest
	msg := []byte("hello world")
	digest := sha256.Sum256(msg)
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}

	// Verify the signature
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
		t.Error("signature verification failed")
	}
}

func TestVaultTransitSigner_IssueCert(t *testing.T) {
	// This is the key test: use VaultTransitSigner as the crypto.Signer
	// for IssueCert, proving end-to-end certificate signing via Vault Transit.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	srv := mockVaultTransit(t, key)
	defer srv.Close()

	vaultSigner, err := NewVaultTransitSignerWithClient(srv.URL, "test-token", "identree-ca", srv.Client())
	if err != nil {
		t.Fatalf("NewVaultTransitSignerWithClient: %v", err)
	}

	// Create a CA certificate using the Vault key's public key.
	// In production, the CA cert would be generated during key creation
	// and stored separately (or fetched from Vault).
	serial, _ := randomSerial()
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"identree"},
			CommonName:   "identree mTLS CA (Vault Transit)",
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	// Self-sign the CA cert using the Vault signer
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, vaultSigner)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	// Now issue a client certificate using the Vault signer
	clientCertPEM, clientKeyPEM, err := IssueCert(caCert, vaultSigner, "vault-test-host.local", 24*time.Hour)
	if err != nil {
		t.Fatalf("IssueCert with VaultTransitSigner: %v", err)
	}

	// Parse and verify the client cert
	block, _ := pem.Decode(clientCertPEM)
	if block == nil {
		t.Fatal("no PEM block in client cert")
	}
	clientCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}

	if clientCert.Subject.CommonName != "vault-test-host.local" {
		t.Errorf("unexpected CN: %q", clientCert.Subject.CommonName)
	}

	// Verify the chain: client cert -> CA cert
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := clientCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("client cert does not chain to CA: %v", err)
	}

	// Verify the client key matches the cert
	if _, err := tls_x509KeyPair(clientCertPEM, clientKeyPEM); err != nil {
		t.Fatalf("client X509KeyPair: %v", err)
	}

	// Verify the client cert via VerifyClientCert
	hostname, err := VerifyClientCert(caCert, []*x509.Certificate{clientCert})
	if err != nil {
		t.Fatalf("VerifyClientCert: %v", err)
	}
	if hostname != "vault-test-host.local" {
		t.Errorf("hostname: got %q, want %q", hostname, "vault-test-host.local")
	}
}

// tls_x509KeyPair wraps crypto/tls.X509KeyPair to avoid importing crypto/tls
// with the same name as the test package's variables.
func tls_x509KeyPair(certPEM, keyPEM []byte) (interface{}, error) {
	import_tls_x509kp := func() (interface{}, error) {
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return nil, fmt.Errorf("no cert PEM block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		keyBlock, _ := pem.Decode(keyPEM)
		if keyBlock == nil {
			return nil, fmt.Errorf("no key PEM block")
		}
		privKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, err
		}

		// Verify the public key matches
		ecPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("cert public key is not ECDSA")
		}
		if !ecPub.Equal(&privKey.PublicKey) {
			return nil, fmt.Errorf("cert public key does not match private key")
		}
		return cert, nil
	}
	return import_tls_x509kp()
}

func TestVaultTransitSigner_SignRawRS(t *testing.T) {
	// Test that the signer handles Vault returning raw r||s format
	// (without ASN.1 wrapping) by re-encoding to ASN.1 DER.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Create a mock that returns raw r||s instead of ASN.1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			return
		}

		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/v1/transit/keys/"):
			pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
			pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"keys": map[string]interface{}{
						"1": map[string]interface{}{
							"public_key": string(pubPEM),
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case r.Method == "POST" && strings.Contains(r.URL.Path, "/v1/transit/sign/"):
			var req struct {
				Input string `json:"input"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			digest, _ := base64.StdEncoding.DecodeString(req.Input)

			rInt, sInt, _ := ecdsa.Sign(rand.Reader, key, digest)

			// Return raw r||s (32 bytes each for P-256)
			byteLen := 32
			rBytes := rInt.Bytes()
			sBytes := sInt.Bytes()
			rawSig := make([]byte, 2*byteLen)
			copy(rawSig[byteLen-len(rBytes):byteLen], rBytes)
			copy(rawSig[2*byteLen-len(sBytes):], sBytes)

			sig64 := base64.StdEncoding.EncodeToString(rawSig)
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"signature": "vault:v1:" + sig64,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		default:
			http.Error(w, `{"errors":["not found"]}`, http.StatusNotFound)
		}
	}))
	defer srv.Close()

	signer, err := NewVaultTransitSignerWithClient(srv.URL, "test-token", "identree-ca", srv.Client())
	if err != nil {
		t.Fatalf("NewVaultTransitSignerWithClient: %v", err)
	}

	msg := []byte("test raw rs")
	digest := sha256.Sum256(msg)
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Should be valid ASN.1 DER
	if !isASN1Signature(sig) {
		t.Error("expected ASN.1 DER signature")
	}

	// Should verify
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
		t.Error("signature verification failed for raw r||s input")
	}
}
