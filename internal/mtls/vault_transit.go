package mtls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
)

// VaultTransitSigner implements crypto.Signer using HashiCorp Vault's Transit
// secrets engine. The CA private key never touches identree's filesystem;
// all signing is delegated to Vault.
type VaultTransitSigner struct {
	client  *http.Client
	addr    string           // Vault address (e.g. "http://vault:8200")
	token   string           // Vault token
	keyName string           // Transit key name (e.g. "identree-ca")
	pubKey  crypto.PublicKey  // cached public key
}

// NewVaultTransitSigner creates a new VaultTransitSigner. It immediately
// fetches the public key from Vault to cache it for Public() calls and to
// validate that the key exists and is accessible.
func NewVaultTransitSigner(addr, token, keyName string) (*VaultTransitSigner, error) {
	s := &VaultTransitSigner{
		client:  &http.Client{},
		addr:    strings.TrimRight(addr, "/"),
		token:   token,
		keyName: keyName,
	}

	pub, err := s.fetchPublicKey()
	if err != nil {
		return nil, fmt.Errorf("vault transit: fetch public key: %w", err)
	}
	s.pubKey = pub
	return s, nil
}

// NewVaultTransitSignerWithClient is like NewVaultTransitSigner but accepts
// a custom *http.Client (useful for testing with httptest).
func NewVaultTransitSignerWithClient(addr, token, keyName string, client *http.Client) (*VaultTransitSigner, error) {
	s := &VaultTransitSigner{
		client:  client,
		addr:    strings.TrimRight(addr, "/"),
		token:   token,
		keyName: keyName,
	}

	pub, err := s.fetchPublicKey()
	if err != nil {
		return nil, fmt.Errorf("vault transit: fetch public key: %w", err)
	}
	s.pubKey = pub
	return s, nil
}

// Public returns the public key associated with the Vault Transit key.
func (s *VaultTransitSigner) Public() crypto.PublicKey {
	return s.pubKey
}

// Sign delegates signing to Vault Transit. The digest parameter is the
// pre-hashed content (identree uses ECDSA P-256 with SHA-256). The rand
// parameter is ignored since Vault handles randomness internally.
//
// Vault Transit returns an ASN.1 DER-encoded ECDSA signature when using
// an ECDSA key, which is exactly what crypto.Signer callers expect.
func (s *VaultTransitSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashAlgo := "sha2-256"
	if opts != nil {
		switch opts.HashFunc() {
		case crypto.SHA256:
			hashAlgo = "sha2-256"
		case crypto.SHA384:
			hashAlgo = "sha2-384"
		case crypto.SHA512:
			hashAlgo = "sha2-512"
		default:
			// Default to sha2-256 for ECDSA P-256
			hashAlgo = "sha2-256"
		}
	}

	payload := map[string]interface{}{
		"input":               base64.StdEncoding.EncodeToString(digest),
		"hash_algorithm":      hashAlgo,
		"signature_algorithm": "pkcs1v15",
		"prehashed":           true,
		"marshaling_algorithm": "asn1",
	}

	// For ECDSA keys, Vault expects signature_algorithm to be omitted or empty;
	// it uses the key type to determine the algorithm. Override for ECDSA.
	if _, ok := s.pubKey.(*ecdsa.PublicKey); ok {
		delete(payload, "signature_algorithm")
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("vault transit: marshal sign request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/transit/sign/%s", s.addr, s.keyName)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("vault transit: create sign request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault transit: sign request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("vault transit: read sign response: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("vault transit: sign: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("vault transit: parse sign response: %w", err)
	}

	// Vault returns "vault:v1:base64_sig" — strip the prefix.
	parts := strings.SplitN(result.Data.Signature, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("vault transit: unexpected signature format: %q", result.Data.Signature)
	}

	sig, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		// Try URL-safe base64 (Vault sometimes uses RawStdEncoding)
		sig, err = base64.RawStdEncoding.DecodeString(parts[2])
		if err != nil {
			return nil, fmt.Errorf("vault transit: decode signature: %w", err)
		}
	}

	// If the key is ECDSA and Vault returned raw r||s (not ASN.1), re-encode
	// to ASN.1 DER which is what Go's x509.CreateCertificate expects.
	if ecPub, ok := s.pubKey.(*ecdsa.PublicKey); ok {
		if !isASN1Signature(sig) {
			byteLen := (ecPub.Curve.Params().BitSize + 7) / 8
			if len(sig) == 2*byteLen {
				r := new(big.Int).SetBytes(sig[:byteLen])
				sVal := new(big.Int).SetBytes(sig[byteLen:])
				sig, err = asn1.Marshal(struct{ R, S *big.Int }{r, sVal})
				if err != nil {
					return nil, fmt.Errorf("vault transit: marshal ECDSA signature to ASN.1: %w", err)
				}
			}
		}
	}

	return sig, nil
}

// isASN1Signature does a quick check whether the byte slice looks like a
// DER-encoded ASN.1 SEQUENCE (ECDSA signature). This is a heuristic —
// DER SEQUENCE starts with 0x30.
func isASN1Signature(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	return data[0] == 0x30
}

// fetchPublicKey retrieves the public key from the Vault Transit key.
func (s *VaultTransitSigner) fetchPublicKey() (crypto.PublicKey, error) {
	url := fmt.Sprintf("%s/v1/transit/keys/%s", s.addr, s.keyName)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", s.token)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data struct {
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	// Get the latest key version (highest numbered key).
	var latestPEM string
	latestVer := 0
	for ver, keyData := range result.Data.Keys {
		var v int
		if _, err := fmt.Sscanf(ver, "%d", &v); err == nil && v > latestVer {
			latestVer = v
			latestPEM = keyData.PublicKey
		}
	}
	if latestPEM == "" {
		return nil, fmt.Errorf("no public key found in transit key %q", s.keyName)
	}

	block, _ := pem.Decode([]byte(latestPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	return pub, nil
}
