// Package signing provides Ed25519-based script signing and verification.
// The identree server signs the install script at startup so hosts can verify
// its integrity before execution.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

// GenerateSigningKey creates a new Ed25519 signing keypair.
func GenerateSigningKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return pub, priv, nil
}

// LoadOrGenerateSigningKey loads an Ed25519 keypair from the given PEM files.
// If the files do not exist, it generates a new keypair and saves them.
func LoadOrGenerateSigningKey(pubPath, privPath string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	// Try loading existing keys.
	pub, priv, err := loadSigningKey(pubPath, privPath)
	if err == nil {
		return pub, priv, nil
	}
	if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("load signing key: %w", err)
	}

	// Generate new keypair.
	pub, priv, err = GenerateSigningKey()
	if err != nil {
		return nil, nil, err
	}

	// Save private key.
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: priv.Seed(),
	})
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return nil, nil, fmt.Errorf("write private key: %w", err)
	}

	// Save public key.
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: pub,
	})
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		return nil, nil, fmt.Errorf("write public key: %w", err)
	}

	return pub, priv, nil
}

// loadSigningKey reads an Ed25519 keypair from PEM files.
func loadSigningKey(pubPath, privPath string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	privData, err := os.ReadFile(privPath)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(privData)
	if block == nil || block.Type != "ED25519 PRIVATE KEY" {
		return nil, nil, fmt.Errorf("invalid private key PEM in %s", privPath)
	}
	if len(block.Bytes) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("invalid private key seed length: got %d, want %d", len(block.Bytes), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(block.Bytes)

	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, nil, err
	}
	pubBlock, _ := pem.Decode(pubData)
	if pubBlock == nil || pubBlock.Type != "ED25519 PUBLIC KEY" {
		return nil, nil, fmt.Errorf("invalid public key PEM in %s", pubPath)
	}
	if len(pubBlock.Bytes) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("invalid public key length: got %d, want %d", len(pubBlock.Bytes), ed25519.PublicKeySize)
	}
	pub := ed25519.PublicKey(pubBlock.Bytes)

	return pub, priv, nil
}

// SignScript signs arbitrary data with the private key and returns a
// base64-encoded (standard encoding, no padding) detached signature.
func SignScript(privateKey ed25519.PrivateKey, data []byte) string {
	sig := ed25519.Sign(privateKey, data)
	return base64.RawStdEncoding.EncodeToString(sig)
}

// VerifyScript verifies a base64-encoded detached Ed25519 signature.
func VerifyScript(publicKey ed25519.PublicKey, data []byte, signature string) bool {
	sig, err := base64.RawStdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(publicKey, data, sig)
}

// EncodePubKeyPEM returns the PEM-encoded public key suitable for serving
// at /install.pub.
func EncodePubKeyPEM(pub ed25519.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: pub,
	})
}

// LoadPrivateKey reads an Ed25519 private key from a PEM file.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "ED25519 PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key PEM: expected ED25519 PRIVATE KEY block")
	}
	if len(block.Bytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid private key seed length: got %d, want %d", len(block.Bytes), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(block.Bytes), nil
}

// LoadPublicKey reads an Ed25519 public key from a PEM file.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicKeyPEM(data)
}

// ParsePublicKeyPEM parses an Ed25519 public key from PEM bytes.
func ParsePublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "ED25519 PUBLIC KEY" {
		return nil, fmt.Errorf("invalid public key PEM: expected ED25519 PUBLIC KEY block")
	}
	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: got %d, want %d", len(block.Bytes), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(block.Bytes), nil
}
