package signing

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateSigningKey(t *testing.T) {
	pub, priv, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("public key length: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key length: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}

	data := []byte("#!/bin/bash\nset -euo pipefail\necho hello world\n")
	sig := SignScript(priv, data)
	if sig == "" {
		t.Fatal("SignScript returned empty signature")
	}

	if !VerifyScript(pub, data, sig) {
		t.Error("VerifyScript returned false for valid signature")
	}
}

func TestVerifyFailsWithWrongKey(t *testing.T) {
	_, priv, _ := GenerateSigningKey()
	otherPub, _, _ := GenerateSigningKey()

	data := []byte("install script content")
	sig := SignScript(priv, data)

	if VerifyScript(otherPub, data, sig) {
		t.Error("VerifyScript should fail with wrong public key")
	}
}

func TestVerifyFailsWithTamperedData(t *testing.T) {
	pub, priv, _ := GenerateSigningKey()

	data := []byte("original install script")
	sig := SignScript(priv, data)

	tampered := []byte("tampered install script")
	if VerifyScript(pub, tampered, sig) {
		t.Error("VerifyScript should fail with tampered data")
	}
}

func TestVerifyFailsWithInvalidSignature(t *testing.T) {
	pub, _, _ := GenerateSigningKey()
	data := []byte("some data")

	if VerifyScript(pub, data, "not-valid-base64!!!") {
		t.Error("VerifyScript should fail with invalid base64 signature")
	}
	if VerifyScript(pub, data, "AAAA") {
		t.Error("VerifyScript should fail with wrong-length signature")
	}
}

func TestLoadOrGenerateSigningKey_Generate(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "install-signing.pub")
	privPath := filepath.Join(dir, "install-signing.key")

	pub, priv, err := LoadOrGenerateSigningKey(pubPath, privPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateSigningKey (generate): %v", err)
	}

	// Files should exist.
	if _, err := os.Stat(pubPath); err != nil {
		t.Errorf("public key file not created: %v", err)
	}
	if _, err := os.Stat(privPath); err != nil {
		t.Errorf("private key file not created: %v", err)
	}

	// Private key file should be mode 0600.
	info, _ := os.Stat(privPath)
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("private key file permissions: got %o, want 0600", perm)
	}

	// Sign and verify with generated keys.
	data := []byte("test script")
	sig := SignScript(priv, data)
	if !VerifyScript(pub, data, sig) {
		t.Error("generated keys failed sign/verify round-trip")
	}
}

func TestLoadOrGenerateSigningKey_Load(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "install-signing.pub")
	privPath := filepath.Join(dir, "install-signing.key")

	// Generate first.
	pub1, priv1, err := LoadOrGenerateSigningKey(pubPath, privPath)
	if err != nil {
		t.Fatalf("first LoadOrGenerateSigningKey: %v", err)
	}

	// Load should return same keys.
	pub2, priv2, err := LoadOrGenerateSigningKey(pubPath, privPath)
	if err != nil {
		t.Fatalf("second LoadOrGenerateSigningKey: %v", err)
	}

	if !pub1.Equal(pub2) {
		t.Error("loaded public key differs from generated")
	}
	if !priv1.Equal(priv2) {
		t.Error("loaded private key differs from generated")
	}
}

func TestEncodePubKeyPEM(t *testing.T) {
	pub, _, _ := GenerateSigningKey()
	pemBytes := EncodePubKeyPEM(pub)
	if len(pemBytes) == 0 {
		t.Fatal("EncodePubKeyPEM returned empty")
	}

	// Should be parseable back.
	parsed, err := ParsePublicKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM: %v", err)
	}
	if !pub.Equal(parsed) {
		t.Error("round-trip PEM encode/decode changed the key")
	}
}

func TestParsePublicKeyPEM_Invalid(t *testing.T) {
	if _, err := ParsePublicKeyPEM([]byte("not pem")); err == nil {
		t.Error("expected error for non-PEM input")
	}
	if _, err := ParsePublicKeyPEM([]byte("-----BEGIN RSA PUBLIC KEY-----\nAAAA\n-----END RSA PUBLIC KEY-----\n")); err == nil {
		t.Error("expected error for wrong PEM type")
	}
}
