package config

import (
	"encoding/hex"
	"testing"
)

// ── DeriveLDAPBindPassword ────────────────────────────────────────────────────

func TestDeriveLDAPBindPassword(t *testing.T) {
	t.Run("determinism same inputs same output", func(t *testing.T) {
		a := DeriveLDAPBindPassword("mysecret", "web1.example.com")
		b := DeriveLDAPBindPassword("mysecret", "web1.example.com")
		if a != b {
			t.Errorf("expected identical outputs, got %q and %q", a, b)
		}
	})

	t.Run("different hostnames give different outputs", func(t *testing.T) {
		a := DeriveLDAPBindPassword("mysecret", "web1.example.com")
		b := DeriveLDAPBindPassword("mysecret", "web2.example.com")
		if a == b {
			t.Errorf("expected different outputs for different hostnames, both got %q", a)
		}
	})

	t.Run("different secrets give different outputs", func(t *testing.T) {
		a := DeriveLDAPBindPassword("secret-one", "web1.example.com")
		b := DeriveLDAPBindPassword("secret-two", "web1.example.com")
		if a == b {
			t.Errorf("expected different outputs for different secrets, both got %q", a)
		}
	})

	t.Run("output is 64-char hex string", func(t *testing.T) {
		got := DeriveLDAPBindPassword("mysecret", "web1.example.com")
		if len(got) != 64 {
			t.Errorf("expected 64 chars, got %d: %q", len(got), got)
		}
		// Verify it is valid lowercase hex.
		if _, err := hex.DecodeString(got); err != nil {
			t.Errorf("output is not valid hex: %v", err)
		}
	})
}
