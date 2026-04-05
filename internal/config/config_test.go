package config

import (
	"encoding/hex"
	"os"
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

// ── LoadServerConfig ─────────────────────────────────────────────────────────

// setEnvForTest sets an env var and registers cleanup to restore the original value.
func setEnvForTest(t *testing.T, key, value string) {
	t.Helper()
	old, existed := os.LookupEnv(key)
	os.Setenv(key, value)
	t.Cleanup(func() {
		if existed {
			os.Setenv(key, old)
		} else {
			os.Unsetenv(key)
		}
	})
}

// clearEnvForTest unsets an env var and registers cleanup to restore it.
func clearEnvForTest(t *testing.T, key string) {
	t.Helper()
	old, existed := os.LookupEnv(key)
	os.Unsetenv(key)
	t.Cleanup(func() {
		if existed {
			os.Setenv(key, old)
		} else {
			os.Unsetenv(key)
		}
	})
}

func TestLoadServerConfig_AuditLogMaxSize(t *testing.T) {
	t.Run("parses 50MB correctly", func(t *testing.T) {
		setEnvForTest(t, "IDENTREE_AUDIT_LOG_MAX_SIZE", "50MB")
		// Set required fields to avoid unrelated issues.
		setEnvForTest(t, "IDENTREE_OIDC_ISSUER_URL", "http://localhost")
		setEnvForTest(t, "IDENTREE_OIDC_CLIENT_ID", "test")
		setEnvForTest(t, "IDENTREE_OIDC_CLIENT_SECRET", "test")
		setEnvForTest(t, "IDENTREE_EXTERNAL_URL", "http://localhost")
		setEnvForTest(t, "IDENTREE_SHARED_SECRET", "test-secret-that-is-at-least-32-characters-long")
		setEnvForTest(t, "IDENTREE_LDAP_BASE_DN", "dc=test,dc=com")

		cfg, err := LoadServerConfig()
		if err != nil {
			t.Fatalf("LoadServerConfig: %v", err)
		}
		want := 50 * 1024 * 1024
		if cfg.AuditLogMaxSize != want {
			t.Errorf("AuditLogMaxSize = %d, want %d", cfg.AuditLogMaxSize, want)
		}
	})
}

func TestLoadServerConfig_AuditLogMaxFiles(t *testing.T) {
	t.Run("defaults to 5", func(t *testing.T) {
		clearEnvForTest(t, "IDENTREE_AUDIT_LOG_MAX_FILES")
		setEnvForTest(t, "IDENTREE_OIDC_ISSUER_URL", "http://localhost")
		setEnvForTest(t, "IDENTREE_OIDC_CLIENT_ID", "test")
		setEnvForTest(t, "IDENTREE_OIDC_CLIENT_SECRET", "test")
		setEnvForTest(t, "IDENTREE_EXTERNAL_URL", "http://localhost")
		setEnvForTest(t, "IDENTREE_SHARED_SECRET", "test-secret-that-is-at-least-32-characters-long")
		setEnvForTest(t, "IDENTREE_LDAP_BASE_DN", "dc=test,dc=com")

		cfg, err := LoadServerConfig()
		if err != nil {
			t.Fatalf("LoadServerConfig: %v", err)
		}
		if cfg.AuditLogMaxFiles != 5 {
			t.Errorf("AuditLogMaxFiles = %d, want 5", cfg.AuditLogMaxFiles)
		}
	})
}

func TestLoadServerConfig_StateBackend(t *testing.T) {
	t.Run("defaults to local", func(t *testing.T) {
		clearEnvForTest(t, "IDENTREE_STATE_BACKEND")
		setEnvForTest(t, "IDENTREE_OIDC_ISSUER_URL", "http://localhost")
		setEnvForTest(t, "IDENTREE_OIDC_CLIENT_ID", "test")
		setEnvForTest(t, "IDENTREE_OIDC_CLIENT_SECRET", "test")
		setEnvForTest(t, "IDENTREE_EXTERNAL_URL", "http://localhost")
		setEnvForTest(t, "IDENTREE_SHARED_SECRET", "test-secret-that-is-at-least-32-characters-long")
		setEnvForTest(t, "IDENTREE_LDAP_BASE_DN", "dc=test,dc=com")

		cfg, err := LoadServerConfig()
		if err != nil {
			t.Fatalf("LoadServerConfig: %v", err)
		}
		if cfg.StateBackend != "local" {
			t.Errorf("StateBackend = %q, want %q", cfg.StateBackend, "local")
		}
	})
}

func TestLoadServerConfig_RedisURL(t *testing.T) {
	t.Run("parses RedisURL from env", func(t *testing.T) {
		setEnvForTest(t, "IDENTREE_REDIS_URL", "redis://myhost:6379/2")
		setEnvForTest(t, "IDENTREE_OIDC_ISSUER_URL", "http://localhost")
		setEnvForTest(t, "IDENTREE_OIDC_CLIENT_ID", "test")
		setEnvForTest(t, "IDENTREE_OIDC_CLIENT_SECRET", "test")
		setEnvForTest(t, "IDENTREE_EXTERNAL_URL", "http://localhost")
		setEnvForTest(t, "IDENTREE_SHARED_SECRET", "test-secret-that-is-at-least-32-characters-long")
		setEnvForTest(t, "IDENTREE_LDAP_BASE_DN", "dc=test,dc=com")

		cfg, err := LoadServerConfig()
		if err != nil {
			t.Fatalf("LoadServerConfig: %v", err)
		}
		if cfg.RedisURL != "redis://myhost:6379/2" {
			t.Errorf("RedisURL = %q, want %q", cfg.RedisURL, "redis://myhost:6379/2")
		}
	})
}
