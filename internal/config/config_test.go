package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// ── Helper: set minimum viable env for LoadServerConfig ──────────────────────

// setMinServerEnv sets the minimum required env vars for LoadServerConfig to succeed.
func setMinServerEnv(t *testing.T) {
	t.Helper()
	setEnvForTest(t, "IDENTREE_OIDC_ISSUER_URL", "http://localhost:1411")
	setEnvForTest(t, "IDENTREE_OIDC_CLIENT_ID", "test-client")
	setEnvForTest(t, "IDENTREE_OIDC_CLIENT_SECRET", "test-secret")
	setEnvForTest(t, "IDENTREE_EXTERNAL_URL", "http://localhost:8090")
	setEnvForTest(t, "IDENTREE_SHARED_SECRET", "test-secret-that-is-at-least-32-characters-long")
	setEnvForTest(t, "IDENTREE_LDAP_BASE_DN", "dc=test,dc=com")
	// Point TOML config to nonexistent path to avoid reading real config.
	setEnvForTest(t, "IDENTREE_TOML_CONFIG_FILE", filepath.Join(t.TempDir(), "nonexistent.toml"))
}

// ── LoadServerConfig: minimum viable config ──────────────────────────────────

func TestLoadServerConfig_MinimumViable(t *testing.T) {
	setMinServerEnv(t)

	cfg, err := LoadServerConfig()
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}

	// Verify defaults
	if cfg.ListenAddr != ":8090" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":8090")
	}
	if cfg.ChallengeTTL != 120*time.Second {
		t.Errorf("ChallengeTTL = %v, want %v", cfg.ChallengeTTL, 120*time.Second)
	}
	if cfg.GracePeriod != 0 {
		t.Errorf("GracePeriod = %v, want 0", cfg.GracePeriod)
	}
	if cfg.OneTapMaxAge != 24*time.Hour {
		t.Errorf("OneTapMaxAge = %v, want %v", cfg.OneTapMaxAge, 24*time.Hour)
	}
	if cfg.LDAPEnabled != true {
		t.Error("expected LDAPEnabled = true by default")
	}
	if cfg.LDAPListenAddr != ":389" {
		t.Errorf("LDAPListenAddr = %q, want %q", cfg.LDAPListenAddr, ":389")
	}
	if cfg.LDAPRefreshInterval != 300*time.Second {
		t.Errorf("LDAPRefreshInterval = %v, want %v", cfg.LDAPRefreshInterval, 300*time.Second)
	}
	if cfg.LDAPUIDBase != 200000 {
		t.Errorf("LDAPUIDBase = %d, want 200000", cfg.LDAPUIDBase)
	}
	if cfg.LDAPGIDBase != 200000 {
		t.Errorf("LDAPGIDBase = %d, want 200000", cfg.LDAPGIDBase)
	}
	if cfg.LDAPDefaultShell != "/bin/bash" {
		t.Errorf("LDAPDefaultShell = %q, want %q", cfg.LDAPDefaultShell, "/bin/bash")
	}
	if cfg.LDAPDefaultHome != "/home/%s" {
		t.Errorf("LDAPDefaultHome = %q, want %q", cfg.LDAPDefaultHome, "/home/%s")
	}
	if cfg.AuditBufferSize != 4096 {
		t.Errorf("AuditBufferSize = %d, want 4096", cfg.AuditBufferSize)
	}
	if cfg.AuditLogMaxSize != 100*1024*1024 {
		t.Errorf("AuditLogMaxSize = %d, want %d", cfg.AuditLogMaxSize, 100*1024*1024)
	}
	if cfg.DefaultPageSize != 15 {
		t.Errorf("DefaultPageSize = %d, want 15", cfg.DefaultPageSize)
	}
	if cfg.StateBackend != "local" {
		t.Errorf("StateBackend = %q, want %q", cfg.StateBackend, "local")
	}
	if cfg.RedisKeyPrefix != "identree:" {
		t.Errorf("RedisKeyPrefix = %q, want %q", cfg.RedisKeyPrefix, "identree:")
	}
	if cfg.AuthProtocol != "oidc" {
		t.Errorf("AuthProtocol = %q, want %q", cfg.AuthProtocol, "oidc")
	}
	if cfg.NotifyTimeout != 15*time.Second {
		t.Errorf("NotifyTimeout = %v, want %v", cfg.NotifyTimeout, 15*time.Second)
	}
	// APIURL defaults to IssuerURL
	if cfg.APIURL != "http://localhost:1411" {
		t.Errorf("APIURL = %q, want IssuerURL default", cfg.APIURL)
	}
	// InstallURL defaults to ExternalURL
	if cfg.InstallURL != "http://localhost:8090" {
		t.Errorf("InstallURL = %q, want ExternalURL default", cfg.InstallURL)
	}
}

// ── SAML mode ────────────────────────────────────────────────────────────────

func TestLoadServerConfig_SAMLMode(t *testing.T) {
	setMinServerEnv(t)
	setEnvForTest(t, "IDENTREE_AUTH_PROTOCOL", "saml")
	setEnvForTest(t, "IDENTREE_SAML_IDP_METADATA_URL", "https://idp.example.com/metadata")
	// Clear OIDC fields — they should not be required in SAML mode.
	clearEnvForTest(t, "IDENTREE_OIDC_ISSUER_URL")
	clearEnvForTest(t, "IDENTREE_OIDC_CLIENT_ID")
	clearEnvForTest(t, "IDENTREE_OIDC_CLIENT_SECRET")

	cfg, err := LoadServerConfig()
	if err != nil {
		t.Fatalf("LoadServerConfig (SAML): %v", err)
	}
	if cfg.AuthProtocol != "saml" {
		t.Errorf("AuthProtocol = %q, want %q", cfg.AuthProtocol, "saml")
	}
	if cfg.SAMLIdPMetadataURL != "https://idp.example.com/metadata" {
		t.Errorf("SAMLIdPMetadataURL = %q", cfg.SAMLIdPMetadataURL)
	}
	// SAMLEntityID defaults to ExternalURL
	if cfg.SAMLEntityID != "http://localhost:8090" {
		t.Errorf("SAMLEntityID = %q, want ExternalURL", cfg.SAMLEntityID)
	}
}

func TestLoadServerConfig_SAMLMode_MissingMetadata(t *testing.T) {
	setMinServerEnv(t)
	setEnvForTest(t, "IDENTREE_AUTH_PROTOCOL", "saml")
	clearEnvForTest(t, "IDENTREE_SAML_IDP_METADATA_URL")
	clearEnvForTest(t, "IDENTREE_SAML_IDP_METADATA")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for SAML without metadata")
	}
	if !strings.Contains(err.Error(), "SAML") {
		t.Errorf("error should mention SAML: %v", err)
	}
}

// ── mTLS mode: SharedSecret not required ─────────────────────────────────────

func TestLoadServerConfig_MTLSMode(t *testing.T) {
	setMinServerEnv(t)
	clearEnvForTest(t, "IDENTREE_SHARED_SECRET")
	setEnvForTest(t, "IDENTREE_MTLS_CA_CERT", "/tmp/ca.crt")
	setEnvForTest(t, "IDENTREE_MTLS_CA_KEY", "/tmp/ca.key")

	cfg, err := LoadServerConfig()
	if err != nil {
		t.Fatalf("LoadServerConfig (mTLS): %v", err)
	}
	if !cfg.MTLSEnabled {
		t.Error("expected MTLSEnabled = true")
	}
	if cfg.SharedSecret != "" {
		t.Errorf("SharedSecret should be empty in mTLS mode, got %q", cfg.SharedSecret)
	}
}

// ── Split secret fallback ────────────────────────────────────────────────────

func TestLoadServerConfig_SecretFallback(t *testing.T) {
	setMinServerEnv(t)
	clearEnvForTest(t, "IDENTREE_SESSION_SECRET")
	clearEnvForTest(t, "IDENTREE_ESCROW_SECRET")
	clearEnvForTest(t, "IDENTREE_LDAP_SECRET")

	cfg, err := LoadServerConfig()
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}

	shared := cfg.SharedSecret
	if cfg.SessionSecret != shared {
		t.Errorf("SessionSecret = %q, want SharedSecret fallback %q", cfg.SessionSecret, shared)
	}
	if cfg.EscrowSecret != shared {
		t.Errorf("EscrowSecret = %q, want SharedSecret fallback %q", cfg.EscrowSecret, shared)
	}
	if cfg.LDAPSecret != shared {
		t.Errorf("LDAPSecret = %q, want SharedSecret fallback %q", cfg.LDAPSecret, shared)
	}
}

// ── Split secret independence ────────────────────────────────────────────────

func TestLoadServerConfig_SecretIndependence(t *testing.T) {
	setMinServerEnv(t)
	setEnvForTest(t, "IDENTREE_SESSION_SECRET", "session-secret-that-is-32-characters-plus")
	setEnvForTest(t, "IDENTREE_ESCROW_SECRET", "escrow-secret-that-is-32-characters-plus")
	setEnvForTest(t, "IDENTREE_LDAP_SECRET", "ldap-secret-that-is-32-characters-plus!!")

	cfg, err := LoadServerConfig()
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}

	if cfg.SessionSecret == cfg.SharedSecret {
		t.Error("SessionSecret should not equal SharedSecret when explicitly set")
	}
	if cfg.EscrowSecret == cfg.SharedSecret {
		t.Error("EscrowSecret should not equal SharedSecret when explicitly set")
	}
	if cfg.LDAPSecret == cfg.SharedSecret {
		t.Error("LDAPSecret should not equal SharedSecret when explicitly set")
	}
	if cfg.SessionSecret == cfg.EscrowSecret {
		t.Error("SessionSecret should not equal EscrowSecret")
	}
}

// ── Validation: missing required fields ──────────────────────────────────────

func TestLoadServerConfig_MissingIssuerURL(t *testing.T) {
	setMinServerEnv(t)
	clearEnvForTest(t, "IDENTREE_OIDC_ISSUER_URL")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for missing OIDC issuer URL")
	}
	if !strings.Contains(err.Error(), "IDENTREE_OIDC_ISSUER_URL") {
		t.Errorf("error should mention IDENTREE_OIDC_ISSUER_URL: %v", err)
	}
}

func TestLoadServerConfig_MissingClientID(t *testing.T) {
	setMinServerEnv(t)
	clearEnvForTest(t, "IDENTREE_OIDC_CLIENT_ID")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for missing OIDC client ID")
	}
}

func TestLoadServerConfig_MissingSharedSecret(t *testing.T) {
	setMinServerEnv(t)
	clearEnvForTest(t, "IDENTREE_SHARED_SECRET")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for missing shared secret")
	}
	if !strings.Contains(err.Error(), "SHARED_SECRET") {
		t.Errorf("error should mention SHARED_SECRET: %v", err)
	}
}

func TestLoadServerConfig_ShortSharedSecret(t *testing.T) {
	setMinServerEnv(t)
	setEnvForTest(t, "IDENTREE_SHARED_SECRET", "tooshort")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for short shared secret")
	}
	if !strings.Contains(err.Error(), "32 characters") {
		t.Errorf("error should mention 32 characters: %v", err)
	}
}

func TestLoadServerConfig_MissingExternalURL(t *testing.T) {
	setMinServerEnv(t)
	clearEnvForTest(t, "IDENTREE_EXTERNAL_URL")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for missing external URL")
	}
}

func TestLoadServerConfig_InvalidExternalURL(t *testing.T) {
	setMinServerEnv(t)
	setEnvForTest(t, "IDENTREE_EXTERNAL_URL", "not-a-url")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for invalid external URL")
	}
}

func TestLoadServerConfig_MissingLDAPBaseDN(t *testing.T) {
	setMinServerEnv(t)
	clearEnvForTest(t, "IDENTREE_LDAP_BASE_DN")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for missing LDAP base DN when LDAP enabled")
	}
}

func TestLoadServerConfig_InvalidAuthProtocol(t *testing.T) {
	setMinServerEnv(t)
	setEnvForTest(t, "IDENTREE_AUTH_PROTOCOL", "kerberos")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for invalid auth protocol")
	}
}

func TestLoadServerConfig_InvalidStateBackend(t *testing.T) {
	setMinServerEnv(t)
	setEnvForTest(t, "IDENTREE_STATE_BACKEND", "postgres")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for invalid state backend")
	}
}

func TestLoadServerConfig_RedisWithoutURL(t *testing.T) {
	setMinServerEnv(t)
	setEnvForTest(t, "IDENTREE_STATE_BACKEND", "redis")
	clearEnvForTest(t, "IDENTREE_REDIS_URL")
	clearEnvForTest(t, "IDENTREE_REDIS_CLUSTER_ADDRS")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for redis backend without URL")
	}
}

func TestLoadServerConfig_LocalEscrowWithoutKey(t *testing.T) {
	setMinServerEnv(t)
	setEnvForTest(t, "IDENTREE_ESCROW_BACKEND", "local")
	clearEnvForTest(t, "IDENTREE_ESCROW_ENCRYPTION_KEY")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for local escrow without encryption key")
	}
}

func TestLoadServerConfig_EscrowCommandAndBackendConflict(t *testing.T) {
	setMinServerEnv(t)
	setEnvForTest(t, "IDENTREE_ESCROW_COMMAND", "/usr/bin/escrow")
	setEnvForTest(t, "IDENTREE_ESCROW_BACKEND", "vault")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for escrow command + backend conflict")
	}
}

func TestLoadServerConfig_InvalidLDAPDefaultShell(t *testing.T) {
	setMinServerEnv(t)
	setEnvForTest(t, "IDENTREE_LDAP_DEFAULT_SHELL", "relative/path")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for non-absolute LDAP default shell")
	}
}

func TestLoadServerConfig_ShellWithMetachars(t *testing.T) {
	setMinServerEnv(t)
	setEnvForTest(t, "IDENTREE_LDAP_DEFAULT_SHELL", "/bin/bash; rm -rf /")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for shell with metacharacters")
	}
}

func TestLoadServerConfig_HalfConfiguredLDAPBind(t *testing.T) {
	setMinServerEnv(t)
	setEnvForTest(t, "IDENTREE_LDAP_BIND_DN", "cn=admin,dc=test,dc=com")
	clearEnvForTest(t, "IDENTREE_LDAP_BIND_PASSWORD")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for bind DN without password")
	}
}

func TestLoadServerConfig_DevLoginWithHTTPS(t *testing.T) {
	setMinServerEnv(t)
	setEnvForTest(t, "IDENTREE_DEV_LOGIN", "true")
	setEnvForTest(t, "IDENTREE_EXTERNAL_URL", "https://prod.example.com")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for dev login with HTTPS external URL")
	}
}

// ── LoadTOMLConfig ───────────────────────────────────────────────────────────

func TestLoadTOMLConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `[oidc]
issuer_url = "http://localhost:1411"
client_id = "my-client"

[server]
listen_addr = ":9090"
external_url = "http://myhost:9090"

[auth]
challenge_ttl = "300s"
justification_choices = ["Routine maintenance", "Incident response"]
require_justification = true

[ldap]
enabled = true
base_dn = "dc=example,dc=com"
uid_base = 300000
`
	os.WriteFile(path, []byte(content), 0600)

	m, err := LoadTOMLConfig(path)
	if err != nil {
		t.Fatalf("LoadTOMLConfig: %v", err)
	}

	if m["IDENTREE_OIDC_ISSUER_URL"] != "http://localhost:1411" {
		t.Errorf("issuer_url = %q", m["IDENTREE_OIDC_ISSUER_URL"])
	}
	if m["IDENTREE_OIDC_CLIENT_ID"] != "my-client" {
		t.Errorf("client_id = %q", m["IDENTREE_OIDC_CLIENT_ID"])
	}
	if m["IDENTREE_LISTEN_ADDR"] != ":9090" {
		t.Errorf("listen_addr = %q", m["IDENTREE_LISTEN_ADDR"])
	}
	if m["IDENTREE_CHALLENGE_TTL"] != "300s" {
		t.Errorf("challenge_ttl = %q", m["IDENTREE_CHALLENGE_TTL"])
	}
	if m["IDENTREE_JUSTIFICATION_CHOICES"] != "Routine maintenance,Incident response" {
		t.Errorf("justification_choices = %q", m["IDENTREE_JUSTIFICATION_CHOICES"])
	}
	if m["IDENTREE_REQUIRE_JUSTIFICATION"] != "true" {
		t.Errorf("require_justification = %q", m["IDENTREE_REQUIRE_JUSTIFICATION"])
	}
	if m["IDENTREE_LDAP_ENABLED"] != "true" {
		t.Errorf("ldap enabled = %q", m["IDENTREE_LDAP_ENABLED"])
	}
	if m["IDENTREE_LDAP_BASE_DN"] != "dc=example,dc=com" {
		t.Errorf("base_dn = %q", m["IDENTREE_LDAP_BASE_DN"])
	}
	if m["IDENTREE_LDAP_UID_BASE"] != "300000" {
		t.Errorf("uid_base = %q", m["IDENTREE_LDAP_UID_BASE"])
	}
}

func TestLoadTOMLConfig_InlineComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `[server]
listen_addr = ":8080" # the listen address
external_url = "http://localhost:8080" # must be reachable

[ldap] # LDAP settings
enabled = true # turn it on
`
	os.WriteFile(path, []byte(content), 0600)

	m, err := LoadTOMLConfig(path)
	if err != nil {
		t.Fatalf("LoadTOMLConfig: %v", err)
	}
	if m["IDENTREE_LISTEN_ADDR"] != ":8080" {
		t.Errorf("listen_addr = %q, want %q (inline comment not stripped?)", m["IDENTREE_LISTEN_ADDR"], ":8080")
	}
	if m["IDENTREE_EXTERNAL_URL"] != "http://localhost:8080" {
		t.Errorf("external_url = %q", m["IDENTREE_EXTERNAL_URL"])
	}
	if m["IDENTREE_LDAP_ENABLED"] != "true" {
		t.Errorf("ldap enabled = %q", m["IDENTREE_LDAP_ENABLED"])
	}
}

func TestLoadTOMLConfig_NonexistentFile(t *testing.T) {
	_, err := LoadTOMLConfig("/tmp/nonexistent-file-12345.toml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected os.ErrNotExist, got: %v", err)
	}
}

// ── SaveTOMLConfig + round-trip ──────────────────────────────────────────────

func TestSaveTOMLConfig_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	input := map[string]string{
		"IDENTREE_OIDC_ISSUER_URL":        "http://localhost:1411",
		"IDENTREE_OIDC_CLIENT_ID":         "my-client",
		"IDENTREE_LISTEN_ADDR":            ":9090",
		"IDENTREE_ADMIN_GROUPS":           "admins,ops",
		"IDENTREE_JUSTIFICATION_CHOICES":  "Routine,Incident",
		"IDENTREE_LDAP_ENABLED":           "true",
		"IDENTREE_LDAP_UID_BASE":          "300000",
	}

	err := SaveTOMLConfig(path, input)
	if err != nil {
		t.Fatalf("SaveTOMLConfig: %v", err)
	}

	// Reload and verify round-trip
	got, err := LoadTOMLConfig(path)
	if err != nil {
		t.Fatalf("LoadTOMLConfig after save: %v", err)
	}

	for key, want := range input {
		if got[key] != want {
			t.Errorf("round-trip %s: got %q, want %q", key, got[key], want)
		}
	}
}

func TestSaveTOMLConfig_EscapedStrings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	input := map[string]string{
		"IDENTREE_EXTERNAL_URL": `http://host:8090`,
		"IDENTREE_LDAP_BASE_DN": `dc=example,dc=com`,
	}

	if err := SaveTOMLConfig(path, input); err != nil {
		t.Fatalf("SaveTOMLConfig: %v", err)
	}

	got, err := LoadTOMLConfig(path)
	if err != nil {
		t.Fatalf("LoadTOMLConfig: %v", err)
	}

	if got["IDENTREE_EXTERNAL_URL"] != input["IDENTREE_EXTERNAL_URL"] {
		t.Errorf("ExternalURL = %q, want %q", got["IDENTREE_EXTERNAL_URL"], input["IDENTREE_EXTERNAL_URL"])
	}
	if got["IDENTREE_LDAP_BASE_DN"] != input["IDENTREE_LDAP_BASE_DN"] {
		t.Errorf("BaseDN = %q, want %q", got["IDENTREE_LDAP_BASE_DN"], input["IDENTREE_LDAP_BASE_DN"])
	}
}

// ── parseTOMLValue edge cases ────────────────────────────────────────────────

func TestParseTOMLValue(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		isList bool
		want   string
	}{
		{"empty string", `""`, false, ""},
		{"simple quoted", `"hello"`, false, "hello"},
		{"unquoted", "42", false, "42"},
		{"boolean true", "true", false, "true"},
		{"escaped newline", `"line1\nline2"`, false, "line1\nline2"},
		{"escaped tab", `"col1\tcol2"`, false, "col1\tcol2"},
		{"escaped backslash", `"path\\to\\file"`, false, `path\to\file`},
		{"escaped quote", `"say \"hello\""`, false, `say "hello"`},
		{"empty list", "[]", true, ""},
		{"single item list", `["one"]`, true, "one"},
		{"multi item list", `["a", "b", "c"]`, true, "a,b,c"},
		{"list with single quotes", `['a', 'b']`, true, "a,b"},
		{"list with spaces in items", `["admin, ops", "users"]`, true, "admin, ops,users"},
		{"non-list raw", "rawvalue", false, "rawvalue"},
		{"list not array", "notanarray", true, "notanarray"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTOMLValue(tt.raw, tt.isList)
			if got != tt.want {
				t.Errorf("parseTOMLValue(%q, %v) = %q, want %q", tt.raw, tt.isList, got, tt.want)
			}
		})
	}
}

// ── LoadClientConfig ─────────────────────────────────────────────────────────

func TestLoadClientConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.conf")
	content := `IDENTREE_SERVER_URL=http://localhost:8090
IDENTREE_SHARED_SECRET=my-shared-secret
IDENTREE_POLL_INTERVAL=5s
IDENTREE_TIMEOUT=60s
IDENTREE_BREAKGLASS_ENABLED=true
IDENTREE_BREAKGLASS_ROTATION_DAYS=30
IDENTREE_BREAKGLASS_PASSWORD_TYPE=passphrase
`
	os.WriteFile(path, []byte(content), 0600)

	// Override the default client config path by setting env vars directly.
	// LoadClientConfig reads from DefaultClientConfigPath which we can't easily override,
	// so we set env vars which take precedence.
	setEnvForTest(t, "IDENTREE_SERVER_URL", "http://localhost:8090")
	setEnvForTest(t, "IDENTREE_SHARED_SECRET", "my-shared-secret")
	setEnvForTest(t, "IDENTREE_POLL_INTERVAL", "5s")
	setEnvForTest(t, "IDENTREE_TIMEOUT", "60s")
	setEnvForTest(t, "IDENTREE_BREAKGLASS_ENABLED", "true")
	setEnvForTest(t, "IDENTREE_BREAKGLASS_ROTATION_DAYS", "30")
	setEnvForTest(t, "IDENTREE_BREAKGLASS_PASSWORD_TYPE", "passphrase")

	cfg, err := LoadClientConfig(false)
	if err != nil {
		t.Fatalf("LoadClientConfig: %v", err)
	}

	if cfg.ServerURL != "http://localhost:8090" {
		t.Errorf("ServerURL = %q", cfg.ServerURL)
	}
	if cfg.SharedSecret != "my-shared-secret" {
		t.Errorf("SharedSecret = %q", cfg.SharedSecret)
	}
	if cfg.PollInterval != 5*time.Second {
		t.Errorf("PollInterval = %v, want 5s", cfg.PollInterval)
	}
	if cfg.Timeout != 60*time.Second {
		t.Errorf("Timeout = %v, want 60s", cfg.Timeout)
	}
	if !cfg.BreakglassEnabled {
		t.Error("expected BreakglassEnabled = true")
	}
	if cfg.BreakglassRotationDays != 30 {
		t.Errorf("BreakglassRotationDays = %d, want 30", cfg.BreakglassRotationDays)
	}
	if cfg.BreakglassPasswordType != "passphrase" {
		t.Errorf("BreakglassPasswordType = %q, want %q", cfg.BreakglassPasswordType, "passphrase")
	}
}

func TestLoadClientConfig_Defaults(t *testing.T) {
	setEnvForTest(t, "IDENTREE_SERVER_URL", "http://localhost:8090")
	clearEnvForTest(t, "IDENTREE_SHARED_SECRET")
	clearEnvForTest(t, "IDENTREE_POLL_INTERVAL")
	clearEnvForTest(t, "IDENTREE_TIMEOUT")
	clearEnvForTest(t, "IDENTREE_BREAKGLASS_ENABLED")
	clearEnvForTest(t, "IDENTREE_BREAKGLASS_ROTATION_DAYS")
	clearEnvForTest(t, "IDENTREE_BREAKGLASS_PASSWORD_TYPE")
	clearEnvForTest(t, "IDENTREE_BREAKGLASS_BCRYPT_COST")
	clearEnvForTest(t, "IDENTREE_TOKEN_CACHE_ENABLED")

	cfg, err := LoadClientConfig(false)
	if err != nil {
		t.Fatalf("LoadClientConfig: %v", err)
	}
	if cfg.PollInterval != 2*time.Second {
		t.Errorf("PollInterval default = %v, want 2s", cfg.PollInterval)
	}
	if cfg.Timeout != 120*time.Second {
		t.Errorf("Timeout default = %v, want 120s", cfg.Timeout)
	}
	if !cfg.BreakglassEnabled {
		t.Error("BreakglassEnabled default should be true")
	}
	if cfg.BreakglassRotationDays != 90 {
		t.Errorf("BreakglassRotationDays default = %d, want 90", cfg.BreakglassRotationDays)
	}
	if cfg.BreakglassPasswordType != "random" {
		t.Errorf("BreakglassPasswordType default = %q, want %q", cfg.BreakglassPasswordType, "random")
	}
	if cfg.BreakglassBcryptCost != 12 {
		t.Errorf("BreakglassBcryptCost default = %d, want 12", cfg.BreakglassBcryptCost)
	}
	if !cfg.TokenCacheEnabled {
		t.Error("TokenCacheEnabled default should be true")
	}
}

func TestLoadClientConfig_MissingServerURL(t *testing.T) {
	clearEnvForTest(t, "IDENTREE_SERVER_URL")

	_, err := LoadClientConfig(false)
	if err == nil {
		t.Fatal("expected error for missing server URL")
	}
}

func TestLoadClientConfig_AllowNoServer(t *testing.T) {
	clearEnvForTest(t, "IDENTREE_SERVER_URL")

	cfg, err := LoadClientConfig(true)
	if err != nil {
		t.Fatalf("LoadClientConfig(allowNoServer=true): %v", err)
	}
	if cfg.ServerURL != "" {
		t.Errorf("expected empty ServerURL, got %q", cfg.ServerURL)
	}
}

func TestLoadClientConfig_InvalidServerURL(t *testing.T) {
	setEnvForTest(t, "IDENTREE_SERVER_URL", "ftp://bad-scheme")

	_, err := LoadClientConfig(false)
	if err == nil {
		t.Fatal("expected error for non-http(s) server URL")
	}
}

// ── loadConfigFile ───────────────────────────────────────────────────────────

func TestLoadConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identree.conf")
	content := `# comment line
IDENTREE_OIDC_ISSUER_URL=http://localhost:1411
IDENTREE_OIDC_CLIENT_ID="my-client"
export IDENTREE_OIDC_CLIENT_SECRET='my-secret'

IDENTREE_EXTERNAL_URL=http://localhost:8090
`
	os.WriteFile(path, []byte(content), 0600)

	m, err := loadConfigFile(path)
	if err != nil {
		t.Fatalf("loadConfigFile: %v", err)
	}
	if m["IDENTREE_OIDC_ISSUER_URL"] != "http://localhost:1411" {
		t.Errorf("ISSUER_URL = %q", m["IDENTREE_OIDC_ISSUER_URL"])
	}
	if m["IDENTREE_OIDC_CLIENT_ID"] != "my-client" {
		t.Errorf("CLIENT_ID = %q (quotes not stripped?)", m["IDENTREE_OIDC_CLIENT_ID"])
	}
	if m["IDENTREE_OIDC_CLIENT_SECRET"] != "my-secret" {
		t.Errorf("CLIENT_SECRET = %q (export prefix or quotes not stripped?)", m["IDENTREE_OIDC_CLIENT_SECRET"])
	}
}

// ── TOMLConfigPath ───────────────────────────────────────────────────────────

func TestTOMLConfigPath_Default(t *testing.T) {
	clearEnvForTest(t, "IDENTREE_TOML_CONFIG_FILE")
	if got := TOMLConfigPath(); got != DefaultTOMLConfigPath {
		t.Errorf("TOMLConfigPath() = %q, want %q", got, DefaultTOMLConfigPath)
	}
}

func TestTOMLConfigPath_Override(t *testing.T) {
	setEnvForTest(t, "IDENTREE_TOML_CONFIG_FILE", "/custom/path.toml")
	if got := TOMLConfigPath(); got != "/custom/path.toml" {
		t.Errorf("TOMLConfigPath() = %q, want %q", got, "/custom/path.toml")
	}
}

// ── stringDefault ────────────────────────────────────────────────────────────

func TestStringDefault(t *testing.T) {
	if got := stringDefault("", "default"); got != "default" {
		t.Errorf("stringDefault(\"\", \"default\") = %q", got)
	}
	if got := stringDefault("value", "default"); got != "value" {
		t.Errorf("stringDefault(\"value\", \"default\") = %q", got)
	}
}

// ── formatTOMLScalar ─────────────────────────────────────────────────────────

func TestFormatTOMLScalar(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"true", "true"},
		{"false", "false"},
		{"42", "42"},
		{"0", "0"},
		{"hello", `"hello"`},
		{":8090", `":8090"`},
		{"dc=example,dc=com", `"dc=example,dc=com"`},
	}
	for _, tt := range tests {
		got := formatTOMLScalar(tt.input)
		if got != tt.want {
			t.Errorf("formatTOMLScalar(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── tomlEscapeString ─────────────────────────────────────────────────────────

func TestTomlEscapeString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{`path\to\file`, `path\\to\\file`},
		{`say "hi"`, `say \"hi\"`},
		{"line1\nline2", `line1\nline2`},
		{"col1\tcol2", `col1\tcol2`},
		{"a\rb", `a\rb`},
	}
	for _, tt := range tests {
		got := tomlEscapeString(tt.input)
		if got != tt.want {
			t.Errorf("tomlEscapeString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── IsEnvSourced ─────────────────────────────────────────────────────────────

func TestIsEnvSourced(t *testing.T) {
	setEnvForTest(t, "IDENTREE_TEST_PRESENT", "yes")
	clearEnvForTest(t, "IDENTREE_TEST_ABSENT")

	if !IsEnvSourced("IDENTREE_TEST_PRESENT") {
		t.Error("expected IsEnvSourced to return true for present env var")
	}
	if IsEnvSourced("IDENTREE_TEST_ABSENT") {
		t.Error("expected IsEnvSourced to return false for absent env var")
	}
}

// ── LoadServerConfig from TOML file ──────────────────────────────────────────

func TestLoadServerConfig_FromTOML(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "config.toml")
	content := `[oidc]
issuer_url = "http://localhost:1411"
client_id = "toml-client"

[server]
listen_addr = ":7070"
external_url = "http://localhost:7070"

[ldap]
base_dn = "dc=toml,dc=com"
`
	os.WriteFile(tomlPath, []byte(content), 0600)

	setEnvForTest(t, "IDENTREE_TOML_CONFIG_FILE", tomlPath)
	// Set secrets via env (they can't be in TOML)
	setEnvForTest(t, "IDENTREE_OIDC_CLIENT_SECRET", "test-secret")
	setEnvForTest(t, "IDENTREE_SHARED_SECRET", "test-secret-that-is-at-least-32-characters-long")
	// Clear env vars that TOML should provide
	clearEnvForTest(t, "IDENTREE_OIDC_ISSUER_URL")
	clearEnvForTest(t, "IDENTREE_OIDC_CLIENT_ID")
	clearEnvForTest(t, "IDENTREE_EXTERNAL_URL")
	clearEnvForTest(t, "IDENTREE_LISTEN_ADDR")
	clearEnvForTest(t, "IDENTREE_LDAP_BASE_DN")

	cfg, err := LoadServerConfig()
	if err != nil {
		t.Fatalf("LoadServerConfig from TOML: %v", err)
	}
	if cfg.IssuerURL != "http://localhost:1411" {
		t.Errorf("IssuerURL = %q, want value from TOML", cfg.IssuerURL)
	}
	if cfg.ClientID != "toml-client" {
		t.Errorf("ClientID = %q, want value from TOML", cfg.ClientID)
	}
	if cfg.ListenAddr != ":7070" {
		t.Errorf("ListenAddr = %q, want value from TOML", cfg.ListenAddr)
	}
}

// ── ExternalURL with special chars ───────────────────────────────────────────

func TestLoadServerConfig_ExternalURLWithQuotes(t *testing.T) {
	setMinServerEnv(t)
	setEnvForTest(t, "IDENTREE_EXTERNAL_URL", `http://example.com"`)

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for external URL with quotes")
	}
}

// ── Webhook secret validation ────────────────────────────────────────────────

func TestLoadServerConfig_ShortWebhookSecret(t *testing.T) {
	setMinServerEnv(t)
	setEnvForTest(t, "IDENTREE_WEBHOOK_SECRET", "tooshort")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for short webhook secret")
	}
}

// ── LDAPDefaultHome pattern validation ───────────────────────────────────────

func TestLoadServerConfig_InvalidHomePattern(t *testing.T) {
	setMinServerEnv(t)
	setEnvForTest(t, "IDENTREE_LDAP_DEFAULT_HOME", "/home/%d/data")

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatal("expected error for invalid home pattern with percent-d")
	}
}
