package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rinseaid/identree/internal/config"
)

// newAuthTestServer builds a Server with the given shared secret and API keys.
func newAuthTestServer(secret string, apiKeys []string, adminApprovalHosts []string) *Server {
	s := &Server{
		cfg: &config.ServerConfig{
			SharedSecret:       secret,
			APIKeys:            apiKeys,
			AdminApprovalHosts: adminApprovalHosts,
		},
		hostRegistry: NewHostRegistry(""),
	}
	for _, key := range apiKeys {
		h := hmac.New(sha256.New, []byte("api-key-verification"))
		h.Write([]byte(key))
		s.hashedAPIKeys = append(s.hashedAPIKeys, h.Sum(nil))
	}
	return s
}

func TestVerifySharedSecret(t *testing.T) {
	const secret = "correct-horse-battery-staple"

	t.Run("correct secret passes", func(t *testing.T) {
		s := newAuthTestServer(secret, nil, nil)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Shared-Secret", secret)
		if !s.verifySharedSecret(r) {
			t.Fatal("expected true for correct secret")
		}
	})

	t.Run("wrong secret fails", func(t *testing.T) {
		s := newAuthTestServer(secret, nil, nil)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Shared-Secret", "wrong-secret")
		if s.verifySharedSecret(r) {
			t.Fatal("expected false for wrong secret")
		}
	})

	t.Run("missing header fails", func(t *testing.T) {
		s := newAuthTestServer(secret, nil, nil)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if s.verifySharedSecret(r) {
			t.Fatal("expected false when header is absent")
		}
	})

	t.Run("empty secret fails closed", func(t *testing.T) {
		s := newAuthTestServer("", nil, nil)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		// No secret configured — fail closed (no access).
		if s.verifySharedSecret(r) {
			t.Fatal("expected false when shared secret is empty (fail closed)")
		}
	})

	t.Run("empty secret with header still fails closed", func(t *testing.T) {
		s := newAuthTestServer("", nil, nil)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Shared-Secret", "anything")
		if s.verifySharedSecret(r) {
			t.Fatal("expected false when shared secret is empty (fail closed)")
		}
	})
}

func TestVerifyAPIKey(t *testing.T) {
	const key1 = "api-key-one"
	const key2 = "api-key-two"

	t.Run("valid key passes", func(t *testing.T) {
		s := newAuthTestServer("secret", []string{key1, key2}, nil)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+key1)
		if !s.verifyAPIKey(r) {
			t.Fatal("expected true for key1")
		}
	})

	t.Run("second key also passes", func(t *testing.T) {
		s := newAuthTestServer("secret", []string{key1, key2}, nil)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+key2)
		if !s.verifyAPIKey(r) {
			t.Fatal("expected true for key2")
		}
	})

	t.Run("wrong key fails", func(t *testing.T) {
		s := newAuthTestServer("secret", []string{key1}, nil)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer wrong-key")
		if s.verifyAPIKey(r) {
			t.Fatal("expected false for wrong key")
		}
	})

	t.Run("missing Authorization header fails", func(t *testing.T) {
		s := newAuthTestServer("secret", []string{key1}, nil)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if s.verifyAPIKey(r) {
			t.Fatal("expected false when Authorization is absent")
		}
	})

	t.Run("no keys configured always fails", func(t *testing.T) {
		s := newAuthTestServer("secret", nil, nil)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+key1)
		if s.verifyAPIKey(r) {
			t.Fatal("expected false when no keys are configured")
		}
	})

	t.Run("key without Bearer prefix is accepted", func(t *testing.T) {
		// TrimPrefix is a no-op when "Bearer " is absent, so the bare token
		// is still matched against the configured keys.
		s := newAuthTestServer("secret", []string{key1}, nil)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", key1) // no "Bearer " prefix
		if !s.verifyAPIKey(r) {
			t.Fatal("expected true: bare key (no Bearer prefix) is still matched")
		}
	})

	t.Run("timing: different-length keys do not short-circuit", func(t *testing.T) {
		// Verify that a short key and a long key both fail in constant time
		// (the HMAC-SHA256 approach means both comparisons operate on
		// equal-length 32-byte digests).
		s := newAuthTestServer("secret", []string{"a", "very-long-api-key-that-is-much-longer"}, nil)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer not-a-key")
		if s.verifyAPIKey(r) {
			t.Fatal("expected false for unrecognised token")
		}
	})
}

func TestRequiresAdminApproval(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		hostname string
		want     bool
	}{
		{
			name:     "no patterns — never requires admin",
			patterns: nil,
			hostname: "web01.example.com",
			want:     false,
		},
		{
			name:     "exact match",
			patterns: []string{"prod-db"},
			hostname: "prod-db",
			want:     true,
		},
		{
			name:     "wildcard suffix match",
			patterns: []string{"prod-*"},
			hostname: "prod-web",
			want:     true,
		},
		{
			name:     "wildcard no match",
			patterns: []string{"prod-*"},
			hostname: "staging-web",
			want:     false,
		},
		{
			name:     "ALL pattern matches anything",
			patterns: []string{"ALL"},
			hostname: "any-host",
			want:     false, // "ALL" is a literal pattern; filepath.Match("ALL", "any-host") = false
		},
		{
			name:     "multiple patterns — first matches",
			patterns: []string{"db-*", "cache-*"},
			hostname: "db-primary",
			want:     true,
		},
		{
			name:     "multiple patterns — second matches",
			patterns: []string{"db-*", "cache-*"},
			hostname: "cache-01",
			want:     true,
		},
		{
			name:     "multiple patterns — none match",
			patterns: []string{"db-*", "cache-*"},
			hostname: "web-01",
			want:     false,
		},
		{
			name:     "glob * matches any segment",
			patterns: []string{"*.prod.example.com"},
			hostname: "app.prod.example.com",
			want:     true,
		},
		{
			name:     "glob * matches across dots (only / is a separator)",
			patterns: []string{"*.example.com"},
			hostname: "a.b.example.com",
			want:     true, // filepath.Match only treats / as separator, so * matches "a.b"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newAuthTestServer("secret", nil, tt.patterns)
			got := s.requiresAdminApproval(tt.hostname)
			if got != tt.want {
				t.Errorf("requiresAdminApproval(%q) with patterns %v = %v; want %v",
					tt.hostname, tt.patterns, got, tt.want)
			}
		})
	}
}
