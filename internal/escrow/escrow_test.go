package escrow

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/rinseaid/identree/internal/config"
)

// memStorer is a minimal in-memory EscrowStorer for tests.
type memStorer struct {
	data map[string]string
}

func newMemStorer() *memStorer {
	return &memStorer{data: make(map[string]string)}
}

func (s *memStorer) StoreEscrowCiphertext(_ context.Context, hostname, ciphertext string) {
	s.data[hostname] = ciphertext
}

func (s *memStorer) GetEscrowCiphertext(_ context.Context, hostname string) (string, bool) {
	v, ok := s.data[hostname]
	return v, ok
}

// ── DeriveEscrowKey ──────────────────────────────────────────────────────────

func TestDeriveEscrowKey_Deterministic(t *testing.T) {
	salt := []byte("test-salt-1234")
	a, err := DeriveEscrowKey("my-raw-key", salt)
	if err != nil {
		t.Fatalf("DeriveEscrowKey: %v", err)
	}
	b, err := DeriveEscrowKey("my-raw-key", salt)
	if err != nil {
		t.Fatalf("DeriveEscrowKey: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("same inputs produced different keys")
	}
	if len(a) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(a))
	}
}

func TestDeriveEscrowKey_DifferentSalts(t *testing.T) {
	a, err := DeriveEscrowKey("my-raw-key", []byte("salt-A"))
	if err != nil {
		t.Fatalf("DeriveEscrowKey: %v", err)
	}
	b, err := DeriveEscrowKey("my-raw-key", []byte("salt-B"))
	if err != nil {
		t.Fatalf("DeriveEscrowKey: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Errorf("different salts produced identical keys")
	}
}

func TestDeriveEscrowKey_DifferentRawKeys(t *testing.T) {
	salt := []byte("same-salt")
	a, err := DeriveEscrowKey("key-one", salt)
	if err != nil {
		t.Fatalf("DeriveEscrowKey: %v", err)
	}
	b, err := DeriveEscrowKey("key-two", salt)
	if err != nil {
		t.Fatalf("DeriveEscrowKey: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Errorf("different raw keys produced identical keys")
	}
}

func TestDeriveEscrowKey_NilSaltUsesLegacy(t *testing.T) {
	// nil salt and empty salt should both use the legacy static salt.
	a, err := DeriveEscrowKey("my-key", nil)
	if err != nil {
		t.Fatalf("DeriveEscrowKey nil: %v", err)
	}
	b, err := DeriveEscrowKey("my-key", []byte{})
	if err != nil {
		t.Fatalf("DeriveEscrowKey empty: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("nil and empty salt should produce the same key (legacy fallback)")
	}
}

// ── Local Escrow Backend Store/Retrieve round-trip ───────────────────────────

func TestLocalEscrowBackend_RoundTrip(t *testing.T) {
	key, err := DeriveEscrowKey("test-secret", []byte("test-salt"))
	if err != nil {
		t.Fatalf("DeriveEscrowKey: %v", err)
	}
	storer := newMemStorer()
	backend := NewLocalEscrowBackend(key, storer)
	ctx := context.Background()

	hostname := "web1.example.com"
	password := "super-secret-breakglass-pass"

	_, _, err = backend.Store(ctx, hostname, password, "")
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	got, err := backend.Retrieve(ctx, hostname, "", "")
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if got != password {
		t.Errorf("got %q, want %q", got, password)
	}
}

func TestLocalEscrowBackend_HostnameAADBinding(t *testing.T) {
	key, err := DeriveEscrowKey("test-secret", []byte("test-salt"))
	if err != nil {
		t.Fatalf("DeriveEscrowKey: %v", err)
	}
	storer := newMemStorer()
	backend := NewLocalEscrowBackend(key, storer)
	ctx := context.Background()

	_, _, err = backend.Store(ctx, "host-A.example.com", "my-password", "")
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	// Copy the ciphertext from host-A to host-B to simulate replay.
	ct, ok := storer.GetEscrowCiphertext(context.Background(), "host-A.example.com")
	if !ok {
		t.Fatal("expected ciphertext stored for host-A")
	}
	storer.StoreEscrowCiphertext(context.Background(), "host-B.example.com", ct)

	// Retrieve with host-B should fail because AAD won't match.
	_, err = backend.Retrieve(ctx, "host-B.example.com", "", "")
	if err == nil {
		t.Error("expected decryption to fail for wrong hostname AAD, got nil error")
	}
}

func TestLocalEscrowBackend_WrongKey(t *testing.T) {
	key1, err := DeriveEscrowKey("secret-one", []byte("salt"))
	if err != nil {
		t.Fatalf("DeriveEscrowKey: %v", err)
	}
	key2, err := DeriveEscrowKey("secret-two", []byte("salt"))
	if err != nil {
		t.Fatalf("DeriveEscrowKey: %v", err)
	}

	storer := newMemStorer()
	backend1 := NewLocalEscrowBackend(key1, storer)
	backend2 := NewLocalEscrowBackend(key2, storer)
	ctx := context.Background()

	hostname := "host.example.com"
	_, _, err = backend1.Store(ctx, hostname, "my-password", "")
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	_, err = backend2.Retrieve(ctx, hostname, "", "")
	if err == nil {
		t.Error("expected decryption to fail with wrong key, got nil error")
	}
}

func TestLocalEscrowBackend_RetrieveNoEntry(t *testing.T) {
	key, _ := DeriveEscrowKey("key", []byte("salt"))
	storer := newMemStorer()
	backend := NewLocalEscrowBackend(key, storer)

	_, err := backend.Retrieve(context.Background(), "nonexistent.host", "", "")
	if err == nil {
		t.Error("expected error for nonexistent hostname")
	}
}

// ── ResolveEscrowVault ───────────────────────────────────────────────────────

func TestResolveEscrowVault(t *testing.T) {
	tests := []struct {
		name         string
		hostname     string
		vaultMap     map[string]string
		defaultVault string
		want         string
	}{
		{
			name:         "empty map returns default",
			hostname:     "web1.example.com",
			vaultMap:     nil,
			defaultVault: "global-vault",
			want:         "global-vault",
		},
		{
			name:     "exact match",
			hostname: "web1.example.com",
			vaultMap: map[string]string{
				"web1.example.com": "vault-exact",
				"web2.example.com": "vault-other",
			},
			defaultVault: "global",
			want:         "vault-exact",
		},
		{
			name:     "prefix glob",
			hostname: "staging-web1.example.com",
			vaultMap: map[string]string{
				"staging-*": "vault-staging",
			},
			defaultVault: "global",
			want:         "vault-staging",
		},
		{
			name:     "suffix glob",
			hostname: "web1.prod.example.com",
			vaultMap: map[string]string{
				"*.prod.example.com": "vault-prod",
			},
			defaultVault: "global",
			want:         "vault-prod",
		},
		{
			name:     "explicit default key in map",
			hostname: "unknown.host",
			vaultMap: map[string]string{
				"default":    "vault-default-key",
				"other.host": "vault-other",
			},
			defaultVault: "global",
			want:         "vault-default-key",
		},
		{
			name:     "no match falls through to global default",
			hostname: "unknown.host",
			vaultMap: map[string]string{
				"other.host": "vault-other",
			},
			defaultVault: "global",
			want:         "global",
		},
		{
			name:     "longest glob wins",
			hostname: "staging-web1.example.com",
			vaultMap: map[string]string{
				"staging-*":              "vault-short",
				"staging-web1.example.*": "vault-long",
			},
			defaultVault: "global",
			want:         "vault-long",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveEscrowVault(tt.hostname, tt.vaultMap, tt.defaultVault)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// ── ResolveEscrowVault edge cases ────────────────────────────────────────────

func TestResolveEscrowVault_EdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		hostname     string
		vaultMap     map[string]string
		defaultVault string
		want         string
	}{
		{
			name:         "empty hostname with no match",
			hostname:     "",
			vaultMap:     map[string]string{"web*": "vault-web"},
			defaultVault: "fallback",
			want:         "fallback",
		},
		{
			name:     "empty hostname exact match",
			hostname: "",
			vaultMap: map[string]string{"": "vault-empty"},
			want:     "vault-empty",
		},
		{
			name:         "glob star only matches everything",
			hostname:     "anything.example.com",
			vaultMap:     map[string]string{"*": "vault-star"},
			defaultVault: "fallback",
			want:         "vault-star",
		},
		{
			name:     "exact match takes priority over glob",
			hostname: "staging-web1.example.com",
			vaultMap: map[string]string{
				"staging-*":                  "vault-glob",
				"staging-web1.example.com":   "vault-exact",
			},
			defaultVault: "fallback",
			want:         "vault-exact",
		},
		{
			name:     "prefix glob no match",
			hostname: "prod-web1.example.com",
			vaultMap: map[string]string{
				"staging-*": "vault-staging",
			},
			defaultVault: "global",
			want:         "global",
		},
		{
			name:     "suffix glob no match",
			hostname: "web1.staging.example.com",
			vaultMap: map[string]string{
				"*.prod.example.com": "vault-prod",
			},
			defaultVault: "global",
			want:         "global",
		},
		{
			name:         "empty default vault",
			hostname:     "host.example.com",
			vaultMap:     nil,
			defaultVault: "",
			want:         "",
		},
		{
			name:     "default key in map with empty default vault",
			hostname: "unknown.host",
			vaultMap: map[string]string{
				"default": "from-map-default",
			},
			defaultVault: "",
			want:         "from-map-default",
		},
		{
			name:     "multiple suffix globs longest wins",
			hostname: "web1.us-east.prod.example.com",
			vaultMap: map[string]string{
				"*.example.com":              "vault-short",
				"*.prod.example.com":         "vault-medium",
				"*.us-east.prod.example.com": "vault-long",
			},
			defaultVault: "fallback",
			want:         "vault-long",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveEscrowVault(tt.hostname, tt.vaultMap, tt.defaultVault)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// ── Local backend: empty password, long password, unicode hostname ────────────

func TestLocalEscrowBackend_EmptyPassword(t *testing.T) {
	key, _ := DeriveEscrowKey("test-secret", []byte("salt"))
	storer := newMemStorer()
	backend := NewLocalEscrowBackend(key, storer)
	ctx := context.Background()

	_, _, err := backend.Store(ctx, "host.example.com", "", "")
	if err != nil {
		t.Fatalf("Store empty password: %v", err)
	}
	got, err := backend.Retrieve(ctx, "host.example.com", "", "")
	if err != nil {
		t.Fatalf("Retrieve empty password: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestLocalEscrowBackend_VeryLongPassword(t *testing.T) {
	key, _ := DeriveEscrowKey("test-secret", []byte("salt"))
	storer := newMemStorer()
	backend := NewLocalEscrowBackend(key, storer)
	ctx := context.Background()

	// 64 KB password
	password := strings.Repeat("A", 65536)
	_, _, err := backend.Store(ctx, "host.example.com", password, "")
	if err != nil {
		t.Fatalf("Store long password: %v", err)
	}
	got, err := backend.Retrieve(ctx, "host.example.com", "", "")
	if err != nil {
		t.Fatalf("Retrieve long password: %v", err)
	}
	if got != password {
		t.Errorf("round-trip mismatch: got len=%d, want len=%d", len(got), len(password))
	}
}

func TestLocalEscrowBackend_UnicodeHostname(t *testing.T) {
	key, _ := DeriveEscrowKey("test-secret", []byte("salt"))
	storer := newMemStorer()
	backend := NewLocalEscrowBackend(key, storer)
	ctx := context.Background()

	hostname := "server-\u00e9\u00e8\u00ea.\u4e16\u754c.example.com"
	password := "test-password"

	_, _, err := backend.Store(ctx, hostname, password, "")
	if err != nil {
		t.Fatalf("Store unicode hostname: %v", err)
	}
	got, err := backend.Retrieve(ctx, hostname, "", "")
	if err != nil {
		t.Fatalf("Retrieve unicode hostname: %v", err)
	}
	if got != password {
		t.Errorf("got %q, want %q", got, password)
	}
}

// ── Local backend: ciphertext integrity (AAD) ────────────────────────────────

func TestLocalEscrowBackend_ModifiedCiphertextFailsDecrypt(t *testing.T) {
	key, _ := DeriveEscrowKey("test-secret", []byte("salt"))
	storer := newMemStorer()
	backend := NewLocalEscrowBackend(key, storer)
	ctx := context.Background()

	hostname := "host.example.com"
	_, _, err := backend.Store(ctx, hostname, "my-password", "")
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	// Tamper with the ciphertext
	encoded, ok := storer.GetEscrowCiphertext(context.Background(), hostname)
	if !ok {
		t.Fatal("no ciphertext stored")
	}
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Flip a byte in the ciphertext portion (after the nonce)
	if len(blob) > 13 {
		blob[13] ^= 0xFF
	}
	storer.StoreEscrowCiphertext(context.Background(), hostname, base64.StdEncoding.EncodeToString(blob))

	_, err = backend.Retrieve(ctx, hostname, "", "")
	if err == nil {
		t.Error("expected decryption failure for tampered ciphertext, got nil")
	}
}

func TestLocalEscrowBackend_SwapHostnameOnRetrieve(t *testing.T) {
	key, _ := DeriveEscrowKey("test-secret", []byte("salt"))
	storer := newMemStorer()
	backend := NewLocalEscrowBackend(key, storer)
	ctx := context.Background()

	// Store for host-A, try to retrieve the same ciphertext but claim to be host-C.
	_, _, err := backend.Store(ctx, "host-A.example.com", "password-A", "")
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	// Manually copy ciphertext under a different hostname key
	ct, _ := storer.GetEscrowCiphertext(context.Background(), "host-A.example.com")
	storer.StoreEscrowCiphertext(context.Background(), "host-C.example.com", ct)

	_, err = backend.Retrieve(ctx, "host-C.example.com", "", "")
	if err == nil {
		t.Error("expected decryption to fail when hostname AAD differs")
	}
}

// ── NewLocalEscrowBackend with invalid key length ────────────────────────────

func TestNewLocalEscrowBackend_InvalidKeyLength(t *testing.T) {
	// AES-256-GCM requires a 32-byte key. A 16-byte key should fail on Store.
	shortKey := make([]byte, 16)
	storer := newMemStorer()
	backend := NewLocalEscrowBackend(shortKey, storer)

	// Store should fail because aes.NewCipher with 16 bytes creates AES-128,
	// but actually AES-128 is valid. So test with truly invalid sizes.
	invalidKey := make([]byte, 7) // not 16, 24, or 32
	backend = NewLocalEscrowBackend(invalidKey, storer)
	_, _, err := backend.Store(context.Background(), "host", "pass", "")
	if err == nil {
		t.Error("expected error for 7-byte key, got nil")
	}

	// Also test with zero-length key
	backend = NewLocalEscrowBackend([]byte{}, storer)
	_, _, err = backend.Store(context.Background(), "host", "pass", "")
	if err == nil {
		t.Error("expected error for empty key, got nil")
	}
}

// ── Concurrent Store/Retrieve on local backend ──────────────────────────────

func TestLocalEscrowBackend_ConcurrentStoreRetrieve(t *testing.T) {
	key, _ := DeriveEscrowKey("concurrent-test", []byte("salt"))
	storer := &syncMemStorer{data: make(map[string]string)}
	backend := NewLocalEscrowBackend(key, storer)
	ctx := context.Background()

	const n = 50
	var wg sync.WaitGroup

	// Concurrently store passwords for different hosts
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := strings.Repeat("a", i+1) + ".example.com"
			password := strings.Repeat("p", i+1)
			if _, _, err := backend.Store(ctx, host, password, ""); err != nil {
				t.Errorf("Store(%q): %v", host, err)
			}
		}(i)
	}
	wg.Wait()

	// Concurrently retrieve and verify
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := strings.Repeat("a", i+1) + ".example.com"
			want := strings.Repeat("p", i+1)
			got, err := backend.Retrieve(ctx, host, "", "")
			if err != nil {
				t.Errorf("Retrieve(%q): %v", host, err)
				return
			}
			if got != want {
				t.Errorf("Retrieve(%q): got len=%d, want len=%d", host, len(got), len(want))
			}
		}(i)
	}
	wg.Wait()
}

// syncMemStorer is a goroutine-safe memStorer for concurrent tests.
type syncMemStorer struct {
	mu   sync.Mutex
	data map[string]string
}

func (s *syncMemStorer) StoreEscrowCiphertext(_ context.Context, hostname, ciphertext string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[hostname] = ciphertext
}

func (s *syncMemStorer) GetEscrowCiphertext(_ context.Context, hostname string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[hostname]
	return v, ok
}

// ── truncateOutput ──────────────────────────────────────────────────────────

func TestTruncateOutput(t *testing.T) {
	t.Run("short string unchanged", func(t *testing.T) {
		got := truncateOutput("  hello world  ")
		if got != "hello world" {
			t.Errorf("got %q, want %q", got, "hello world")
		}
	})

	t.Run("long string truncated", func(t *testing.T) {
		long := strings.Repeat("x", maxLogOutput+100)
		got := truncateOutput(long)
		if !strings.HasSuffix(got, "...(truncated)") {
			t.Errorf("expected truncation suffix, got %q", got[len(got)-30:])
		}
		if len(got) > maxLogOutput+20 {
			t.Errorf("truncated output too long: %d", len(got))
		}
	})

	t.Run("empty string", func(t *testing.T) {
		got := truncateOutput("")
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("unicode truncation respects rune boundaries", func(t *testing.T) {
		// Create a string with multi-byte runes near the truncation boundary
		prefix := strings.Repeat("x", maxLogOutput-2)
		s := prefix + "\u00e9\u00e9\u00e9\u00e9" // each is 2 bytes
		got := truncateOutput(s)
		if !strings.HasSuffix(got, "...(truncated)") {
			t.Errorf("expected truncation suffix")
		}
	})
}

// ── looksLikeID ─────────────────────────────────────────────────────────────

func TestLooksLikeID(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"abc12345-def6-7890-abcd-ef1234567890", true},  // 36-char UUID
		{"abcdefghijklmnopqrst", true},                   // 20-char alphanum
		{"short", false},                                  // too short
		{"this-is-way-too-long-to-be-a-valid-uuid-or-id-string", false}, // too long
		{"has spaces in the string!", false},               // spaces
		{"abc123!@#$%^&*()", false},                        // special chars
		{"12345678901234567890", true},                     // exactly 20 chars, all digits
	}
	for _, tt := range tests {
		got := looksLikeID(tt.input)
		if got != tt.want {
			t.Errorf("looksLikeID(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// ── opConnectEscapeTitle ────────────────────────────────────────────────────

func TestOpConnectEscapeTitle(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"simple", "simple"},
		{`has"quote`, `has\"quote`},
		{`has\backslash`, `has\\backslash`},
		{`both"and\`, `both\"and\\`},
		{"", ""},
	}
	for _, tt := range tests {
		got := opConnectEscapeTitle(tt.input)
		if got != tt.want {
			t.Errorf("opConnectEscapeTitle(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── NewEscrowBackend ────────────────────────────────────────────────────────

func TestNewEscrowBackend(t *testing.T) {
	tests := []struct {
		name    string
		backend config.EscrowBackend
		wantNil bool
	}{
		{"1password-connect", "1password-connect", false},
		{"vault", "vault", false},
		{"bitwarden", "bitwarden", false},
		{"infisical", "infisical", false},
		{"unknown", "unknown", true},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.ServerConfig{
				EscrowBackend:    tt.backend,
				EscrowURL:        "http://localhost:8080/",
				EscrowAuthID:     "auth-id",
				EscrowAuthSecret: "auth-secret",
				EscrowPath:       "test-path",
			}
			got := NewEscrowBackend(cfg)
			if tt.wantNil && got != nil {
				t.Errorf("expected nil, got %T", got)
			}
			if !tt.wantNil && got == nil {
				t.Errorf("expected non-nil backend for %q", tt.backend)
			}
		})
	}
}

// ── newEscrowHTTPClient ─────────────────────────────────────────────────────

func TestNewEscrowHTTPClient(t *testing.T) {
	client := newEscrowHTTPClient()
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Timeout != 30*1e9 {
		t.Errorf("expected 30s timeout, got %v", client.Timeout)
	}
	// Verify redirect following is disabled
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := client.Get(srv.URL + "/redirect")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected 302 (no redirect following), got %d", resp.StatusCode)
	}
}

// ── doJSONRequest ───────────────────────────────────────────────────────────

func TestDoJSONRequest(t *testing.T) {
	t.Run("GET with auth header", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				t.Errorf("method = %s, want GET", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("auth header = %q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		}))
		defer srv.Close()

		client := &http.Client{}
		data, err := doJSONRequest(context.Background(), client, "GET", srv.URL, nil, "Bearer test-token")
		if err != nil {
			t.Fatalf("doJSONRequest: %v", err)
		}
		if !strings.Contains(string(data), "ok") {
			t.Errorf("unexpected response: %s", data)
		}
	})

	t.Run("POST with body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("method = %s, want POST", r.Method)
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
			}
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if body["key"] != "value" {
				t.Errorf("body key = %q, want %q", body["key"], "value")
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"created":true}`))
		}))
		defer srv.Close()

		client := &http.Client{}
		body := map[string]string{"key": "value"}
		data, err := doJSONRequest(context.Background(), client, "POST", srv.URL, body, "")
		if err != nil {
			t.Fatalf("doJSONRequest: %v", err)
		}
		if !strings.Contains(string(data), "created") {
			t.Errorf("unexpected response: %s", data)
		}
	})

	t.Run("returns error for 4xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found"))
		}))
		defer srv.Close()

		client := &http.Client{}
		_, err := doJSONRequest(context.Background(), client, "GET", srv.URL, nil, "")
		if err == nil {
			t.Error("expected error for 404")
		}
		if !strings.Contains(err.Error(), "404") {
			t.Errorf("error should mention 404: %v", err)
		}
	})

	t.Run("no auth header when empty", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				t.Errorf("expected no auth header, got %q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		}))
		defer srv.Close()

		client := &http.Client{}
		_, err := doJSONRequest(context.Background(), client, "GET", srv.URL, nil, "")
		if err != nil {
			t.Fatalf("doJSONRequest: %v", err)
		}
	})
}

// ── identityURL (bitwarden) ─────────────────────────────────────────────────

func TestBitwardenIdentityURL(t *testing.T) {
	tests := []struct {
		apiURL string
		want   string
	}{
		{"https://api.bitwarden.com", "https://identity.bitwarden.com"},
		{"https://example.com/api", "https://example.com/identity"},
		{"https://vault.local/api", "https://vault.local/identity"},
	}
	for _, tt := range tests {
		b := &bitwardenBackend{apiURL: tt.apiURL}
		got := b.identityURL()
		if got != tt.want {
			t.Errorf("identityURL(%q) = %q, want %q", tt.apiURL, got, tt.want)
		}
	}
}

// ── opConnect backend via httptest ──────────────────────────────────────────

func TestOpConnectBackend_StoreAndRetrieve(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		switch {
		// List vaults
		case r.Method == "GET" && r.URL.Path == "/v1/vaults":
			json.NewEncoder(w).Encode([]map[string]string{
				{"id": "vault-uuid-123", "name": "TestVault"},
			})
		// Search items (empty result = create new)
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/items") && r.URL.RawQuery != "":
			json.NewEncoder(w).Encode([]map[string]string{})
		// Create item
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/items"):
			json.NewEncoder(w).Encode(map[string]string{"id": "item-uuid-456"})
		// Get item (retrieve)
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/items/"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"fields": []map[string]string{
					{"purpose": "PASSWORD", "value": "retrieved-password"},
				},
			})
		// Update item
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/items/"):
			json.NewEncoder(w).Encode(map[string]string{"id": "item-uuid-456"})
		default:
			http.Error(w, "not found", 404)
		}
	}))
	defer srv.Close()

	backend := &opConnectBackend{
		baseURL: srv.URL,
		token:   "test-token",
		vault:   "TestVault",
		client:  &http.Client{},
	}
	ctx := context.Background()

	// Store
	itemID, vaultID, err := backend.Store(ctx, "web1.example.com", "my-password", "")
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if itemID != "item-uuid-456" {
		t.Errorf("itemID = %q, want %q", itemID, "item-uuid-456")
	}
	if vaultID != "vault-uuid-123" {
		t.Errorf("vaultID = %q, want %q", vaultID, "vault-uuid-123")
	}

	// Retrieve
	pw, err := backend.Retrieve(ctx, "web1.example.com", "item-uuid-456", "vault-uuid-123")
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if pw != "retrieved-password" {
		t.Errorf("password = %q, want %q", pw, "retrieved-password")
	}
}

func TestOpConnectBackend_RetrieveMissingIDs(t *testing.T) {
	backend := &opConnectBackend{client: &http.Client{}}
	_, err := backend.Retrieve(context.Background(), "host", "", "")
	if err == nil {
		t.Error("expected error for missing vault/item IDs")
	}
}

// ── hcVault backend via httptest ────────────────────────────────────────────

func TestHCVaultBackend_StoreAndRetrieve(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Vault-Token")
		if token != "direct-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		switch r.Method {
		case "POST", "PUT":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		case "GET":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]string{"password": "vault-password"},
				},
			})
		}
	}))
	defer srv.Close()

	backend := &hcVaultBackend{
		baseURL:  srv.URL,
		roleID:   "",           // direct token auth
		secretID: "direct-token",
		path:     "secret/identree",
		client:   &http.Client{},
	}
	ctx := context.Background()

	// Store
	itemID, _, err := backend.Store(ctx, "web1.example.com", "my-password", "")
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if !strings.Contains(itemID, "web1.example.com") {
		t.Errorf("itemID should contain hostname: %q", itemID)
	}

	// Retrieve
	pw, err := backend.Retrieve(ctx, "web1.example.com", "", "")
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if pw != "vault-password" {
		t.Errorf("password = %q, want %q", pw, "vault-password")
	}
}

func TestHCVaultBackend_AppRoleAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]string{"client_token": "approle-token"},
			})
			return
		}
		token := r.Header.Get("X-Vault-Token")
		if token != "approle-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]string{"password": "approle-pass"},
			},
		})
	}))
	defer srv.Close()

	backend := &hcVaultBackend{
		baseURL:  srv.URL,
		roleID:   "role-123",
		secretID: "secret-456",
		path:     "secret",
		client:   &http.Client{},
	}

	pw, err := backend.Retrieve(context.Background(), "host", "", "")
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if pw != "approle-pass" {
		t.Errorf("password = %q, want %q", pw, "approle-pass")
	}
}

// ── infisical backend via httptest ──────────────────────────────────────────

func TestInfisicalBackend_StoreAndRetrieve(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Auth endpoint
		if strings.Contains(r.URL.Path, "/auth/universal-auth/login") {
			json.NewEncoder(w).Encode(map[string]string{"accessToken": "inf-token"})
			return
		}

		auth := r.Header.Get("Authorization")
		if auth != "Bearer inf-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		switch r.Method {
		case "PATCH":
			// Update secret - return 404 to trigger create
			http.Error(w, "HTTP 404: not found", http.StatusNotFound)
		case "POST":
			// Create secret
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		case "GET":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"secret": map[string]string{"secretValue": "inf-password"},
			})
		}
	}))
	defer srv.Close()

	backend := &infisicalBackend{
		baseURL:      srv.URL,
		clientID:     "client-id",
		clientSecret: "client-secret",
		projectEnv:   "workspace123/prod",
		client:       &http.Client{},
	}
	ctx := context.Background()

	// Store (PATCH 404 -> POST create)
	itemID, _, err := backend.Store(ctx, "web1.example.com", "my-password", "")
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if !strings.Contains(itemID, "BREAKGLASS_WEB1_EXAMPLE_COM") {
		t.Errorf("itemID should contain normalized hostname: %q", itemID)
	}

	// Retrieve
	pw, err := backend.Retrieve(ctx, "web1.example.com", "", "")
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if pw != "inf-password" {
		t.Errorf("password = %q, want %q", pw, "inf-password")
	}
}

// ── bitwarden backend via httptest ──────────────────────────────────────────

func TestBitwardenBackend_StoreAndRetrieve(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Token endpoint
		if strings.Contains(r.URL.Path, "/connect/token") {
			json.NewEncoder(w).Encode(map[string]string{"access_token": "bw-token"})
			return
		}

		auth := r.Header.Get("Authorization")
		if auth != "Bearer bw-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		switch {
		// Search secrets - empty result
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/organizations/"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]string{},
			})
		// Create secret
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/secrets"):
			json.NewEncoder(w).Encode(map[string]string{"id": "bw-secret-id"})
		// Get secret
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/secrets/"):
			json.NewEncoder(w).Encode(map[string]string{"value": "bw-password"})
		default:
			http.Error(w, "not found", 404)
		}
	}))
	defer srv.Close()

	// The bitwarden backend derives identity URL from api URL
	backend := &bitwardenBackend{
		apiURL:       srv.URL,
		clientID:     "client-id",
		clientSecret: "client-secret",
		orgProject:   "org-uuid/project-uuid",
		client:       &http.Client{},
	}
	ctx := context.Background()

	// Store
	secretID, _, err := backend.Store(ctx, "web1.example.com", "my-password", "")
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if secretID != "bw-secret-id" {
		t.Errorf("secretID = %q, want %q", secretID, "bw-secret-id")
	}

	// Retrieve
	pw, err := backend.Retrieve(ctx, "web1.example.com", "bw-secret-id", "")
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if pw != "bw-password" {
		t.Errorf("password = %q, want %q", pw, "bw-password")
	}
}

func TestBitwardenBackend_RetrieveMissingID(t *testing.T) {
	backend := &bitwardenBackend{client: &http.Client{}}
	_, err := backend.Retrieve(context.Background(), "host", "", "")
	if err == nil {
		t.Error("expected error for missing item ID")
	}
}
