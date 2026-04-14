package escrow

import (
	"bytes"
	"context"
	"testing"
)

// memStorer is a minimal in-memory EscrowStorer for tests.
type memStorer struct {
	data map[string]string
}

func newMemStorer() *memStorer {
	return &memStorer{data: make(map[string]string)}
}

func (s *memStorer) StoreEscrowCiphertext(hostname, ciphertext string) {
	s.data[hostname] = ciphertext
}

func (s *memStorer) GetEscrowCiphertext(hostname string) (string, bool) {
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
	ct, ok := storer.GetEscrowCiphertext("host-A.example.com")
	if !ok {
		t.Fatal("expected ciphertext stored for host-A")
	}
	storer.StoreEscrowCiphertext("host-B.example.com", ct)

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
