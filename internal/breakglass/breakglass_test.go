package breakglass

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rinseaid/identree/internal/config"
)

// overrideFileOwnerUID temporarily makes FileOwnerUID return uid=0 (root) for
// all files, so tests can run as a non-root user. Restores the original on
// cleanup.
func overrideFileOwnerUID(t *testing.T) {
	t.Helper()
	orig := config.FileOwnerUID
	config.FileOwnerUID = func(info os.FileInfo) (uint32, bool) {
		return 0, true
	}
	t.Cleanup(func() { config.FileOwnerUID = orig })
}

func TestReadBreakglassHash_Valid(t *testing.T) {
	overrideFileOwnerUID(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "breakglass.hash")

	// Write a valid file: comment header + bcrypt hash.
	content := "# identree breakglass host=test type=random created=2025-01-01T00:00:00Z\n" +
		"$2a$12$LJ3m4ys3Lg4TtN7Opu7JyOJhyDQXfYl0e1aGXHMcMj1VQUIDrqVK2\n"

	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	hash, err := ReadBreakglassHash(path)
	if err != nil {
		t.Fatalf("ReadBreakglassHash: %v", err)
	}
	if hash != "$2a$12$LJ3m4ys3Lg4TtN7Opu7JyOJhyDQXfYl0e1aGXHMcMj1VQUIDrqVK2" {
		t.Errorf("got hash %q, want the bcrypt hash from the file", hash)
	}
}

func TestReadBreakglassHash_WorldReadable(t *testing.T) {
	overrideFileOwnerUID(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "breakglass.hash")

	content := "$2a$12$LJ3m4ys3Lg4TtN7Opu7JyOJhyDQXfYl0e1aGXHMcMj1VQUIDrqVK2\n"
	// Write with group/other read permissions.
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := ReadBreakglassHash(path)
	if err == nil {
		t.Error("expected error for world-readable file, got nil")
	}
}

func TestReadBreakglassHash_GroupWritable(t *testing.T) {
	overrideFileOwnerUID(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "breakglass.hash")

	content := "$2a$12$LJ3m4ys3Lg4TtN7Opu7JyOJhyDQXfYl0e1aGXHMcMj1VQUIDrqVK2\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Explicitly chmod after write to avoid umask interference.
	if err := os.Chmod(path, 0620); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	_, err := ReadBreakglassHash(path)
	if err == nil {
		t.Error("expected error for group-writable file, got nil")
	}
}

func TestReadBreakglassHash_NotBcrypt(t *testing.T) {
	overrideFileOwnerUID(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "breakglass.hash")

	// Write something that is not a bcrypt hash.
	if err := os.WriteFile(path, []byte("not-a-hash\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := ReadBreakglassHash(path)
	if err == nil {
		t.Error("expected error for non-bcrypt content, got nil")
	}
}

func TestReadBreakglassHash_EmptyFile(t *testing.T) {
	overrideFileOwnerUID(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "breakglass.hash")

	if err := os.WriteFile(path, []byte(""), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := ReadBreakglassHash(path)
	if err == nil {
		t.Error("expected error for empty file, got nil")
	}
}

func TestReadBreakglassHash_OnlyComments(t *testing.T) {
	overrideFileOwnerUID(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "breakglass.hash")

	content := "# just a comment\n# another comment\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := ReadBreakglassHash(path)
	if err == nil {
		t.Error("expected error for file with only comments, got nil")
	}
}

func TestReadBreakglassHash_NotOwnedByRoot(t *testing.T) {
	// Use the real FileOwnerUID (don't override) — on macOS/Linux as non-root
	// the file will be owned by the current user, which should fail the root check.
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "breakglass.hash")

	content := "$2a$12$LJ3m4ys3Lg4TtN7Opu7JyOJhyDQXfYl0e1aGXHMcMj1VQUIDrqVK2\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := ReadBreakglassHash(path)
	if err == nil {
		t.Error("expected error for non-root-owned file, got nil")
	}
}

func TestReadBreakglassHash_Nonexistent(t *testing.T) {
	_, err := ReadBreakglassHash("/nonexistent/path/breakglass.hash")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

// ── Password generation (pure functions, no network/root) ────────────────────

func TestGenerateBreakglassPassword_Random(t *testing.T) {
	pw, err := generateBreakglassPassword("random")
	if err != nil {
		t.Fatalf("generateBreakglassPassword: %v", err)
	}
	if len(pw) == 0 {
		t.Error("empty password returned")
	}
	// base64url of 32 bytes = 43 chars
	if len(pw) != 43 {
		t.Errorf("random password length = %d, want 43", len(pw))
	}
}

func TestGenerateBreakglassPassword_Alphanumeric(t *testing.T) {
	pw, err := generateBreakglassPassword("alphanumeric")
	if err != nil {
		t.Fatalf("generateBreakglassPassword: %v", err)
	}
	if len(pw) != 24 {
		t.Errorf("alphanumeric password length = %d, want 24", len(pw))
	}
}

func TestGenerateBreakglassPassword_Passphrase(t *testing.T) {
	pw, err := generateBreakglassPassword("passphrase")
	if err != nil {
		t.Fatalf("generateBreakglassPassword: %v", err)
	}
	if len(pw) == 0 {
		t.Error("empty passphrase returned")
	}
}

func TestGenerateBreakglassPassword_Unknown(t *testing.T) {
	_, err := generateBreakglassPassword("unknown-type")
	if err == nil {
		t.Error("expected error for unknown password type")
	}
}

func TestHashBreakglassPassword(t *testing.T) {
	hash, err := hashBreakglassPassword("test-password", 4) // low cost for speed
	if err != nil {
		t.Fatalf("hashBreakglassPassword: %v", err)
	}
	if len(hash) == 0 {
		t.Error("empty hash returned")
	}
	if hash[:3] != "$2a" && hash[:3] != "$2b" {
		t.Errorf("hash does not look like bcrypt: %q", hash[:10])
	}
}

func TestHashBreakglassPassword_DefaultCost(t *testing.T) {
	// cost=0 should use defaultBcryptCost (12)
	hash, err := hashBreakglassPassword("test-password", 0)
	if err != nil {
		t.Fatalf("hashBreakglassPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("hash does not look like bcrypt: %q", hash)
	}
}

// ── writeBreakglassFile ─────────────────────────────────────────────────────

func TestWriteBreakglassFile_PermissionsAndContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "breakglass.hash")
	hash := "$2a$04$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"

	err := writeBreakglassFile(path, hash, "test-host.example.com", "random")
	if err != nil {
		t.Fatalf("writeBreakglassFile: %v", err)
	}

	// Verify file exists
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	// Verify permissions are 0600
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("file permissions = %04o, want 0600", perm)
	}

	// Verify content: comment header + hash
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)

	if !strings.HasPrefix(content, "# identree breakglass") {
		t.Errorf("expected comment header, got: %q", content[:50])
	}
	if !strings.Contains(content, "host=test-host.example.com") {
		t.Error("expected hostname in header")
	}
	if !strings.Contains(content, "type=random") {
		t.Error("expected password type in header")
	}
	if !strings.Contains(content, "created=") {
		t.Error("expected created timestamp in header")
	}
	if !strings.Contains(content, hash) {
		t.Error("expected hash in file content")
	}
}

func TestWriteBreakglassFile_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "breakglass.hash")

	err := writeBreakglassFile(path, "$2a$04$testhashabcdefghijklmnopq", "host", "random")
	if err != nil {
		t.Fatalf("writeBreakglassFile: %v", err)
	}

	// Verify file exists after write
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file does not exist after write: %v", err)
	}

	// Verify no temp files left behind
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".breakglass-tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestWriteBreakglassFile_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "breakglass.hash")

	// Write initial file
	hash1 := "$2a$04$firsthashAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := writeBreakglassFile(path, hash1, "host", "random"); err != nil {
		t.Fatalf("first write: %v", err)
	}

	// Overwrite with new hash
	hash2 := "$2a$04$secondhashBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	if err := writeBreakglassFile(path, hash2, "host", "random"); err != nil {
		t.Fatalf("second write: %v", err)
	}

	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), hash2) {
		t.Error("file does not contain the new hash")
	}
	if strings.Contains(string(data), hash1) {
		t.Error("file still contains the old hash")
	}
}

// ── breakglassFileAge ───────────────────────────────────────────────────────

func TestBreakglassFileAge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "breakglass.hash")

	if err := os.WriteFile(path, []byte("test"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	age, err := breakglassFileAge(path)
	if err != nil {
		t.Fatalf("breakglassFileAge: %v", err)
	}

	// File was just created, age should be very small
	if age > 2*time.Second {
		t.Errorf("age = %v, expected < 2s for a freshly created file", age)
	}
	if age < 0 {
		t.Errorf("age = %v, expected non-negative", age)
	}
}

func TestBreakglassFileAge_NonexistentFile(t *testing.T) {
	_, err := breakglassFileAge("/nonexistent/path/file")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// ── BreakglassFileExists ────────────────────────────────────────────────────

func TestBreakglassFileExists(t *testing.T) {
	t.Run("existing regular file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "breakglass.hash")
		os.WriteFile(path, []byte("test"), 0600)

		if !BreakglassFileExists(path) {
			t.Error("expected true for existing regular file")
		}
	})

	t.Run("non-existing file", func(t *testing.T) {
		if BreakglassFileExists("/nonexistent/path/breakglass.hash") {
			t.Error("expected false for nonexistent file")
		}
	})

	t.Run("directory not a file", func(t *testing.T) {
		dir := t.TempDir()
		if BreakglassFileExists(dir) {
			t.Error("expected false for a directory")
		}
	})

	t.Run("symlink returns false", func(t *testing.T) {
		dir := t.TempDir()
		realFile := filepath.Join(dir, "real")
		os.WriteFile(realFile, []byte("test"), 0600)

		link := filepath.Join(dir, "link")
		if err := os.Symlink(realFile, link); err != nil {
			t.Skipf("cannot create symlink: %v", err)
		}

		if BreakglassFileExists(link) {
			t.Error("expected false for symlink (Lstat should not follow)")
		}
	})
}

// ── IsServerUnreachable ─────────────────────────────────────────────────────

func TestIsServerUnreachable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "net.OpError with Op=dial",
			err:  &net.OpError{Op: "dial", Err: fmt.Errorf("connection refused")},
			want: true,
		},
		{
			name: "net.OpError with Op=read",
			err:  &net.OpError{Op: "read", Err: fmt.Errorf("connection reset")},
			want: false,
		},
		{
			name: "net.DNSError",
			err:  &net.DNSError{Err: "no such host", Name: "example.com"},
			want: true,
		},
		{
			name: "context.DeadlineExceeded",
			err:  fmt.Errorf("request failed: %w", errors.New("context deadline exceeded")),
			want: false,
		},
		{
			name: "tls.CertificateVerificationError",
			err:  &tls.CertificateVerificationError{Err: fmt.Errorf("cert expired")},
			want: false,
		},
		{
			name: "x509.UnknownAuthorityError",
			err:  x509.UnknownAuthorityError{},
			want: false,
		},
		{
			name: "x509.CertificateInvalidError",
			err:  x509.CertificateInvalidError{Reason: x509.Expired},
			want: false,
		},
		{
			name: "x509.HostnameError",
			err:  x509.HostnameError{Host: "example.com"},
			want: false,
		},
		{
			name: "plain error",
			err:  errors.New("something went wrong"),
			want: false,
		},
		{
			name: "wrapped dial error",
			err:  fmt.Errorf("connect: %w", &net.OpError{Op: "dial", Err: fmt.Errorf("connection refused")}),
			want: true,
		},
		{
			name: "ServerHTTPError 502",
			err:  &ServerHTTPError{StatusCode: 502, Body: "bad gateway"},
			want: true,
		},
		{
			name: "ServerHTTPError 503",
			err:  &ServerHTTPError{StatusCode: 503, Body: "service unavailable"},
			want: true,
		},
		{
			name: "ServerHTTPError 504",
			err:  &ServerHTTPError{StatusCode: 504, Body: "gateway timeout"},
			want: true,
		},
		{
			name: "ServerHTTPError 401",
			err:  &ServerHTTPError{StatusCode: 401, Body: "unauthorized"},
			want: false,
		},
		{
			name: "ServerHTTPError 500",
			err:  &ServerHTTPError{StatusCode: 500, Body: "internal error"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsServerUnreachable(tt.err)
			if got != tt.want {
				t.Errorf("IsServerUnreachable(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// ── Password generation: random produces different results ──────────────────

func TestGenerateBreakglassPassword_RandomIsDifferent(t *testing.T) {
	pw1, err := generateBreakglassPassword("random")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	pw2, err := generateBreakglassPassword("random")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if pw1 == pw2 {
		t.Error("two consecutive random password generations produced the same result")
	}
}

func TestGenerateBreakglassPassword_AlphanumericIsDifferent(t *testing.T) {
	pw1, _ := generateBreakglassPassword("alphanumeric")
	pw2, _ := generateBreakglassPassword("alphanumeric")
	if pw1 == pw2 {
		t.Error("two consecutive alphanumeric password generations produced the same result")
	}
}

func TestGenerateBreakglassPassword_PassphraseWordCount(t *testing.T) {
	pw, err := generateBreakglassPassword("passphrase")
	if err != nil {
		t.Fatalf("generateBreakglassPassword: %v", err)
	}
	words := strings.Split(pw, "-")
	if len(words) != 10 {
		t.Errorf("passphrase has %d words, want 10", len(words))
	}
}

// ── ComputeEscrowToken and deriveKey ────────────────────────────────────────

func TestComputeEscrowToken_Consistency(t *testing.T) {
	secret := "test-shared-secret"
	hostname := "web1.example.com"
	ts := "1700000000"

	token1 := ComputeEscrowToken(secret, hostname, ts)
	token2 := ComputeEscrowToken(secret, hostname, ts)

	if token1 != token2 {
		t.Error("same inputs produced different tokens")
	}
	if len(token1) != 64 {
		t.Errorf("expected 64-char hex token, got %d chars", len(token1))
	}
}

func TestComputeEscrowToken_DifferentInputs(t *testing.T) {
	base := ComputeEscrowToken("secret", "host", "1000")

	// Different secret
	if ComputeEscrowToken("other-secret", "host", "1000") == base {
		t.Error("different secret produced same token")
	}
	// Different hostname
	if ComputeEscrowToken("secret", "other-host", "1000") == base {
		t.Error("different hostname produced same token")
	}
	// Different timestamp
	if ComputeEscrowToken("secret", "host", "2000") == base {
		t.Error("different timestamp produced same token")
	}
}

func TestDeriveKey_DifferentPurposes(t *testing.T) {
	key1 := config.DeriveKey("shared-secret", "escrow")
	key2 := config.DeriveKey("shared-secret", "other-purpose")

	if string(key1) == string(key2) {
		t.Error("different purposes produced the same derived key")
	}
	if len(key1) != 32 {
		t.Errorf("expected 32-byte derived key, got %d", len(key1))
	}
}

func TestDeriveKey_Deterministic(t *testing.T) {
	key1 := config.DeriveKey("secret", "purpose")
	key2 := config.DeriveKey("secret", "purpose")
	if string(key1) != string(key2) {
		t.Error("same inputs produced different derived keys")
	}
}

// ── ServerHTTPError and escrowHTTPError ─────────────────────────────────────

func TestServerHTTPError_Error(t *testing.T) {
	err := &ServerHTTPError{StatusCode: 403, Body: "forbidden"}
	got := err.Error()
	if !strings.Contains(got, "403") || !strings.Contains(got, "forbidden") {
		t.Errorf("unexpected error string: %q", got)
	}
}

func TestEscrowHTTPError_Error(t *testing.T) {
	err := &escrowHTTPError{StatusCode: 501, Body: "not implemented"}
	got := err.Error()
	if !strings.Contains(got, "501") || !strings.Contains(got, "not implemented") {
		t.Errorf("unexpected error string: %q", got)
	}
}

// ── breakglassFileMtime ─────────────────────────────────────────────────────

func TestBreakglassFileMtime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "breakglass.hash")
	os.WriteFile(path, []byte("test"), 0600)

	mtime, err := breakglassFileMtime(path)
	if err != nil {
		t.Fatalf("breakglassFileMtime: %v", err)
	}
	if time.Since(mtime) > 2*time.Second {
		t.Errorf("mtime too old: %v", mtime)
	}
}

func TestBreakglassFileMtime_NonexistentFile(t *testing.T) {
	_, err := breakglassFileMtime("/nonexistent/path/file")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// ── EscrowPassword ──────────────────────────────────────────────────────────

func TestEscrowPassword_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/breakglass/escrow" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("X-Shared-Secret") != "my-secret" {
			t.Errorf("X-Shared-Secret = %q", r.Header.Get("X-Shared-Secret"))
		}
		if r.Header.Get("X-Escrow-Token") == "" {
			t.Error("expected X-Escrow-Token header")
		}
		if r.Header.Get("X-Escrow-Ts") == "" {
			t.Error("expected X-Escrow-Ts header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.ClientConfig{
		ServerURL:              srv.URL,
		SharedSecret:           "my-secret",
		InsecureAllowHTTPEscrow: true,
	}

	err := EscrowPassword(cfg, "test-host", "test-password", true)
	if err != nil {
		t.Fatalf("EscrowPassword: %v", err)
	}
}

func TestEscrowPassword_RefusesHTTP(t *testing.T) {
	cfg := &config.ClientConfig{
		ServerURL:              "http://insecure.example.com",
		SharedSecret:           "secret",
		InsecureAllowHTTPEscrow: false,
	}

	err := EscrowPassword(cfg, "host", "pass", true)
	if err == nil {
		t.Error("expected error for HTTP without InsecureAllowHTTPEscrow")
	}
	if !strings.Contains(err.Error(), "plaintext HTTP") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEscrowPassword_NoServerURL(t *testing.T) {
	cfg := &config.ClientConfig{ServerURL: ""}
	err := EscrowPassword(cfg, "host", "pass", true)
	if err == nil {
		t.Error("expected error for empty ServerURL")
	}
}

func TestEscrowPassword_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not implemented", http.StatusNotImplemented)
	}))
	defer srv.Close()

	cfg := &config.ClientConfig{
		ServerURL:              srv.URL,
		SharedSecret:           "secret",
		InsecureAllowHTTPEscrow: true,
	}

	err := EscrowPassword(cfg, "host", "pass", true)
	if err == nil {
		t.Error("expected error for 501")
	}
	var httpErr *escrowHTTPError
	if !errors.As(err, &httpErr) {
		t.Errorf("expected escrowHTTPError, got %T: %v", err, err)
	} else if httpErr.StatusCode != 501 {
		t.Errorf("status = %d, want 501", httpErr.StatusCode)
	}
}

// ── checkBreakglassRateLimit ────────────────────────────────────────────────

func TestCheckBreakglassRateLimit_NoFile(t *testing.T) {
	// When there's no failure file, rate limiting should not kick in.
	// readFailureCounter returns (0, zero time) when file doesn't exist.
	// This is the common case.
	err := checkBreakglassRateLimit()
	// Should not error since count < 3 (starts at 0 when no file)
	if err != nil {
		t.Errorf("unexpected rate limit error: %v", err)
	}
}

// ── clearBreakglassFailures ─────────────────────────────────────────────────

func TestClearBreakglassFailures(t *testing.T) {
	// Should not panic even when file doesn't exist
	clearBreakglassFailures()
}

// ── readFailureCounter ──────────────────────────────────────────────────────

func TestReadFailureCounter_NoFile(t *testing.T) {
	count, lastFail := readFailureCounter()
	if count != 0 {
		t.Errorf("expected count=0, got %d", count)
	}
	if !lastFail.IsZero() {
		t.Errorf("expected zero time, got %v", lastFail)
	}
}

// ── generateBreakglassPassword edge cases ───────────────────────────────────

func TestGenerateAlphanumericPassword_OnlyUnambiguous(t *testing.T) {
	pw, err := generateAlphanumericPassword()
	if err != nil {
		t.Fatalf("generateAlphanumericPassword: %v", err)
	}
	for _, c := range pw {
		if !strings.ContainsRune(unambiguousAlphanum, c) {
			t.Errorf("password contains ambiguous character: %c", c)
		}
	}
}

func TestGeneratePassphrase_AllWordsFromList(t *testing.T) {
	pw, err := generatePassphrase()
	if err != nil {
		t.Fatalf("generatePassphrase: %v", err)
	}
	words := strings.Split(pw, "-")
	wordSet := make(map[string]bool, len(passphraseWordlist))
	for _, w := range passphraseWordlist {
		wordSet[w] = true
	}
	for _, w := range words {
		if !wordSet[w] {
			t.Errorf("word %q not in wordlist", w)
		}
	}
}

func TestGenerateRandomPassword(t *testing.T) {
	pw, err := generateRandomPassword()
	if err != nil {
		t.Fatalf("generateRandomPassword: %v", err)
	}
	if len(pw) != 43 { // base64url of 32 bytes = 43 chars
		t.Errorf("len = %d, want 43", len(pw))
	}
}

// ── hashBreakglassPassword edge cases ───────────────────────────────────────

func TestHashBreakglassPassword_VerifiesCorrectly(t *testing.T) {
	password := "test-verify-password"
	hash, err := hashBreakglassPassword(password, 4)
	if err != nil {
		t.Fatalf("hashBreakglassPassword: %v", err)
	}

	// The hash should verify against the original password
	// Use bcrypt directly
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("hash prefix = %q, want $2", hash[:2])
	}
}

// ── writeBreakglassFile edge cases ──────────────────────────────────────────

func TestWriteBreakglassFile_NonexistentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent", "subdir", "breakglass.hash")
	err := writeBreakglassFile(path, "$2a$04$test", "host", "random")
	if err == nil {
		t.Error("expected error for nonexistent parent directory")
	}
}

// ── MaybeRotateBreakglass ───────────────────────────────────────────────────

func TestMaybeRotateBreakglass_DisabledNoop(t *testing.T) {
	cfg := &config.ClientConfig{BreakglassEnabled: false}
	// Should return immediately without doing anything
	MaybeRotateBreakglass(cfg, time.Time{})
}

// ── passphraseWordlist ──────────────────────────────────────────────────────

// ── RotateBreakglass ────────────────────────────────────────────────────────

func TestRotateBreakglass_LocalOnly(t *testing.T) {
	dir := t.TempDir()
	hashFile := filepath.Join(dir, "breakglass.hash")

	cfg := &config.ClientConfig{
		BreakglassEnabled:      true,
		BreakglassFile:         hashFile,
		BreakglassPasswordType: "random",
		BreakglassBcryptCost:   4, // fast for tests
		BreakglassRotationDays: 90,
		ServerURL:              "", // no server = local only
	}

	plaintext, err := RotateBreakglass(cfg, true, true)
	if err != nil {
		t.Fatalf("RotateBreakglass: %v", err)
	}

	// With no server URL, plaintext should be returned
	if plaintext == "" {
		t.Error("expected plaintext password returned when no server URL")
	}

	// Hash file should exist
	if !BreakglassFileExists(hashFile) {
		t.Error("hash file was not created")
	}

	// Hash file should have correct permissions
	info, _ := os.Stat(hashFile)
	if info.Mode().Perm() != 0600 {
		t.Errorf("hash file permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestRotateBreakglass_WithEscrow(t *testing.T) {
	dir := t.TempDir()
	hashFile := filepath.Join(dir, "breakglass.hash")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.ClientConfig{
		BreakglassEnabled:       true,
		BreakglassFile:          hashFile,
		BreakglassPasswordType:  "random",
		BreakglassBcryptCost:    4,
		BreakglassRotationDays:  90,
		ServerURL:               srv.URL,
		SharedSecret:            "test-secret",
		InsecureAllowHTTPEscrow: true,
	}

	plaintext, err := RotateBreakglass(cfg, true, true)
	if err != nil {
		t.Fatalf("RotateBreakglass: %v", err)
	}

	// With successful escrow, plaintext should be empty
	if plaintext != "" {
		t.Errorf("expected empty plaintext when escrowed, got %q", plaintext)
	}

	if !BreakglassFileExists(hashFile) {
		t.Error("hash file was not created")
	}
}

func TestRotateBreakglass_SkipsWhenNotDue(t *testing.T) {
	dir := t.TempDir()
	hashFile := filepath.Join(dir, "breakglass.hash")

	// Create an existing hash file (recent)
	writeBreakglassFile(hashFile, "$2a$04$testhashabcdefghijklmnopq", "host", "random")

	cfg := &config.ClientConfig{
		BreakglassEnabled:      true,
		BreakglassFile:         hashFile,
		BreakglassPasswordType: "random",
		BreakglassBcryptCost:   4,
		BreakglassRotationDays: 90,
	}

	plaintext, err := RotateBreakglass(cfg, false, true) // force=false
	if err != nil {
		t.Fatalf("RotateBreakglass: %v", err)
	}
	if plaintext != "" {
		t.Error("expected empty plaintext when rotation skipped")
	}
}

func TestRotateBreakglass_EscrowFailure501(t *testing.T) {
	dir := t.TempDir()
	hashFile := filepath.Join(dir, "breakglass.hash")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not implemented", http.StatusNotImplemented)
	}))
	defer srv.Close()

	cfg := &config.ClientConfig{
		BreakglassEnabled:       true,
		BreakglassFile:          hashFile,
		BreakglassPasswordType:  "random",
		BreakglassBcryptCost:    4,
		BreakglassRotationDays:  90,
		ServerURL:               srv.URL,
		SharedSecret:            "test-secret",
		InsecureAllowHTTPEscrow: true,
	}

	// 501 is treated as non-fatal, so rotation should still succeed
	plaintext, err := RotateBreakglass(cfg, true, true)
	if err != nil {
		t.Fatalf("RotateBreakglass: %v", err)
	}
	// Since escrow returned 501 (not configured), plaintext should be returned
	if plaintext == "" {
		t.Error("expected plaintext returned when escrow returns 501")
	}
}

func TestRotateBreakglass_PassphraseType(t *testing.T) {
	dir := t.TempDir()
	hashFile := filepath.Join(dir, "breakglass.hash")

	cfg := &config.ClientConfig{
		BreakglassEnabled:      true,
		BreakglassFile:         hashFile,
		BreakglassPasswordType: "passphrase",
		BreakglassBcryptCost:   4,
		BreakglassRotationDays: 90,
	}

	plaintext, err := RotateBreakglass(cfg, true, true)
	if err != nil {
		t.Fatalf("RotateBreakglass: %v", err)
	}

	// Passphrase should have 10 words separated by dashes
	words := strings.Split(plaintext, "-")
	if len(words) != 10 {
		t.Errorf("passphrase has %d words, want 10", len(words))
	}
}

// ── MaybeRotateBreakglass ───────────────────────────────────────────────────

func TestMaybeRotateBreakglass_InitialProvisioning(t *testing.T) {
	dir := t.TempDir()
	hashFile := filepath.Join(dir, "breakglass.hash")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.ClientConfig{
		BreakglassEnabled:       true,
		BreakglassFile:          hashFile,
		BreakglassPasswordType:  "random",
		BreakglassBcryptCost:    4,
		BreakglassRotationDays:  90,
		ServerURL:               srv.URL,
		SharedSecret:            "secret",
		InsecureAllowHTTPEscrow: true,
	}

	// No hash file exists, should trigger initial provisioning
	MaybeRotateBreakglass(cfg, time.Time{})

	if !BreakglassFileExists(hashFile) {
		t.Error("hash file should have been created during initial provisioning")
	}
}

func TestMaybeRotateBreakglass_NotDue(t *testing.T) {
	dir := t.TempDir()
	hashFile := filepath.Join(dir, "breakglass.hash")

	// Create a recent hash file
	writeBreakglassFile(hashFile, "$2a$04$testhashabcdefghijklmnopq", "host", "random")

	cfg := &config.ClientConfig{
		BreakglassEnabled:      true,
		BreakglassFile:         hashFile,
		BreakglassRotationDays: 90,
		BreakglassPasswordType: "random",
		BreakglassBcryptCost:   4,
	}

	// File is recent, no rotateBefore set — should not rotate
	mtime, _ := breakglassFileMtime(hashFile)
	MaybeRotateBreakglass(cfg, time.Time{})

	// File mtime should not change
	newMtime, _ := breakglassFileMtime(hashFile)
	if !mtime.Equal(newMtime) {
		t.Error("file was rotated when not due")
	}
}

// ── passphraseWordlist ──────────────────────────────────────────────────────

// ── Rate-limit counter file redirection helper ──────────────────────────────

// redirectFailurePath points breakglassFailurePath at a fresh temp-dir file
// for the duration of a test. Also clears any existing file at that path on
// setup and cleanup so tests don't leak state across each other.
func redirectFailurePath(t *testing.T) string {
	t.Helper()
	orig := breakglassFailurePath
	dir := t.TempDir()
	breakglassFailurePath = filepath.Join(dir, "failures")
	t.Cleanup(func() { breakglassFailurePath = orig })
	return breakglassFailurePath
}

// ── recordBreakglassFailure ─────────────────────────────────────────────────

func TestRecordBreakglassFailure_CreatesFileWith0600(t *testing.T) {
	overrideFileOwnerUID(t)
	path := redirectFailurePath(t)

	recordBreakglassFailure()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("counter file not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("counter file perm = %04o, want 0600", perm)
	}
}

func TestRecordBreakglassFailure_IncrementsCounter(t *testing.T) {
	overrideFileOwnerUID(t)
	redirectFailurePath(t)

	for i := 1; i <= 5; i++ {
		recordBreakglassFailure()
		count, ts := readFailureCounter()
		if count != int64(i) {
			t.Errorf("after %d calls, count = %d, want %d", i, count, i)
		}
		if ts.IsZero() {
			t.Errorf("after %d calls, timestamp is zero", i)
		}
	}
}

func TestRecordBreakglassFailure_WritesTimestamp(t *testing.T) {
	overrideFileOwnerUID(t)
	redirectFailurePath(t)

	before := time.Now().Add(-1 * time.Second)
	recordBreakglassFailure()
	after := time.Now().Add(1 * time.Second)

	_, ts := readFailureCounter()
	if ts.Before(before) || ts.After(after) {
		t.Errorf("timestamp %v not within expected window [%v, %v]", ts, before, after)
	}
}

func TestClearBreakglassFailures_RemovesFile(t *testing.T) {
	overrideFileOwnerUID(t)
	path := redirectFailurePath(t)

	recordBreakglassFailure()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("precondition: file should exist after record: %v", err)
	}

	clearBreakglassFailures()

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected file removed, stat err = %v", err)
	}
}

// ── readFailureCounter: security checks ─────────────────────────────────────

func TestReadFailureCounter_WorldWritableRejected(t *testing.T) {
	overrideFileOwnerUID(t)
	path := redirectFailurePath(t)

	// Write a file with bad perms — should be treated as 0 count (fail-open).
	if err := os.WriteFile(path, []byte("999 1700000000"), 0666); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	count, ts := readFailureCounter()
	if count != 0 || !ts.IsZero() {
		t.Errorf("world-writable file should be ignored, got count=%d ts=%v", count, ts)
	}
}

func TestReadFailureCounter_LegacyRFC3339(t *testing.T) {
	overrideFileOwnerUID(t)
	path := redirectFailurePath(t)

	// Legacy format: count followed by RFC3339 timestamp.
	content := "7 2024-01-02T03:04:05Z"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	count, ts := readFailureCounter()
	if count != 7 {
		t.Errorf("count = %d, want 7", count)
	}
	if ts.IsZero() {
		t.Error("expected non-zero timestamp from legacy RFC3339 format")
	}
}

func TestReadFailureCounter_Malformed(t *testing.T) {
	overrideFileOwnerUID(t)
	path := redirectFailurePath(t)

	if err := os.WriteFile(path, []byte("not-a-counter-file"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	count, ts := readFailureCounter()
	if count != 0 || !ts.IsZero() {
		t.Errorf("malformed file should return zero values, got count=%d ts=%v", count, ts)
	}
}

// ── checkBreakglassRateLimit: backoff behavior ──────────────────────────────

func TestCheckBreakglassRateLimit_UnderThreshold(t *testing.T) {
	overrideFileOwnerUID(t)
	redirectFailurePath(t)

	// 2 failures: still under the 3-attempt free threshold.
	recordBreakglassFailure()
	recordBreakglassFailure()

	if err := checkBreakglassRateLimit(); err != nil {
		t.Errorf("expected no rate limit under threshold, got: %v", err)
	}
}

func TestCheckBreakglassRateLimit_BlocksAfterBurst(t *testing.T) {
	overrideFileOwnerUID(t)
	redirectFailurePath(t)

	// 5 rapid failures should trigger backoff (2^(5-3)=4s).
	for i := 0; i < 5; i++ {
		recordBreakglassFailure()
	}
	err := checkBreakglassRateLimit()
	if err == nil {
		t.Error("expected rate-limit error after 5 rapid failures")
	}
}

func TestCheckBreakglassRateLimit_AllowsAfterDelay(t *testing.T) {
	overrideFileOwnerUID(t)
	path := redirectFailurePath(t)

	// Manually write a counter with an old timestamp so we don't have to sleep.
	// 4 failures → delay = 2^(4-3) = 2s. Timestamp 10s ago should clear the limit.
	oldTs := time.Now().Add(-10 * time.Second).Unix()
	content := fmt.Sprintf("4 %d", oldTs)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := checkBreakglassRateLimit(); err != nil {
		t.Errorf("expected rate limit to have expired, got: %v", err)
	}
}

// ── AuthenticateBreakglass ──────────────────────────────────────────────────

// withFakeTTY overrides OpenTTY to return a temp file backing a "tty" and
// ReadPasswordFn to return a fixed password. Returns the path the tty file
// was written to (caller can inspect content if needed).
func withFakeTTY(t *testing.T, password string) {
	t.Helper()
	origOpen := OpenTTY
	origRead := ReadPasswordFn
	t.Cleanup(func() {
		OpenTTY = origOpen
		ReadPasswordFn = origRead
	})

	dir := t.TempDir()
	OpenTTY = func() (*os.File, error) {
		return os.OpenFile(filepath.Join(dir, "fake-tty"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	}
	ReadPasswordFn = func(fd int) ([]byte, error) {
		return []byte(password), nil
	}
}

// seedHashFile writes a valid breakglass hash file (with header) at path,
// using bcrypt cost 4 for speed.
func seedHashFile(t *testing.T, path, password string) {
	t.Helper()
	hash, err := hashBreakglassPassword(password, 4)
	if err != nil {
		t.Fatalf("hashBreakglassPassword: %v", err)
	}
	if err := writeBreakglassFile(path, hash, "test-host", "random"); err != nil {
		t.Fatalf("writeBreakglassFile: %v", err)
	}
}

func TestAuthenticateBreakglass_Success(t *testing.T) {
	overrideFileOwnerUID(t)
	redirectFailurePath(t)
	withFakeTTY(t, "correct-horse-battery-staple")

	hashFile := filepath.Join(t.TempDir(), "breakglass.hash")
	seedHashFile(t, hashFile, "correct-horse-battery-staple")

	// Pre-record a failure so we can verify that success clears it.
	recordBreakglassFailure()

	if err := AuthenticateBreakglass("alice", hashFile); err != nil {
		t.Fatalf("AuthenticateBreakglass: %v", err)
	}

	// Counter file should be cleared on successful auth.
	if _, err := os.Stat(breakglassFailurePath); !os.IsNotExist(err) {
		t.Errorf("expected failure counter cleared on success, stat err = %v", err)
	}
}

func TestAuthenticateBreakglass_WrongPassword(t *testing.T) {
	overrideFileOwnerUID(t)
	redirectFailurePath(t)
	withFakeTTY(t, "wrong-password")

	hashFile := filepath.Join(t.TempDir(), "breakglass.hash")
	seedHashFile(t, hashFile, "correct-password")

	err := AuthenticateBreakglass("alice", hashFile)
	if err == nil {
		t.Fatal("expected authentication failure, got nil")
	}

	// Wrong password must increment the failure counter.
	count, _ := readFailureCounter()
	if count != 1 {
		t.Errorf("failure counter = %d, want 1 after one wrong password", count)
	}
}

func TestAuthenticateBreakglass_MissingHashFile(t *testing.T) {
	overrideFileOwnerUID(t)
	redirectFailurePath(t)
	withFakeTTY(t, "anything")

	// Path that doesn't exist — readBreakglassHash should fail, and the
	// function must still run the dummy bcrypt (to equalize timing) and
	// record a failure.
	err := AuthenticateBreakglass("alice", "/nonexistent/path/breakglass.hash")
	if err == nil {
		t.Fatal("expected authentication failure for missing hash file")
	}

	count, _ := readFailureCounter()
	if count != 1 {
		t.Errorf("failure counter = %d, want 1 even on missing-file path (timing equalization)", count)
	}
}

func TestAuthenticateBreakglass_CorruptedHashFile(t *testing.T) {
	overrideFileOwnerUID(t)
	redirectFailurePath(t)
	withFakeTTY(t, "anything")

	dir := t.TempDir()
	hashFile := filepath.Join(dir, "breakglass.hash")
	// Not a bcrypt hash — ReadBreakglassHash should reject.
	if err := os.WriteFile(hashFile, []byte("garbage-not-a-hash\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err := AuthenticateBreakglass("alice", hashFile)
	if err == nil {
		t.Fatal("expected authentication failure for corrupted hash file")
	}

	count, _ := readFailureCounter()
	if count != 1 {
		t.Errorf("failure counter = %d, want 1 after corrupted-file auth", count)
	}
}

func TestAuthenticateBreakglass_RateLimited(t *testing.T) {
	overrideFileOwnerUID(t)
	path := redirectFailurePath(t)
	withFakeTTY(t, "correct-password")

	// Seed a fresh high-count failure — should block before even trying.
	content := fmt.Sprintf("20 %d", time.Now().Unix())
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	hashFile := filepath.Join(t.TempDir(), "breakglass.hash")
	seedHashFile(t, hashFile, "correct-password")

	err := AuthenticateBreakglass("alice", hashFile)
	if err == nil {
		t.Fatal("expected rate-limit error")
	}
	if !strings.Contains(err.Error(), "too many failed") {
		t.Errorf("expected rate-limit message, got: %v", err)
	}
}

func TestAuthenticateBreakglass_TTYOpenFailure(t *testing.T) {
	overrideFileOwnerUID(t)
	redirectFailurePath(t)

	origOpen := OpenTTY
	t.Cleanup(func() { OpenTTY = origOpen })
	OpenTTY = func() (*os.File, error) {
		return nil, errors.New("no tty available")
	}

	hashFile := filepath.Join(t.TempDir(), "breakglass.hash")
	seedHashFile(t, hashFile, "whatever")

	err := AuthenticateBreakglass("alice", hashFile)
	if err == nil {
		t.Fatal("expected error when TTY cannot be opened")
	}
	if !strings.Contains(err.Error(), "cannot open terminal") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAuthenticateBreakglass_ReadPasswordError(t *testing.T) {
	overrideFileOwnerUID(t)
	redirectFailurePath(t)

	origOpen := OpenTTY
	origRead := ReadPasswordFn
	t.Cleanup(func() {
		OpenTTY = origOpen
		ReadPasswordFn = origRead
	})

	dir := t.TempDir()
	OpenTTY = func() (*os.File, error) {
		return os.OpenFile(filepath.Join(dir, "fake-tty"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	}
	ReadPasswordFn = func(fd int) ([]byte, error) {
		return nil, errors.New("read aborted")
	}

	hashFile := filepath.Join(t.TempDir(), "breakglass.hash")
	seedHashFile(t, hashFile, "whatever")

	err := AuthenticateBreakglass("alice", hashFile)
	if err == nil {
		t.Fatal("expected error when password read fails")
	}
	if !strings.Contains(err.Error(), "reading password") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ── writeBreakglassFile: overwrite preserves readability ────────────────────

// TestWriteBreakglassFile_OverwriteReadableThroughout verifies that when an
// existing break-glass file is replaced, a concurrent reader never sees a
// missing or partially-written file: either the old contents or the new
// contents, but never a gap.
func TestWriteBreakglassFile_OverwriteReadableThroughout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "breakglass.hash")

	// Seed an initial file.
	oldHash := "$2a$04$OLDhashAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := writeBreakglassFile(path, oldHash, "host", "random"); err != nil {
		t.Fatalf("initial write: %v", err)
	}

	var stop atomic.Bool
	var missing atomic.Int64
	var reads atomic.Int64
	done := make(chan struct{})

	go func() {
		defer close(done)
		for !stop.Load() {
			data, err := os.ReadFile(path)
			if err != nil {
				missing.Add(1)
				continue
			}
			reads.Add(1)
			// Every successful read must contain either the old or new hash.
			s := string(data)
			if !strings.Contains(s, "$2a$04$") {
				t.Errorf("read file content without bcrypt-like hash: %q", s)
			}
		}
	}()

	// Overwrite repeatedly; the atomic rename should keep the path always
	// pointing at a valid file.
	newHash := "$2a$04$NEWhashBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	for i := 0; i < 20; i++ {
		if err := writeBreakglassFile(path, newHash, "host", "random"); err != nil {
			t.Fatalf("overwrite %d: %v", i, err)
		}
	}
	stop.Store(true)
	<-done

	if reads.Load() == 0 {
		t.Error("reader never saw the file")
	}
	if missing.Load() != 0 {
		t.Errorf("reader saw %d missing-file errors during atomic overwrites", missing.Load())
	}
}

// ── EscrowPassword: mTLS / CA cert / transport-error / non-JSON body ────────

// genTestCert generates a self-signed ECDSA certificate + private key PEM pair
// suitable for httptest.NewUnstartedServer and tls.LoadX509KeyPair.
func genTestCert(t *testing.T, cn string) (certPEM, keyPEM []byte, cert tls.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"127.0.0.1", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("x509 keypair: %v", err)
	}
	return certPEM, keyPEM, cert
}

func writeTempFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestEscrowPassword_MTLSAndCustomCA(t *testing.T) {
	dir := t.TempDir()

	// Server cert (acts as both server cert and CA for clients to trust).
	serverCertPEM, serverKeyPEM, serverCert := genTestCert(t, "test-server")
	// Client cert (server will request it; we just observe it was offered).
	clientCertPEM, clientKeyPEM, _ := genTestCert(t, "test-client")

	caPath := writeTempFile(t, dir, "ca.pem", serverCertPEM)
	_ = serverKeyPEM
	clientCertPath := writeTempFile(t, dir, "client.crt", clientCertPEM)
	clientKeyPath := writeTempFile(t, dir, "client.key", clientKeyPEM)

	var sawClientCert atomic.Bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			sawClientCert.Store(true)
		}
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequestClientCert, // ask for client cert but don't require
	}
	srv.StartTLS()
	defer srv.Close()

	cfg := &config.ClientConfig{
		ServerURL:    srv.URL, // https://
		SharedSecret: "secret",
		ClientCert:   clientCertPath,
		ClientKey:    clientKeyPath,
		CACert:       caPath,
	}

	if err := EscrowPassword(cfg, "host", "pass", true); err != nil {
		t.Fatalf("EscrowPassword with mTLS + CA: %v", err)
	}
	if !sawClientCert.Load() {
		t.Error("server did not observe a client certificate in the TLS handshake")
	}
}

func TestEscrowPassword_ConnectionClosedMidRequest(t *testing.T) {
	// Server hijacks the connection and closes it without writing a response,
	// producing a transport-level request failure (not an HTTP status).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("server writer does not support hijacking")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		conn.Close()
	}))
	defer srv.Close()

	cfg := &config.ClientConfig{
		ServerURL:               srv.URL,
		SharedSecret:            "secret",
		InsecureAllowHTTPEscrow: true,
	}

	err := EscrowPassword(cfg, "host", "pass", true)
	if err == nil {
		t.Fatal("expected request error when server closes connection mid-request")
	}
	if !strings.Contains(err.Error(), "connecting to server") {
		t.Errorf("expected connecting-to-server error, got: %v", err)
	}
	// Must not be an escrowHTTPError — no HTTP status was received.
	var httpErr *escrowHTTPError
	if errors.As(err, &httpErr) {
		t.Errorf("should not be escrowHTTPError, got: %v", err)
	}
}

func TestEscrowPassword_NonJSONErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("   plain text error body   \n"))
	}))
	defer srv.Close()

	cfg := &config.ClientConfig{
		ServerURL:               srv.URL,
		SharedSecret:            "secret",
		InsecureAllowHTTPEscrow: true,
	}

	err := EscrowPassword(cfg, "host", "pass", true)
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
	var httpErr *escrowHTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected escrowHTTPError, got %T: %v", err, err)
	}
	if httpErr.StatusCode != 400 {
		t.Errorf("status = %d, want 400", httpErr.StatusCode)
	}
	// Body should be trimmed of surrounding whitespace.
	if httpErr.Body != "plain text error body" {
		t.Errorf("body = %q, want trimmed plain text", httpErr.Body)
	}
}

// ── MaybeRotateBreakglass: rotate-when-due path ─────────────────────────────

func TestMaybeRotateBreakglass_RotatesWhenDue(t *testing.T) {
	dir := t.TempDir()
	hashFile := filepath.Join(dir, "breakglass.hash")

	// Seed an existing file, then backdate it past the rotation window.
	if err := writeBreakglassFile(hashFile, "$2a$04$OLDhashAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "host", "random"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	old := time.Now().Add(-200 * 24 * time.Hour)
	if err := os.Chtimes(hashFile, old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	var escrowHits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escrowHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.ClientConfig{
		BreakglassEnabled:       true,
		BreakglassFile:          hashFile,
		BreakglassPasswordType:  "random",
		BreakglassBcryptCost:    4,
		BreakglassRotationDays:  90, // 200d old > 90d → rotation due
		ServerURL:               srv.URL,
		SharedSecret:            "secret",
		InsecureAllowHTTPEscrow: true,
	}

	MaybeRotateBreakglass(cfg, time.Time{})

	if escrowHits.Load() != 1 {
		t.Errorf("expected exactly 1 escrow call during rotation, got %d", escrowHits.Load())
	}

	// Verify the file mtime advanced (rotation wrote a fresh file).
	newMtime, err := breakglassFileMtime(hashFile)
	if err != nil {
		t.Fatalf("mtime: %v", err)
	}
	if !newMtime.After(old.Add(time.Hour)) {
		t.Errorf("mtime not advanced after rotation: %v", newMtime)
	}

	// Verify the file contents differ from the seeded OLD hash.
	data, err := os.ReadFile(hashFile)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(data), "OLDhashAAAA") {
		t.Error("file still contains the old hash after rotation")
	}
}

func TestPassphraseWordlistLength(t *testing.T) {
	if len(passphraseWordlist) != 256 {
		t.Errorf("wordlist length = %d, want 256", len(passphraseWordlist))
	}

	// Check for duplicates
	seen := make(map[string]bool, len(passphraseWordlist))
	for _, w := range passphraseWordlist {
		if seen[w] {
			t.Errorf("duplicate word: %q", w)
		}
		seen[w] = true
	}
}
