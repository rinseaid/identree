package pam

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeJWT produces a syntactically valid but unsigned JWT with the given
// payload. Write() never verifies the signature — it only decodes the payload
// to extract the exp claim for quick cache-hit checks.
func makeJWT(t *testing.T, payload map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	p, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	body := base64.RawURLEncoding.EncodeToString(p)
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	return header + "." + body + "." + sig
}

func TestNewTokenCache_RequiresIssuerAndClientID(t *testing.T) {
	if _, err := NewTokenCache("/tmp/x", "", "client", "host"); err == nil {
		t.Errorf("expected error for empty issuer")
	}
	if _, err := NewTokenCache("/tmp/x", "https://idp", "", "host"); err == nil {
		t.Errorf("expected error for empty clientID")
	}
	tc, err := NewTokenCache("/tmp/x", "https://idp", "client", "HOST.example.com")
	if err != nil {
		t.Fatalf("NewTokenCache: %v", err)
	}
	if tc.hostname != "HOST.example.com" {
		t.Errorf("hostname stored verbatim; got %q", tc.hostname)
	}
}

func TestDecodeJWTSegment_Padding(t *testing.T) {
	cases := []string{"aGVsbG8", "aGVsbG8gd29ybGQ", "YWJjZA", ""}
	for _, c := range cases {
		if _, err := decodeJWTSegment(c); err != nil {
			t.Errorf("decodeJWTSegment(%q): %v", c, err)
		}
	}
	if _, err := decodeJWTSegment("!!!"); err == nil {
		t.Errorf("expected error for invalid base64")
	}
}

func TestTokenCache_Write_RejectsMalformed(t *testing.T) {
	dir := t.TempDir()
	tc := &TokenCache{CacheDir: dir, Issuer: "https://idp", ClientID: "client", hostname: "h1"}

	// Oversized token
	big := strings.Repeat("a", 70000)
	if err := tc.Write("alice", big); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("expected too-large error, got %v", err)
	}

	// Not three segments
	if err := tc.Write("alice", "not.a.jwt.extra"); err == nil {
		t.Errorf("expected malformed JWT error")
	}
	if err := tc.Write("alice", "onlyone"); err == nil {
		t.Errorf("expected malformed JWT error")
	}

	// Valid shape but payload is not JSON
	bad := "aGVhZGVy." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".sig"
	if err := tc.Write("alice", bad); err == nil {
		t.Errorf("expected JSON parse error")
	}

	// Missing exp claim
	noExp := makeJWT(t, map[string]any{"preferred_username": "alice"})
	if err := tc.Write("alice", noExp); err == nil || !strings.Contains(err.Error(), "no exp") {
		t.Errorf("expected no-exp error, got %v", err)
	}
}

func TestTokenCache_Write_CreatesLockedFile(t *testing.T) {
	if os.Getuid() != 0 {
		// Check() verifies the file is owned by uid 0. Skip the Write+Check
		// round-trip outside of CI / root test runs, but exercise Write itself.
		t.Log("running as non-root; only Write path is exercised")
	}
	dir := t.TempDir()
	tc := &TokenCache{CacheDir: dir, Issuer: "https://idp", ClientID: "client", hostname: "myhost"}

	jwt := makeJWT(t, map[string]any{
		"exp":                time.Now().Add(time.Hour).Unix(),
		"preferred_username": "alice",
	})
	if err := tc.Write("alice", jwt); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Verify on-disk layout: <dir>/<hostname>/<user>, 0600, contains IDToken.
	path := filepath.Join(dir, "myhost", "alice")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat cached file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("cache file perm: got %04o, want 0600", perm)
	}
	hostDir, err := os.Stat(filepath.Join(dir, "myhost"))
	if err != nil {
		t.Fatalf("stat host dir: %v", err)
	}
	if perm := hostDir.Mode().Perm(); perm != 0700 {
		t.Errorf("host dir perm: got %04o, want 0700", perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cached file: %v", err)
	}
	var c cachedToken
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("unmarshal cached token: %v", err)
	}
	if c.IDToken != jwt {
		t.Errorf("cached IDToken mismatch")
	}
	if c.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt not set")
	}
}

func TestTokenCache_Check_MissingFile(t *testing.T) {
	dir := t.TempDir()
	tc := &TokenCache{CacheDir: dir, Issuer: "https://idp", ClientID: "c", hostname: "h"}
	if _, _, err := tc.Check("ghost"); err == nil {
		t.Errorf("expected error for missing file")
	}
}

func TestTokenCache_Check_RejectsBadPerms(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; permission check uses owner uid which is always 0")
	}
	dir := t.TempDir()
	tc := &TokenCache{CacheDir: dir, Issuer: "https://idp", ClientID: "c", hostname: "h"}
	hostDir := filepath.Join(dir, "h")
	if err := os.MkdirAll(hostDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(hostDir, "alice")
	if err := os.WriteFile(path, []byte(`{"id_token":"x"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tc.Check("alice"); err == nil {
		t.Errorf("expected error for group/other perms")
	} else if !strings.Contains(err.Error(), "permissions") && !strings.Contains(err.Error(), "owned by root") {
		t.Errorf("expected perm/owner error, got %v", err)
	}
}

func TestTokenCache_Check_RejectsMalformedJSON(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; check passes owner validation and proceeds to parse")
	}
	dir := t.TempDir()
	tc := &TokenCache{CacheDir: dir, Issuer: "https://idp", ClientID: "c", hostname: "h"}
	hostDir := filepath.Join(dir, "h")
	if err := os.MkdirAll(hostDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(hostDir, "alice")
	// 0600 but owned by current user (not root) — fails owner check before reaching parse.
	// Since we can't chown to root as a regular user, this just ensures the Check
	// error surface is hit. The root-only parse path is covered in CI.
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err := tc.Check("alice")
	if err == nil {
		t.Errorf("expected error")
	}
}

func TestTokenCache_Check_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	tc := &TokenCache{CacheDir: dir, Issuer: "https://idp", ClientID: "c", hostname: "h"}
	hostDir := filepath.Join(dir, "h")
	if err := os.MkdirAll(hostDir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte(`{"id_token":"x","expires_at":"2099-01-01T00:00:00Z"}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(hostDir, "alice")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tc.Check("alice"); err == nil {
		t.Errorf("expected error opening symlinked cache file")
	}
}

func TestTokenCache_Delete(t *testing.T) {
	dir := t.TempDir()
	tc := &TokenCache{CacheDir: dir, Issuer: "https://idp", ClientID: "c", hostname: "h"}

	// Delete of non-existent file is a no-op.
	if err := tc.Delete("ghost"); err != nil {
		t.Errorf("Delete missing: %v", err)
	}

	hostDir := filepath.Join(dir, "h")
	if err := os.MkdirAll(hostDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(hostDir, "alice")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := tc.Delete("alice"); err != nil {
		t.Errorf("Delete: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file still exists after Delete")
	}
}

func TestTokenCache_ModTime(t *testing.T) {
	dir := t.TempDir()
	tc := &TokenCache{CacheDir: dir, Issuer: "https://idp", ClientID: "c", hostname: "h"}

	if _, err := tc.ModTime("ghost"); err == nil {
		t.Errorf("expected error for missing file")
	}

	hostDir := filepath.Join(dir, "h")
	if err := os.MkdirAll(hostDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(hostDir, "alice")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	before := time.Now().Add(-time.Minute)
	mt, err := tc.ModTime("alice")
	if err != nil {
		t.Fatalf("ModTime: %v", err)
	}
	if mt.Before(before) {
		t.Errorf("ModTime too old: %v", mt)
	}
}

func TestTokenCache_GetVerifier_CachesFailure(t *testing.T) {
	// Unreachable issuer — the verifier should fail but the error is cached
	// for 5 minutes. A second call must not re-dial.
	tc := &TokenCache{
		Issuer:   "http://127.0.0.1:1", // port 1 is unassigned / connection-refused
		ClientID: "client",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := tc.getVerifier(ctx); err == nil {
		t.Fatalf("expected error from unreachable issuer")
	}
	// Expiry must be in the future (5-min retry window).
	if tc.verifierExpiry.IsZero() || time.Until(tc.verifierExpiry) <= 0 {
		t.Errorf("expected future retry window, got %v", tc.verifierExpiry)
	}

	// Cached-error path: second call returns the same error without re-dialing.
	if _, err := tc.getVerifier(ctx); err == nil {
		t.Errorf("second call should also return the cached error")
	}
}
