package breakglass

import (
	"os"
	"path/filepath"
	"testing"

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
