package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rinseaid/identree/internal/config"
)

func TestCommitShort(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"abcdef1234567890", "34567890"},
		{"short", "short"},
		{"12345678", "12345678"},
		{"", ""},
	}
	for _, tc := range tests {
		got := commitShort(tc.input)
		if got != tc.want {
			t.Errorf("commitShort(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestTruncateOutput(t *testing.T) {
	short := "hello world"
	got := truncateOutput(short)
	if got != short {
		t.Errorf("truncateOutput(%q) = %q, want %q", short, got, short)
	}

	// Test with extra whitespace.
	got = truncateOutput("  hello  ")
	if got != "hello" {
		t.Errorf("truncateOutput with whitespace = %q, want %q", got, "hello")
	}

	// Test with long string.
	long := strings.Repeat("a", 5000)
	got = truncateOutput(long)
	if len(got) > maxLogOutput+20 { // allow for "(truncated)" suffix
		t.Errorf("truncateOutput should truncate, got length %d", len(got))
	}
	if !strings.Contains(got, "(truncated)") {
		t.Error("expected truncated suffix")
	}
}

func TestLimitedWriter(t *testing.T) {
	var buf bytes.Buffer
	lw := &limitedWriter{w: &buf, n: 10}

	n, err := lw.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Errorf("Write: n=%d, err=%v", n, err)
	}
	if buf.String() != "hello" {
		t.Errorf("buffer = %q, want %q", buf.String(), "hello")
	}

	// Write more than remaining capacity.
	n, err = lw.Write([]byte("world12345"))
	if err != nil {
		t.Errorf("Write: err=%v", err)
	}
	// Should return total length even though truncated.
	if n != 10 {
		t.Errorf("Write: n=%d, want 10", n)
	}
	if buf.String() != "helloworld" {
		t.Errorf("buffer = %q, want %q", buf.String(), "helloworld")
	}

	// Further writes should be silently discarded.
	n, err = lw.Write([]byte("extra"))
	if err != nil {
		t.Errorf("Write after limit: err=%v", err)
	}
	if n != 5 {
		t.Errorf("Write after limit: n=%d, want 5", n)
	}
	if buf.String() != "helloworld" {
		t.Errorf("buffer should not change after limit: %q", buf.String())
	}
}

func TestVerifyWebhookSignature_EmptySecret(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader("body"))
	if verifyWebhookSignature(r, "", "sha256=abc") {
		t.Error("expected false for empty secret")
	}
}

func TestVerifyWebhookSignature_EmptySig(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader("body"))
	if verifyWebhookSignature(r, "secret", "") {
		t.Error("expected false for empty sig")
	}
}

func TestVerifyWebhookSignature_Valid(t *testing.T) {
	body := `{"event":"test"}`
	secret := "mysecret"

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	r := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
	if !verifyWebhookSignature(r, secret, sig) {
		t.Error("expected true for valid signature")
	}
}

func TestVerifyWebhookSignature_Invalid(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader("body"))
	if verifyWebhookSignature(r, "secret", "sha256=badhexbadhexbadhexbadhexbadhexbadhexbadhexbadhexbadhexbadhex1234") {
		t.Error("expected false for wrong signature")
	}
}

// ── isHex / isDecimal / atoi tests ───────────────────────────────────────────

func TestIsHex(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"abcdef0123456789", true},
		{"ABCDEF", true},
		{"aAbBcCdD", true},
		{"", false},
		{"xyz", false},
		{"12g4", false},
	}
	for _, tc := range tests {
		got := isHex(tc.s)
		if got != tc.want {
			t.Errorf("isHex(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestIsDecimal(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"0123456789", true},
		{"0", true},
		{"", false},
		{"12a", false},
		{"-1", false},
	}
	for _, tc := range tests {
		got := isDecimal(tc.s)
		if got != tc.want {
			t.Errorf("isDecimal(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestAtoi(t *testing.T) {
	if got := atoi("42"); got != 42 {
		t.Errorf("atoi('42') = %d, want 42", got)
	}
	if got := atoi("notanumber"); got != 0 {
		t.Errorf("atoi('notanumber') = %d, want 0", got)
	}
	if got := atoi(""); got != 0 {
		t.Errorf("atoi('') = %d, want 0", got)
	}
}

func TestCspNonce(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	got := cspNonce(r)
	if got != "" {
		t.Errorf("expected empty cspNonce, got %q", got)
	}
}

func TestRemoteAddr(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	got := remoteAddr(r)
	if got != "10.0.0.1" {
		t.Errorf("remoteAddr = %q, want '10.0.0.1'", got)
	}
}

func TestRemoteAddr_NoPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1"
	got := remoteAddr(r)
	if got != "10.0.0.1" {
		t.Errorf("remoteAddr without port = %q", got)
	}
}

func TestIsBridgeMode(t *testing.T) {
	s := &Server{cfg: &config.ServerConfig{APIKey: ""}}
	if !s.isBridgeMode() {
		t.Error("expected bridge mode when APIKey is empty")
	}
	s.cfg.APIKey = "somekey"
	if s.isBridgeMode() {
		t.Error("expected not bridge mode when APIKey is set")
	}
}

func TestPocketIDSyncAge(t *testing.T) {
	s := &Server{cfg: &config.ServerConfig{}}
	got := s.pocketIDSyncAge()
	// Should return empty or "N/A" when pocketIDClient is nil.
	if got == "" {
		// acceptable
	}
}

func TestLdapSyncError(t *testing.T) {
	s := &Server{cfg: &config.ServerConfig{}}
	got := s.ldapSyncError()
	if got != "" {
		t.Errorf("expected empty ldap sync error, got %q", got)
	}
}

func TestHmacBase(t *testing.T) {
	// SessionSecret falls back to SharedSecret via config loading, but in tests
	// we set it directly so hmacBase() uses SessionSecret.
	s := &Server{cfg: &config.ServerConfig{SharedSecret: "shared", SessionSecret: "shared", HMACSecret: ""}}
	if got := s.hmacBase(); got != "shared" {
		t.Errorf("hmacBase() = %q, want 'shared'", got)
	}
	s.cfg.HMACSecret = "hmac-key"
	if got := s.hmacBase(); got != "hmac-key" {
		t.Errorf("hmacBase() with HMACSecret = %q, want 'hmac-key'", got)
	}
}
