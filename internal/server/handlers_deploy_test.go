package server

import (
	"context"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/policy"
	gossh "golang.org/x/crypto/ssh"
)

// ── deployJob tests ──────────────────────────────────────────────────────────

func TestDeployJob_AppendAndSnapshot(t *testing.T) {
	j := newDeployJob("test-id", "web01", "root", "admin")

	j.appendOutput([]byte("line 1\n"))
	j.appendLine("line 2")

	data, done, failed := j.snapshot()
	if done {
		t.Error("expected not done")
	}
	if failed {
		t.Error("expected not failed")
	}
	if string(data) != "line 1\nline 2\n" {
		t.Errorf("unexpected output: %q", string(data))
	}
}

func TestDeployJob_Finish(t *testing.T) {
	j := newDeployJob("test-id", "web01", "root", "admin")
	j.appendLine("some output")
	j.finish(false)

	_, done, failed := j.snapshot()
	if !done {
		t.Error("expected done")
	}
	if failed {
		t.Error("expected not failed")
	}
}

func TestDeployJob_FinishFailed(t *testing.T) {
	j := newDeployJob("test-id", "web01", "root", "admin")
	j.finish(true)

	_, done, failed := j.snapshot()
	if !done {
		t.Error("expected done")
	}
	if !failed {
		t.Error("expected failed")
	}
}

func TestDeployJob_DoubleFinish(t *testing.T) {
	j := newDeployJob("test-id", "web01", "root", "admin")
	j.finish(false)
	// Second finish should not panic.
	j.finish(true)

	_, done, _ := j.snapshot()
	if !done {
		t.Error("expected done")
	}
}

func TestDeployJob_AppendAfterFinish(t *testing.T) {
	j := newDeployJob("test-id", "web01", "root", "admin")
	j.appendLine("before")
	j.finish(false)
	// Append after finish should be silently ignored.
	j.appendLine("after")

	data, _, _ := j.snapshot()
	if string(data) != "before\n" {
		t.Errorf("unexpected output after finish: %q", string(data))
	}
}

// ── deployRateLimiter tests ──────────────────────────────────────────────────

func TestDeployRateLimiter_FirstRequestAllowed(t *testing.T) {
	rl := newDeployRateLimiter()
	if !rl.allow("10.0.0.1") {
		t.Error("first request should be allowed")
	}
}

func TestDeployRateLimiter_SecondRequestBlocked(t *testing.T) {
	rl := newDeployRateLimiter()
	rl.allow("10.0.0.1")
	if rl.allow("10.0.0.1") {
		t.Error("second request within cooldown should be blocked")
	}
}

func TestDeployRateLimiter_DifferentIPAllowed(t *testing.T) {
	rl := newDeployRateLimiter()
	rl.allow("10.0.0.1")
	if !rl.allow("10.0.0.2") {
		t.Error("different IP should be allowed")
	}
}

// newDeployTestServer builds a minimal server for deploy handler tests.
func newDeployTestServer(t *testing.T, secret string) *Server {
	t.Helper()
	store := newTestStore(t, 5*time.Minute, 10*time.Minute)
	return &Server{
		cfg: &config.ServerConfig{
			SharedSecret:  secret,
			SessionSecret: secret,
			ChallengeTTL:  5 * time.Minute,
		},
		store:          store,
		hostRegistry:   NewHostRegistry(""),
		authFailRL:     newAuthFailTracker(),
		mutationRL:     newMutationRateLimiter(),
		sseBroadcaster: noopBroadcaster{},
		policyEngine:   policy.NewEngine(nil),
		notifyCfg:      &notify.NotificationConfig{},
		revokedNonces:  make(map[string]time.Time),
		deployJobs:     make(map[string]*deployJob),
		deployRL:       newDeployRateLimiter(),
		stopCh:         make(chan struct{}),
	}
}

// ── handleDeployPubkey tests ─────────────────────────────────────────────────

func TestHandleDeployPubkey_MethodNotAllowed(t *testing.T) {
	s := newDeployTestServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/api/deploy/pubkey", nil)
	w := httptest.NewRecorder()
	s.handleDeployPubkey(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleDeployPubkey_NoAuth(t *testing.T) {
	s := newDeployTestServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodPost, "/api/deploy/pubkey", nil)
	w := httptest.NewRecorder()
	s.handleDeployPubkey(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ── handleDeployUsers tests ──────────────────────────────────────────────────

func TestHandleDeployUsers_MethodNotAllowed(t *testing.T) {
	s := newDeployTestServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodPost, "/api/deploy/users", nil)
	w := httptest.NewRecorder()
	s.handleDeployUsers(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleDeployUsers_NoAuth(t *testing.T) {
	s := newDeployTestServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/api/deploy/users", nil)
	w := httptest.NewRecorder()
	s.handleDeployUsers(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ── handleDeploy tests ───────────────────────────────────────────────────────

func TestHandleDeploy_MethodNotAllowed(t *testing.T) {
	s := newDeployTestServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/api/deploy", nil)
	w := httptest.NewRecorder()
	s.handleDeploy(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleDeploy_NoAuth(t *testing.T) {
	s := newDeployTestServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodPost, "/api/deploy", nil)
	w := httptest.NewRecorder()
	s.handleDeploy(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ── handleRemoveHost tests ───────────────────────────────────────────────────

func TestHandleRemoveHost_MethodNotAllowed(t *testing.T) {
	s := newDeployTestServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/api/hosts/remove", nil)
	w := httptest.NewRecorder()
	s.handleRemoveHost(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── handleDeployStream tests ─────────────────────────────────────────────────

func TestHandleDeployStream_NoAuth(t *testing.T) {
	s := newDeployTestServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/api/deploy/stream/test-id", nil)
	w := httptest.NewRecorder()
	s.handleDeployStream(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ── handleRemoveDeploy tests ─────────────────────────────────────────────────

func TestHandleRemoveDeploy_MethodNotAllowed(t *testing.T) {
	s := newDeployTestServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/api/deploy/remove", nil)
	w := httptest.NewRecorder()
	s.handleRemoveDeploy(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// buildDeployAdminReq returns a POST request to path with a JSON body, a
// valid admin session cookie, and matching CSRF headers.
func buildDeployAdminReq(t *testing.T, secret, path string, body any) *http.Request {
	t.Helper()
	ts := time.Now().Unix()
	csrfTs := fmt.Sprintf("%d", ts)
	csrfToken := computeCSRFToken(secret, "deployadmin", csrfTs)
	sessionCookie := makeCookie(secret, "deployadmin", "admin", ts)

	var buf *bytes.Buffer
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		buf = bytes.NewBuffer(data)
	}
	var r *http.Request
	if buf != nil {
		r = httptest.NewRequest(http.MethodPost, path, buf)
	} else {
		r = httptest.NewRequest(http.MethodPost, path, nil)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrfToken)
	r.Header.Set("X-CSRF-Ts", csrfTs)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
	r.RemoteAddr = "10.0.0.5:33333"
	return r
}

// ── handleDeployUsers — admin branch without pocketIDClient returns "[]" ────

func TestHandleDeployUsers_AdminNoPocketIDClient(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)
	// pocketIDClient is nil for this minimal server; handler returns empty list.
	ts := time.Now().Unix()
	sessionCookie := makeCookie(secret, "deployadmin", "admin", ts)
	r := httptest.NewRequest(http.MethodGet, "/api/deploy/users", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
	w := httptest.NewRecorder()
	s.handleDeployUsers(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if got := strings.TrimSpace(w.Body.String()); got != "[]" {
		t.Errorf("expected empty JSON array, got %q", got)
	}
}

func TestHandleDeployUsers_NonAdminRejected(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)
	ts := time.Now().Unix()
	sessionCookie := makeCookie(secret, "bob", "user", ts)
	r := httptest.NewRequest(http.MethodGet, "/api/deploy/users", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
	w := httptest.NewRecorder()
	s.handleDeployUsers(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for non-admin, got %d", w.Code)
	}
}

// ── handleDeploy — validation branches (admin auth present) ─────────────────

func TestHandleDeploy_WrongContentType(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)
	r := buildDeployAdminReq(t, secret, "/api/deploy", nil)
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	s.handleDeploy(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", w.Code)
	}
}

func TestHandleDeploy_InvalidJSON(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)
	r := buildDeployAdminReq(t, secret, "/api/deploy", nil)
	r.Body = io.NopCloser(bytes.NewBufferString("{not json"))
	w := httptest.NewRecorder()
	s.handleDeploy(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleDeploy_MissingHostname(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)
	r := buildDeployAdminReq(t, secret, "/api/deploy", map[string]any{
		"hostname":    "",
		"private_key": "whatever",
	})
	w := httptest.NewRecorder()
	s.handleDeploy(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d (body=%q)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "hostname") {
		t.Errorf("expected hostname error, got %q", w.Body.String())
	}
}

func TestHandleDeploy_InvalidHostname(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)
	r := buildDeployAdminReq(t, secret, "/api/deploy", map[string]any{
		"hostname":    "bad host with spaces",
		"private_key": "whatever",
	})
	w := httptest.NewRecorder()
	s.handleDeploy(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleDeploy_InvalidPort(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)
	r := buildDeployAdminReq(t, secret, "/api/deploy", map[string]any{
		"hostname":    "web01.example.com",
		"port":        70000,
		"private_key": "whatever",
	})
	w := httptest.NewRecorder()
	s.handleDeploy(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleDeploy_MissingPrivateKey(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)
	r := buildDeployAdminReq(t, secret, "/api/deploy", map[string]any{
		"hostname": "web01.example.com",
	})
	w := httptest.NewRecorder()
	s.handleDeploy(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "private_key") {
		t.Errorf("expected private_key error, got %q", w.Body.String())
	}
}

func TestHandleDeploy_InvalidPrivateKey(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)
	r := buildDeployAdminReq(t, secret, "/api/deploy", map[string]any{
		"hostname":    "web01.example.com",
		"private_key": "not-a-real-ssh-key",
	})
	w := httptest.NewRecorder()
	s.handleDeploy(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid private key") {
		t.Errorf("expected 'invalid private key' body, got %q", w.Body.String())
	}
}

func TestHandleDeploy_RateLimitSecondRequest(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)

	// First call exhausts the per-IP rate-limiter slot (validation error
	// still consumes the budget because the allow-check fires first).
	r1 := buildDeployAdminReq(t, secret, "/api/deploy", map[string]any{"hostname": ""})
	w1 := httptest.NewRecorder()
	s.handleDeploy(w1, r1)

	// Second call from same IP should be rejected with 429.
	r2 := buildDeployAdminReq(t, secret, "/api/deploy", map[string]any{"hostname": ""})
	w2 := httptest.NewRecorder()
	s.handleDeploy(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 on second request, got %d", w2.Code)
	}
}

// ── handleRemoveHost — happy path + validation ──────────────────────────────

func TestHandleRemoveHost_WrongContentType(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)
	r := buildDeployAdminReq(t, secret, "/api/hosts/remove-host", nil)
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	s.handleRemoveHost(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", w.Code)
	}
}

func TestHandleRemoveHost_InvalidJSON(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)
	r := buildDeployAdminReq(t, secret, "/api/hosts/remove-host", nil)
	r.Body = io.NopCloser(bytes.NewBufferString("not json"))
	w := httptest.NewRecorder()
	s.handleRemoveHost(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleRemoveHost_InvalidHostname(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)
	r := buildDeployAdminReq(t, secret, "/api/hosts/remove-host", map[string]any{"hostname": "bad host!"})
	w := httptest.NewRecorder()
	s.handleRemoveHost(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleRemoveHost_Success(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)

	// Seed the store with action history referencing the host so there is
	// observable state to remove.
	s.store.LogAction(context.Background(), "alice", challpkg.ActionDeployed, "web01.example.com", "", "deployadmin")

	r := buildDeployAdminReq(t, secret, "/api/hosts/remove-host", map[string]any{"hostname": "web01.example.com"})
	w := httptest.NewRecorder()
	s.handleRemoveHost(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"ok"`) {
		t.Errorf("expected ok status in body, got %q", w.Body.String())
	}

	// Verify a remove action was logged — observable side effect of success.
	found := false
	for _, entry := range s.store.AllActionHistory(context.Background(), 10000) {
		if entry.Action == challpkg.ActionRemovedHost && entry.Hostname == "web01.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected an ActionRemovedHost entry for web01.example.com in action history")
	}
}

// ── handleRemoveDeploy — validation branches (admin auth present) ───────────

func TestHandleRemoveDeploy_WrongContentType(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)
	r := buildDeployAdminReq(t, secret, "/api/deploy/remove", nil)
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	s.handleRemoveDeploy(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", w.Code)
	}
}

func TestHandleRemoveDeploy_InvalidJSON(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)
	r := buildDeployAdminReq(t, secret, "/api/deploy/remove", nil)
	r.Body = io.NopCloser(bytes.NewBufferString("garbage"))
	w := httptest.NewRecorder()
	s.handleRemoveDeploy(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleRemoveDeploy_MissingHostname(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)
	r := buildDeployAdminReq(t, secret, "/api/deploy/remove", map[string]any{"hostname": ""})
	w := httptest.NewRecorder()
	s.handleRemoveDeploy(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleRemoveDeploy_InvalidPort(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)
	r := buildDeployAdminReq(t, secret, "/api/deploy/remove", map[string]any{
		"hostname":    "web01.example.com",
		"port":        70000,
		"private_key": "stub",
	})
	w := httptest.NewRecorder()
	s.handleRemoveDeploy(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleRemoveDeploy_InvalidPrivateKey(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)
	r := buildDeployAdminReq(t, secret, "/api/deploy/remove", map[string]any{
		"hostname":    "web01.example.com",
		"private_key": "not-a-real-key",
	})
	w := httptest.NewRecorder()
	s.handleRemoveDeploy(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// generateTestSSHKey returns a PEM-encoded ed25519 private key for test use.
func generateTestSSHKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	pemBlock, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	return string(pem.EncodeToMemory(pemBlock))
}

// ── handleDeploy — non-admin rejected ───────────────────────────────────────

func TestHandleDeploy_NonAdminRejected(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)

	ts := time.Now().Unix()
	csrfTs := fmt.Sprintf("%d", ts)
	csrfToken := computeCSRFToken(secret, "bob", csrfTs)
	sessionCookie := makeCookie(secret, "bob", "user", ts)

	body, _ := json.Marshal(map[string]any{
		"hostname":    "web01.example.com",
		"private_key": generateTestSSHKey(t),
	})

	r := httptest.NewRequest(http.MethodPost, "/api/deploy", bytes.NewBuffer(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrfToken)
	r.Header.Set("X-CSRF-Ts", csrfTs)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
	r.RemoteAddr = "10.0.0.5:33333"

	w := httptest.NewRecorder()
	s.handleDeploy(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for non-admin, got %d", w.Code)
	}
}

// ── handleRemoveDeploy — non-admin rejected ─────────────────────────────────

func TestHandleRemoveDeploy_NonAdminRejected(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)

	ts := time.Now().Unix()
	csrfTs := fmt.Sprintf("%d", ts)
	csrfToken := computeCSRFToken(secret, "bob", csrfTs)
	sessionCookie := makeCookie(secret, "bob", "user", ts)

	body, _ := json.Marshal(map[string]any{
		"hostname":    "web01.example.com",
		"private_key": generateTestSSHKey(t),
	})

	r := httptest.NewRequest(http.MethodPost, "/api/deploy/remove", bytes.NewBuffer(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrfToken)
	r.Header.Set("X-CSRF-Ts", csrfTs)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
	r.RemoteAddr = "10.0.0.5:33333"

	w := httptest.NewRecorder()
	s.handleRemoveDeploy(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for non-admin, got %d", w.Code)
	}
}

// ── handleRemoveDeploy — missing private key ────────────────────────────────

func TestHandleRemoveDeploy_MissingPrivateKey(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)
	r := buildDeployAdminReq(t, secret, "/api/deploy/remove", map[string]any{
		"hostname": "web01.example.com",
	})
	w := httptest.NewRecorder()
	s.handleRemoveDeploy(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "private_key") {
		t.Errorf("expected error mentioning private_key, got %q", w.Body.String())
	}
}

// ── handleDeployStream — unknown job ID ─────────────────────────────────────

func TestHandleDeployStream_UnknownJob(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)

	ts := time.Now().Unix()
	sessionCookie := makeCookie(secret, "deployadmin", "admin", ts)
	r := httptest.NewRequest(http.MethodGet, "/api/deploy/stream/deadbeef01234567deadbeef01234567", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
	w := httptest.NewRecorder()
	s.handleDeployStream(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown job, got %d", w.Code)
	}
}

// ── handleDeployStream — invalid (non-hex) job ID ───────────────────────────

func TestHandleDeployStream_InvalidJobID(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)

	ts := time.Now().Unix()
	sessionCookie := makeCookie(secret, "deployadmin", "admin", ts)
	r := httptest.NewRequest(http.MethodGet, "/api/deploy/stream/not-hex-value!", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
	w := httptest.NewRecorder()
	s.handleDeployStream(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-hex job ID, got %d", w.Code)
	}
}

// ── handleDeployPubkey — success with valid key ─────────────────────────────

func TestHandleDeployPubkey_Success(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)

	keyPEM := generateTestSSHKey(t)
	r := buildDeployAdminReq(t, secret, "/api/deploy/pubkey", map[string]any{
		"private_key": keyPEM,
	})
	w := httptest.NewRecorder()
	s.handleDeployPubkey(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["type"] == "" {
		t.Error("expected non-empty key type in response")
	}
	if resp["fingerprint"] == "" {
		t.Error("expected non-empty fingerprint in response")
	}
	// ed25519 key type should be "ssh-ed25519"
	if resp["type"] != "ssh-ed25519" {
		t.Errorf("expected type ssh-ed25519, got %q", resp["type"])
	}
	// Fingerprint should start with "SHA256:"
	if !strings.HasPrefix(resp["fingerprint"], "SHA256:") {
		t.Errorf("expected fingerprint starting with SHA256:, got %q", resp["fingerprint"])
	}
}

// ── handleDeployPubkey — invalid key body ───────────────────────────────────

func TestHandleDeployPubkey_InvalidKey(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)

	r := buildDeployAdminReq(t, secret, "/api/deploy/pubkey", map[string]any{
		"private_key": "this is not a real key",
	})
	w := httptest.NewRecorder()
	s.handleDeployPubkey(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ── privateIP unit tests ────────────────────────────────────────────────────

func TestPrivateIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"100.64.0.1", true},     // CGN range
		{"169.254.1.1", false},   // link-local is not in the explicit CIDR list (only IsLoopback)
		{"8.8.8.8", false},       // public IP
		{"1.1.1.1", false},       // public IP
		{"fc00::1", true},        // ULA IPv6
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			got := privateIP(net.ParseIP(tc.ip))
			if got != tc.want {
				t.Errorf("privateIP(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestPrivateIP_Nil(t *testing.T) {
	if privateIP(nil) {
		t.Error("privateIP(nil) should return false")
	}
}

// ── handleRemoveHost — non-admin rejected ───────────────────────────────────

func TestHandleRemoveHost_NonAdminRejected(t *testing.T) {
	const secret = "test-secret-abcdef"
	s := newDeployTestServer(t, secret)

	ts := time.Now().Unix()
	csrfTs := fmt.Sprintf("%d", ts)
	csrfToken := computeCSRFToken(secret, "bob", csrfTs)
	sessionCookie := makeCookie(secret, "bob", "user", ts)

	body, _ := json.Marshal(map[string]any{
		"hostname": "web01.example.com",
	})
	r := httptest.NewRequest(http.MethodPost, "/api/hosts/remove-host", bytes.NewBuffer(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrfToken)
	r.Header.Set("X-CSRF-Ts", csrfTs)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
	r.RemoteAddr = "10.0.0.5:33333"

	w := httptest.NewRecorder()
	s.handleRemoveHost(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for non-admin, got %d", w.Code)
	}
}

// ── clientIP tests ──────────────────────────────────────────────────────────

func TestClientIP_DirectPublicIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.50:12345"
	got := clientIP(r)
	if got != "203.0.113.50" {
		t.Errorf("expected 203.0.113.50, got %q", got)
	}
}

func TestClientIP_ProxiedPrivateIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")
	// Rightmost entry is taken when RemoteAddr is private.
	got := clientIP(r)
	if got != "10.0.0.1" {
		t.Errorf("expected rightmost XFF entry 10.0.0.1, got %q", got)
	}
}

func TestClientIP_NoXFF(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	// No XFF header; should return the RemoteAddr host portion.
	got := clientIP(r)
	if got != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %q", got)
	}
}
