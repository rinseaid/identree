package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/policy"
)

// ── deployJob tests ──────────────────────────────────────────────────────────

func TestDeployJob_AppendAndSnapshot(t *testing.T) {
	j := newDeployJob("test-id", "web01", "root", "admin")

	j.appendOutput([]byte("line 1\n"))
	j.appendLine("line 2")

	data, done, failed, _ := j.snapshot()
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

	_, done, failed, _ := j.snapshot()
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

	_, done, failed, _ := j.snapshot()
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

	_, done, _, _ := j.snapshot()
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

	data, _, _, _ := j.snapshot()
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
