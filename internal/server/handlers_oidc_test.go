package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/policy"
)

// newOIDCTestServer builds a minimal *Server for OIDC handler tests.
func newOIDCTestServer(t *testing.T, secret string) *Server {
	t.Helper()
	store := challpkg.NewChallengeStore(5*time.Minute, 10*time.Minute, t.TempDir())
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
		loginRL:        newLoginRateLimiter(),
		callbackRL:     newLoginRateLimiter(),
		sseBroadcaster: noopBroadcaster{},
		policyEngine:   policy.NewEngine(nil),
		notifyCfg:      &notify.NotificationConfig{},
		revokedNonces:  make(map[string]time.Time),
	}
}

// ── handleOIDCCallback tests ─────────────────────────────────────────────────

func TestHandleOIDCCallback_MethodNotAllowed(t *testing.T) {
	s := newOIDCTestServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodPost, "/callback", nil)
	w := httptest.NewRecorder()
	s.handleOIDCCallback(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleOIDCCallback_InvalidStateFormat(t *testing.T) {
	s := newOIDCTestServer(t, "test-secret")

	// State that doesn't start with "sessions:" prefix.
	r := httptest.NewRequest(http.MethodGet, "/callback?state=invalid_state_format", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleOIDCCallback(w, r)

	// Should return 400 for unrecognized state.
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleOIDCCallback_MalformedSessionsState(t *testing.T) {
	s := newOIDCTestServer(t, "test-secret")

	// State starts with sessions: but nonce is malformed (not 32 hex chars).
	r := httptest.NewRequest(http.MethodGet, "/callback?state=sessions:tooshort", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleOIDCCallback(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for malformed nonce, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleOIDCCallback_ExpiredNonce(t *testing.T) {
	s := newOIDCTestServer(t, "test-secret")

	// Valid format but nonce not stored (simulates expired).
	nonce := "abcdef1234567890abcdef1234567890"
	r := httptest.NewRequest(http.MethodGet, "/callback?state=sessions:"+nonce, nil)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleOIDCCallback(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for expired nonce, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ── handleSessionsLogin tests ────────────────────────────────────────────────

func TestHandleSessionsLogin_MethodNotAllowed(t *testing.T) {
	s := newOIDCTestServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodPost, "/sessions/login", nil)
	w := httptest.NewRecorder()
	s.handleSessionsLogin(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleSessionsLogin_RateLimit(t *testing.T) {
	s := newOIDCTestServer(t, "test-secret")

	ip := "10.0.0.99"
	// Exhaust the login rate limiter.
	for i := 0; i < loginRateMax+1; i++ {
		s.loginRL.allow(ip)
	}

	r := httptest.NewRequest(http.MethodGet, "/sessions/login", nil)
	r.RemoteAddr = ip + ":12345"
	w := httptest.NewRecorder()
	s.handleSessionsLogin(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
}

// ── loginRateLimiter tests ───────────────────────────────────────────────────

func TestLoginRateLimiter_AllowThenBlock(t *testing.T) {
	rl := newLoginRateLimiter()
	ip := "10.0.0.1"

	// First loginRateMax requests should be allowed.
	for i := 0; i < loginRateMax; i++ {
		if !rl.allow(ip) {
			t.Fatalf("request %d should be allowed", i)
		}
	}

	// Next request should be blocked.
	if rl.allow(ip) {
		t.Error("request should be blocked after exceeding rate limit")
	}
}

func TestLoginRateLimiter_DifferentIPs(t *testing.T) {
	rl := newLoginRateLimiter()

	// Exhaust one IP.
	for i := 0; i < loginRateMax+1; i++ {
		rl.allow("10.0.0.1")
	}

	// Different IP should still be allowed.
	if !rl.allow("10.0.0.2") {
		t.Error("different IP should not be blocked")
	}
}

// ── mutationRateLimiter tests ────────────────────────────────────────────────

func TestMutationRateLimiter_AllowThenBlock(t *testing.T) {
	rl := newMutationRateLimiter()
	user := "alice"

	for i := 0; i < mutationRateMax; i++ {
		if !rl.allow(user) {
			t.Fatalf("request %d should be allowed", i)
		}
	}

	if rl.allow(user) {
		t.Error("request should be blocked after exceeding rate limit")
	}
}

func TestMutationRateLimiter_DifferentUsers(t *testing.T) {
	rl := newMutationRateLimiter()

	// Exhaust one user.
	for i := 0; i < mutationRateMax+1; i++ {
		rl.allow("alice")
	}

	// Different user should still be allowed.
	if !rl.allow("bob") {
		t.Error("different user should not be blocked")
	}
}
