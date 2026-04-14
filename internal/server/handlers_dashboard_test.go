package server

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/policy"
)

// newDashboardTestServer builds a minimal *Server for healthz/metrics tests.
func newDashboardTestServer(t *testing.T, cfg *config.ServerConfig) *Server {
	t.Helper()
	store := challpkg.NewChallengeStore(5*time.Minute, 10*time.Minute, t.TempDir())
	if cfg.SharedSecret == "" {
		cfg.SharedSecret = "test-secret"
	}
	if cfg.ChallengeTTL == 0 {
		cfg.ChallengeTTL = 5 * time.Minute
	}
	s := &Server{
		cfg:            cfg,
		store:          store,
		hostRegistry:   NewHostRegistry(""),
		authFailRL:     newAuthFailTracker(),
		mutationRL:     newMutationRateLimiter(),
		sseBroadcaster: noopBroadcaster{},
		policyEngine:   policy.NewEngine(nil),
		notifyCfg:      &notify.NotificationConfig{},
	}
	// Pre-compute hashed metrics token if set.
	if cfg.MetricsToken != "" {
		s.hashedMetricsToken = sha256.Sum256([]byte(cfg.MetricsToken))
	}
	return s
}

// ── handleHealthz tests ──────────────────────────────────────────────────────

func TestHandleHealthz_OK(t *testing.T) {
	s := newDashboardTestServer(t, &config.ServerConfig{})

	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	s.handleHealthz(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["status"] != "ok" {
		t.Errorf("expected status 'ok', got %q", resp["status"])
	}

	// Verify checks object exists.
	checks, ok := resp["checks"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'checks' object in response")
	}

	// Disk check should always be present.
	if checks["disk"] != "ok" {
		t.Errorf("expected disk check 'ok', got %q", checks["disk"])
	}
}

func TestHandleHealthz_ContentType(t *testing.T) {
	s := newDashboardTestServer(t, &config.ServerConfig{})

	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	s.handleHealthz(w, r)

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

func TestHandleHealthz_MethodNotAllowed(t *testing.T) {
	s := newDashboardTestServer(t, &config.ServerConfig{})

	r := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	w := httptest.NewRecorder()
	s.handleHealthz(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleHealthz_HeadMethod(t *testing.T) {
	s := newDashboardTestServer(t, &config.ServerConfig{})

	r := httptest.NewRequest(http.MethodHead, "/healthz", nil)
	w := httptest.NewRecorder()
	s.handleHealthz(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for HEAD, got %d", w.Code)
	}
}

func TestHandleHealthz_DiskUnwritable(t *testing.T) {
	// Use a non-existent directory as SessionStateFile so disk check fails.
	s := newDashboardTestServer(t, &config.ServerConfig{
		SessionStateFile: "/nonexistent/path/state.json",
	})

	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	s.handleHealthz(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for unwritable disk, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "unhealthy" {
		t.Errorf("expected status 'unhealthy', got %q", resp["status"])
	}
}

// ── handleMetrics tests ──────────────────────────────────────────────────────

func TestHandleMetrics_Unauthenticated(t *testing.T) {
	// No MetricsToken configured → metrics are public.
	s := newDashboardTestServer(t, &config.ServerConfig{})

	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	s.handleMetrics(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Should contain Prometheus metrics format (at least one metric name).
	body := w.Body.String()
	if !strings.Contains(body, "identree_") && !strings.Contains(body, "go_") {
		t.Error("expected Prometheus metrics format in response body")
	}
}

func TestHandleMetrics_WithToken_Authorized(t *testing.T) {
	const token = "my-metrics-token"
	s := newDashboardTestServer(t, &config.ServerConfig{
		MetricsToken: token,
	})

	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.handleMetrics(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleMetrics_WithToken_Unauthorized(t *testing.T) {
	const token = "my-metrics-token"
	s := newDashboardTestServer(t, &config.ServerConfig{
		MetricsToken: token,
	})

	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	s.handleMetrics(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleMetrics_WithToken_QueryParam(t *testing.T) {
	const token = "my-metrics-token"
	s := newDashboardTestServer(t, &config.ServerConfig{
		MetricsToken: token,
	})

	r := httptest.NewRequest(http.MethodGet, "/metrics?token="+token, nil)
	w := httptest.NewRecorder()
	s.handleMetrics(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandleMetrics_WithToken_NoAuth(t *testing.T) {
	const token = "my-metrics-token"
	s := newDashboardTestServer(t, &config.ServerConfig{
		MetricsToken: token,
	})

	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	s.handleMetrics(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when no auth provided, got %d", w.Code)
	}
}
