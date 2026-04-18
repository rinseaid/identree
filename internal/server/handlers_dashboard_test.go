package server

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/policy"
)

// newDashboardTestServer builds a minimal *Server for healthz/metrics tests.
func newDashboardTestServer(t *testing.T, cfg *config.ServerConfig) *Server {
	t.Helper()
	store := newTestStore(t, 5*time.Minute, 10*time.Minute)
	if cfg.SharedSecret == "" {
		cfg.SharedSecret = "test-secret"
	}
	if cfg.SessionSecret == "" {
		cfg.SessionSecret = cfg.SharedSecret
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

// ── handleDashboard tests ────────────────────────────────────────────────────

func newDashboardFullServer(t *testing.T, secret string) *Server {
	t.Helper()
	s := newDashboardTestServer(t, &config.ServerConfig{
		SharedSecret: secret,
	})
	s.revokedNonces = make(map[string]time.Time)
	return s
}

func TestHandleDashboard_NoSession_Redirect(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	s.handleDashboard(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect to login, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "/sessions/login") {
		t.Errorf("expected redirect to /sessions/login, got %q", loc)
	}
}

func TestHandleDashboard_MethodNotAllowed(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	s.handleDashboard(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleDashboard_NotFoundForSubpaths(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	w := httptest.NewRecorder()
	s.handleDashboard(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-root path, got %d", w.Code)
	}
}

func TestHandleDashboard_ValidSession(t *testing.T) {
	const secret = "test-secret"
	s := newDashboardFullServer(t, secret)

	ts := time.Now().Unix()
	cookieVal := makeCookie(secret, "alice", "admin", ts)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleDashboard(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body length: %d", w.Code, w.Body.Len())
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html" {
		t.Errorf("expected Content-Type text/html, got %q", ct)
	}
}

// ── handleSignOut tests ──────────────────────────────────────────────────────

func TestHandleSignOut_GET_Redirect(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/signout", nil)
	w := httptest.NewRecorder()
	s.handleSignOut(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect for GET, got %d", w.Code)
	}
}

func TestHandleSignOut_POST_ClearsCookieAndRedirects(t *testing.T) {
	const secret = "test-secret"
	s := newDashboardFullServer(t, secret)

	ts := time.Now().Unix()
	csrfTs := fmt.Sprintf("%d", ts)
	csrfToken := computeCSRFToken(secret, "alice", csrfTs)
	cookieVal := makeCookie(secret, "alice", "admin", ts)

	form := "csrf_token=" + csrfToken + "&csrf_ts=" + csrfTs
	r := httptest.NewRequest(http.MethodPost, "/signout", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleSignOut(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}

	// Verify session cookie is cleared.
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == sessionCookieName && c.MaxAge < 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected session cookie to be cleared (MaxAge < 0)")
	}
}

func TestHandleSignOut_POST_InvalidCSRF(t *testing.T) {
	const secret = "test-secret"
	s := newDashboardFullServer(t, secret)

	ts := time.Now().Unix()
	cookieVal := makeCookie(secret, "alice", "admin", ts)

	form := "csrf_token=badtoken&csrf_ts=" + fmt.Sprintf("%d", ts)
	r := httptest.NewRequest(http.MethodPost, "/signout", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleSignOut(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for invalid CSRF, got %d", w.Code)
	}
}

// ── handleThemeToggle tests ──────────────────────────────────────────────────

func TestHandleThemeToggle_SetDark(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/theme?set=dark&from=/", nil)
	w := httptest.NewRecorder()
	s.handleThemeToggle(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}

	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "identree_theme" && c.Value == "dark" {
			found = true
		}
	}
	if !found {
		t.Error("expected identree_theme cookie to be set to 'dark'")
	}
}

func TestHandleThemeToggle_SetLight(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/theme?set=light&from=/", nil)
	w := httptest.NewRecorder()
	s.handleThemeToggle(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}

	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "identree_theme" && c.Value == "light" {
			found = true
		}
	}
	if !found {
		t.Error("expected identree_theme cookie to be set to 'light'")
	}
}

func TestHandleThemeToggle_SetSystem(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/theme?set=system&from=/", nil)
	w := httptest.NewRecorder()
	s.handleThemeToggle(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}

	// System should clear the cookie (MaxAge=-1).
	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "identree_theme" && c.MaxAge > 0 {
			t.Error("expected identree_theme cookie to be cleared for system theme")
		}
	}
}

func TestHandleThemeToggle_MethodNotAllowed(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodPost, "/theme?set=dark", nil)
	w := httptest.NewRecorder()
	s.handleThemeToggle(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleThemeToggle_UnsafeRedirectIgnored(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")

	// From with a double slash should be ignored and default to "/"
	r := httptest.NewRequest(http.MethodGet, "/theme?set=dark&from=//evil.com", nil)
	w := httptest.NewRecorder()
	s.handleThemeToggle(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if strings.Contains(loc, "evil.com") {
		t.Errorf("expected safe redirect, got %q", loc)
	}
}

// ── handleDevLogin tests ─────────────────────────────────────────────────────

func TestHandleDevLogin_Disabled(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")
	s.cfg.DevLoginEnabled = false

	r := httptest.NewRequest(http.MethodGet, "/dev/login?user=alice&role=admin", nil)
	w := httptest.NewRecorder()
	s.handleDevLogin(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when dev login disabled, got %d", w.Code)
	}
}

func TestHandleDevLogin_Enabled_Valid(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")
	s.cfg.DevLoginEnabled = true

	r := httptest.NewRequest(http.MethodGet, "/dev/login?user=alice&role=admin", nil)
	w := httptest.NewRecorder()
	s.handleDevLogin(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}

	// Should set a session cookie.
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			found = true
		}
	}
	if !found {
		t.Error("expected session cookie to be set")
	}
}

func TestHandleDevLogin_Enabled_MissingUser(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")
	s.cfg.DevLoginEnabled = true

	r := httptest.NewRequest(http.MethodGet, "/dev/login?role=admin", nil)
	w := httptest.NewRecorder()
	s.handleDevLogin(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing user, got %d", w.Code)
	}
}

func TestHandleDevLogin_Enabled_InvalidUsername(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")
	s.cfg.DevLoginEnabled = true

	r := httptest.NewRequest(http.MethodGet, "/dev/login?user=not+valid!", nil)
	w := httptest.NewRecorder()
	s.handleDevLogin(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid username, got %d", w.Code)
	}
}

func TestHandleDevLogin_Enabled_DefaultsToUser(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")
	s.cfg.DevLoginEnabled = true

	r := httptest.NewRequest(http.MethodGet, "/dev/login?user=bob", nil) // no role param
	w := httptest.NewRecorder()
	s.handleDevLogin(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}
}

// ── handleAccess tests ───────────────────────────────────────────────────────

func TestHandleAccess_NoSession_Redirect(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/access", nil)
	w := httptest.NewRecorder()
	s.handleAccess(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect to login, got %d", w.Code)
	}
}

func TestHandleAccess_MethodNotAllowed(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodPost, "/access", nil)
	w := httptest.NewRecorder()
	s.handleAccess(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── handleHistoryPage tests ──────────────────────────────────────────────────

func TestHandleHistoryPage_NoSession_Redirect(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/history", nil)
	w := httptest.NewRecorder()
	s.handleHistoryPage(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}
}

// ── handleSessionsRedirect tests ─────────────────────────────────────────────

func TestHandleSessionsRedirect(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	w := httptest.NewRecorder()
	s.handleSessionsRedirect(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}
}

// ── handleDashboard with pending challenges ──────────────────────────────────

func TestHandleDashboard_WithSession_ShowsContent(t *testing.T) {
	const secret = "test-secret"
	s := newDashboardFullServer(t, secret)
	s.removedUsers = make(map[string]time.Time)

	// Add a history entry so the dashboard has data to render.
	s.store.LogAction("alice", "approved", "web01", "ABC-123", "admin")

	ts := time.Now().Unix()
	cookieVal := makeCookie(secret, "alice", "admin", ts)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleDashboard(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body length: %d", w.Code, w.Body.Len())
	}
}

// ── handleAccess valid session tests ─────────────────────────────────────────

func TestHandleAccess_ValidSession(t *testing.T) {
	const secret = "test-secret"
	s := newDashboardFullServer(t, secret)
	s.removedUsers = make(map[string]time.Time)

	ts := time.Now().Unix()
	cookieVal := makeCookie(secret, "alice", "admin", ts)
	r := httptest.NewRequest(http.MethodGet, "/access", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleAccess(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body length: %d", w.Code, w.Body.Len())
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html" {
		t.Errorf("expected Content-Type text/html, got %q", ct)
	}
}

// ── handleHealthz additional tests ───────────────────────────────────────────

func TestHandleDevSeedHistory_Disabled(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")
	s.cfg.DevLoginEnabled = false

	r := httptest.NewRequest(http.MethodPost, "/dev/seed-history", strings.NewReader(`[{"username":"alice","action":"approved","hostname":"web01","actor":"admin","minutes_ago":5}]`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleDevSeedHistory(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when dev login disabled, got %d", w.Code)
	}
}

func TestHandleDevSeedHistory_Enabled(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")
	s.cfg.DevLoginEnabled = true

	body := `[{"username":"alice","action":"approved","hostname":"web01","actor":"admin","minutes_ago":5}]`
	r := httptest.NewRequest(http.MethodPost, "/dev/seed-history", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleDevSeedHistory(w, r)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}
}

func TestHandleDevSeedHistory_MethodNotAllowed(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")
	s.cfg.DevLoginEnabled = true

	r := httptest.NewRequest(http.MethodGet, "/dev/seed-history", nil)
	w := httptest.NewRecorder()
	s.handleDevSeedHistory(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleDevSeedHistory_InvalidBody(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")
	s.cfg.DevLoginEnabled = true

	r := httptest.NewRequest(http.MethodPost, "/dev/seed-history", strings.NewReader("not json"))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleDevSeedHistory(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ── handleDevSeedSession tests ───────────────────────────────────────────────

func TestHandleDevSeedSession_Disabled(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")
	s.cfg.DevLoginEnabled = false

	r := httptest.NewRequest(http.MethodPost, "/dev/seed-session", strings.NewReader(`{"username":"alice","hostname":"web01"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleDevSeedSession(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleDevSeedSession_Enabled(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")
	s.cfg.DevLoginEnabled = true

	r := httptest.NewRequest(http.MethodPost, "/dev/seed-session", strings.NewReader(`{"username":"alice","hostname":"web01"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleDevSeedSession(w, r)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}
}

func TestHandleDevSeedSession_MissingUsername(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")
	s.cfg.DevLoginEnabled = true

	r := httptest.NewRequest(http.MethodPost, "/dev/seed-session", strings.NewReader(`{"hostname":"web01"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleDevSeedSession(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleDevSeedSession_MethodNotAllowed(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")
	s.cfg.DevLoginEnabled = true

	r := httptest.NewRequest(http.MethodGet, "/dev/seed-session", nil)
	w := httptest.NewRecorder()
	s.handleDevSeedSession(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── handleApprovalPage tests ─────────────────────────────────────────────────

func newApprovalTestServer(t *testing.T, secret string) *Server {
	t.Helper()
	s := newDashboardFullServer(t, secret)
	s.approveRL = newLoginRateLimiter()
	return s
}

func TestHandleApprovalPage_MethodNotAllowed(t *testing.T) {
	s := newApprovalTestServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodPost, "/approve/ABCDEF-123456", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleApprovalPage(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleApprovalPage_EmptyCode(t *testing.T) {
	s := newApprovalTestServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/approve/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleApprovalPage(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleApprovalPage_InvalidCodeFormat(t *testing.T) {
	s := newApprovalTestServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/approve/shortcode", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleApprovalPage(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleApprovalPage_NonExistentChallenge(t *testing.T) {
	s := newApprovalTestServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/approve/ABCDEF-123456", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleApprovalPage(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleApprovalPage_RateLimit(t *testing.T) {
	s := newApprovalTestServer(t, "test-secret")

	ip := "10.0.0.99"
	// Exhaust the approval rate limiter.
	for i := 0; i < loginRateMax+1; i++ {
		s.approveRL.allow(ip)
	}

	r := httptest.NewRequest(http.MethodGet, "/approve/ABCDEF-123456", nil)
	r.RemoteAddr = ip + ":12345"
	w := httptest.NewRecorder()
	s.handleApprovalPage(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
}

// ── handleHistoryExport tests ────────────────────────────────────────────────

func TestHandleHistoryExport_NoAuth(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/api/history/export?format=json", nil)
	w := httptest.NewRecorder()
	s.handleHistoryExport(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleHistoryExport_MethodNotAllowed(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodPost, "/api/history/export", nil)
	w := httptest.NewRecorder()
	s.handleHistoryExport(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleHistoryExport_InvalidFormat(t *testing.T) {
	const secret = "test-secret"
	s := newDashboardFullServer(t, secret)

	ts := time.Now().Unix()
	cookieVal := makeCookie(secret, "alice", "user", ts)
	r := httptest.NewRequest(http.MethodGet, "/api/history/export?format=xml", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleHistoryExport(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unsupported format, got %d", w.Code)
	}
}

func TestHandleHistoryExport_JSON_WithSession(t *testing.T) {
	const secret = "test-secret"
	s := newDashboardFullServer(t, secret)

	ts := time.Now().Unix()
	cookieVal := makeCookie(secret, "alice", "user", ts)
	r := httptest.NewRequest(http.MethodGet, "/api/history/export?format=json", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleHistoryExport(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

func TestHandleHistoryExport_CSV_WithSession(t *testing.T) {
	const secret = "test-secret"
	s := newDashboardFullServer(t, secret)

	ts := time.Now().Unix()
	cookieVal := makeCookie(secret, "alice", "user", ts)
	r := httptest.NewRequest(http.MethodGet, "/api/history/export?format=csv", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleHistoryExport(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/csv" {
		t.Errorf("expected Content-Type text/csv, got %q", ct)
	}
}

// ── buildPendingViews tests ──────────────────────────────────────────────────

func TestBuildPendingViews_Empty(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")

	views := s.buildPendingViews("alice", "en")
	if len(views) != 0 {
		t.Errorf("expected 0 views, got %d", len(views))
	}
}

func TestBuildPendingViews_WithChallenge(t *testing.T) {
	const secret = "test-secret"
	s := newDashboardFullServer(t, secret)

	// Create a challenge.
	c, err := s.store.Create("alice", "web01", "", "")
	if err != nil {
		t.Fatal(err)
	}

	views := s.buildPendingViews("alice", "en")
	if len(views) != 1 {
		t.Fatalf("expected 1 view, got %d", len(views))
	}
	if views[0].ID != c.ID {
		t.Errorf("expected ID %q, got %q", c.ID, views[0].ID)
	}
	if views[0].Hostname != "web01" {
		t.Errorf("expected hostname web01, got %q", views[0].Hostname)
	}
}

func TestBuildAllPendingViews_Empty(t *testing.T) {
	s := newDashboardFullServer(t, "test-secret")

	views := s.buildAllPendingViews("admin", "en")
	if len(views) != 0 {
		t.Errorf("expected 0 views, got %d", len(views))
	}
}

func TestPendingViewsFor_AdminVsUser(t *testing.T) {
	const secret = "test-secret"
	s := newDashboardFullServer(t, secret)

	// Create challenges for different users.
	s.store.Create("alice", "web01", "", "")
	s.store.Create("bob", "db01", "", "")

	// Admin should see all.
	adminViews := s.pendingViewsFor("admin", "en", true)
	if len(adminViews) != 2 {
		t.Errorf("admin expected 2 views, got %d", len(adminViews))
	}

	// Regular user should only see their own.
	aliceViews := s.pendingViewsFor("alice", "en", false)
	if len(aliceViews) != 1 {
		t.Errorf("alice expected 1 view, got %d", len(aliceViews))
	}
}

func TestHandleHealthz_ChecksStructure(t *testing.T) {
	s := newDashboardTestServer(t, &config.ServerConfig{})

	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	s.handleHealthz(w, r)

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify checks object has disk field.
	checks, ok := resp["checks"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'checks' object in response")
	}
	if checks["disk"] != "ok" {
		t.Errorf("expected disk check 'ok', got %q", checks["disk"])
	}

	// When LDAP is disabled, ldap_sync should not be present.
	if _, present := checks["ldap_sync"]; present {
		t.Error("expected ldap_sync to be absent when LDAP is disabled")
	}
}
