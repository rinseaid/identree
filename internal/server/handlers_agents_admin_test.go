package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/policy"
)

func newAdminAgentsTestServer(t *testing.T) *Server {
	t.Helper()
	store := newTestStore(t, 5*time.Minute, 10*time.Minute)
	cfg := &config.ServerConfig{
		SharedSecret:  "admin-secret-thats-long-enough-for-validators",
		SessionSecret: "admin-secret-thats-long-enough-for-validators",
		ChallengeTTL:  5 * time.Minute,
	}
	return &Server{
		cfg:                cfg,
		store:              store,
		hostRegistry:       NewHostRegistry(""),
		authFailRL:         newAuthFailTracker(),
		mutationRL:         newMutationRateLimiter(),
		sseBroadcaster:     noopBroadcaster{},
		policyEngine:       policy.NewEngine(nil),
		notifyCfg:          &notify.NotificationConfig{},
		notifyStore:        &notify.FileConfigStore{Path: t.TempDir() + "/notify.json"},
		removedUsers:       make(map[string]time.Time),
		revokedNonces:      make(map[string]time.Time),
		prevAdminUsernames: make(map[string]bool),
	}
}

// loginAdmin sets a valid admin session cookie on r. Mirrors the helper used
// in the other admin handler tests.
func loginAdmin(t *testing.T, s *Server, r *http.Request, username string) {
	t.Helper()
	w := httptest.NewRecorder()
	s.setSessionCookie(w, username, "admin")
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
}

func TestHandleAdminAgents_RequiresSession(t *testing.T) {
	s := newAdminAgentsTestServer(t)

	r := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	w := httptest.NewRecorder()
	s.handleAdminAgents(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect when no session, got %d", w.Code)
	}
}

func TestHandleAdminAgents_RendersFleet(t *testing.T) {
	s := newAdminAgentsTestServer(t)

	s.store.RecordHeartbeat(challenge.AgentHeartbeat{
		Hostname: "prod-web-01", Version: "0.42.0", OSInfo: "linux/amd64", IP: "10.0.0.1",
	})
	s.store.RecordHeartbeat(challenge.AgentHeartbeat{
		Hostname: "prod-db-01", Version: "0.41.0", OSInfo: "linux/arm64", IP: "10.0.0.2",
	})

	r := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	loginAdmin(t, s, r, "admin")
	w := httptest.NewRecorder()
	s.handleAdminAgents(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{"prod-web-01", "prod-db-01", "0.42.0", "linux/amd64", "10.0.0.1"} {
		if !strings.Contains(body, want) {
			t.Errorf("response body missing %q", want)
		}
	}
	// Status pill rendered.
	if !strings.Contains(body, "Online") {
		t.Errorf("expected fresh agents to render as Online; body excerpt: ...%s...",
			snippet(body, "prod-web-01", 200))
	}
}

func TestHandleAdminAgents_EmptyFleet(t *testing.T) {
	s := newAdminAgentsTestServer(t)

	r := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	loginAdmin(t, s, r, "admin")
	w := httptest.NewRecorder()
	s.handleAdminAgents(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "No agents") {
		t.Errorf("expected empty-state message; body excerpt: %s", snippet(body, "agents", 200))
	}
}

// snippet returns up to n chars of body around the first occurrence of pivot.
func snippet(body, pivot string, n int) string {
	i := strings.Index(body, pivot)
	if i < 0 {
		if len(body) > n {
			return body[:n]
		}
		return body
	}
	start := i - n/2
	if start < 0 {
		start = 0
	}
	end := start + n
	if end > len(body) {
		end = len(body)
	}
	return body[start:end]
}
