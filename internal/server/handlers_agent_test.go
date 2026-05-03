package server

import (
	"context"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/policy"
)

func newAgentTestServer(t *testing.T, secret string) *Server {
	t.Helper()
	store := newTestStore(t, 5*time.Minute, 10*time.Minute)
	return &Server{
		cfg:            &config.ServerConfig{SharedSecret: secret, SessionSecret: secret, ChallengeTTL: 5 * time.Minute},
		store:          store,
		hostRegistry:   NewHostRegistry(""),
		authFailRL:     newAuthFailTracker(),
		mutationRL:     newMutationRateLimiter(),
		sseBroadcaster: noopBroadcaster{},
		policyEngine:   policy.NewEngine(nil),
		notifyCfg:      &notify.NotificationConfig{},
	}
}

func TestHandleAgentHeartbeat_Success(t *testing.T) {
	const secret = "test-shared-secret-thats-long-enough"
	s := newAgentTestServer(t, secret)

	body, _ := json.Marshal(map[string]string{
		"hostname": "host1", "version": "0.42.0", "os_info": "Ubuntu 24.04",
	})
	r := httptest.NewRequest(http.MethodPost, "/api/agent/heartbeat", bytes.NewReader(body))
	r.Header.Set("X-Shared-Secret", secret)
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "10.0.0.1:55555"
	w := httptest.NewRecorder()

	s.handleAgentHeartbeat(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d; body %s", w.Code, w.Body.String())
	}

	agents := s.store.ListAgents(context.Background())
	if len(agents) != 1 || agents[0].Hostname != "host1" {
		t.Fatalf("ListAgents: got %+v", agents)
	}
	if agents[0].Version != "0.42.0" {
		t.Errorf("Version: got %q", agents[0].Version)
	}
	if agents[0].IP == "" {
		t.Errorf("IP: empty (want remote_addr)")
	}
}

func TestHandleAgentHeartbeat_Unauthorized(t *testing.T) {
	const secret = "test-shared-secret-thats-long-enough"
	s := newAgentTestServer(t, secret)

	body, _ := json.Marshal(map[string]string{"hostname": "host1"})
	r := httptest.NewRequest(http.MethodPost, "/api/agent/heartbeat", bytes.NewReader(body))
	r.Header.Set("X-Shared-Secret", "wrong-secret")
	r.RemoteAddr = "10.0.0.1:1"
	w := httptest.NewRecorder()
	s.handleAgentHeartbeat(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if got := s.store.ListAgents(context.Background()); len(got) != 0 {
		t.Errorf("agents recorded after unauthorized heartbeat: %+v", got)
	}
}

func TestHandleAgentHeartbeat_MissingHostname(t *testing.T) {
	const secret = "test-shared-secret-thats-long-enough"
	s := newAgentTestServer(t, secret)

	body, _ := json.Marshal(map[string]string{"version": "1"})
	r := httptest.NewRequest(http.MethodPost, "/api/agent/heartbeat", bytes.NewReader(body))
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:1"
	w := httptest.NewRecorder()
	s.handleAgentHeartbeat(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleAgentHeartbeat_MethodNotAllowed(t *testing.T) {
	s := newAgentTestServer(t, "secret-thats-long-enough-for-the-validator")
	r := httptest.NewRequest(http.MethodGet, "/api/agent/heartbeat", nil)
	w := httptest.NewRecorder()
	s.handleAgentHeartbeat(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandleAgentList_RequiresAdmin(t *testing.T) {
	s := newAgentTestServer(t, "secret-thats-long-enough-for-the-validator")

	r := httptest.NewRequest(http.MethodGet, "/api/agents", nil)
	w := httptest.NewRecorder()
	s.handleAgentList(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated request, got %d", w.Code)
	}
}

func TestHandleAgentHeartbeat_PerHostSecret(t *testing.T) {
	const globalSecret = "test-shared-secret-thats-long-enough"
	s := newAgentTestServer(t, globalSecret)

	// Replace registry with one populated for "node-1" with its own secret.
	registry := NewHostRegistry(t.TempDir() + "/hosts.json")
	hostSecret, err := registry.AddHost("node-1", []string{"*"}, "")
	if err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	s.hostRegistry = registry

	// Per-host secret: accepted.
	body := []byte(`{"hostname":"node-1","version":"1.0"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/agent/heartbeat", bytes.NewReader(body))
	r.Header.Set("X-Shared-Secret", hostSecret)
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "10.0.0.1:1"
	w := httptest.NewRecorder()
	s.handleAgentHeartbeat(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("per-host secret accepted: expected 204, got %d (%s)", w.Code, w.Body.String())
	}

	// Wrong per-host secret: 401, no record.
	r2 := httptest.NewRequest(http.MethodPost, "/api/agent/heartbeat", bytes.NewReader(body))
	r2.Header.Set("X-Shared-Secret", "wrong-secret-of-sufficient-length-12345")
	r2.RemoteAddr = "10.0.0.1:1"
	w2 := httptest.NewRecorder()
	s.handleAgentHeartbeat(w2, r2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("wrong per-host secret: expected 401, got %d", w2.Code)
	}

	// Per-host secret only matches its own hostname — using node-1's secret
	// for a different hostname must be rejected.
	body3 := []byte(`{"hostname":"node-2","version":"1.0"}`)
	r3 := httptest.NewRequest(http.MethodPost, "/api/agent/heartbeat", bytes.NewReader(body3))
	r3.Header.Set("X-Shared-Secret", hostSecret)
	r3.RemoteAddr = "10.0.0.1:1"
	w3 := httptest.NewRecorder()
	s.handleAgentHeartbeat(w3, r3)
	if w3.Code != http.StatusUnauthorized {
		t.Fatalf("per-host secret cross-host: expected 401, got %d", w3.Code)
	}

	// Global secret still works as fallback even when registry is populated.
	r4 := httptest.NewRequest(http.MethodPost, "/api/agent/heartbeat", bytes.NewReader(body3))
	r4.Header.Set("X-Shared-Secret", globalSecret)
	r4.RemoteAddr = "10.0.0.1:1"
	w4 := httptest.NewRecorder()
	s.handleAgentHeartbeat(w4, r4)
	if w4.Code != http.StatusNoContent {
		t.Fatalf("global-secret fallback: expected 204, got %d", w4.Code)
	}

	agents := s.store.ListAgents(context.Background())
	if len(agents) != 2 {
		t.Errorf("expected 2 agents (node-1 + node-2), got %d", len(agents))
	}
}

func TestAgentStatus_Classification(t *testing.T) {
	now := time.Now()
	cases := []struct {
		delta    time.Duration
		expected string
	}{
		{1 * time.Minute, "green"},
		{9*time.Minute + 59*time.Second, "green"},
		{11 * time.Minute, "amber"},
		{59 * time.Minute, "amber"},
		{61 * time.Minute, "red"},
		{24 * time.Hour, "red"},
	}
	for _, c := range cases {
		got := agentStatus(now, now.Add(-c.delta))
		if got != c.expected {
			t.Errorf("agentStatus(%v ago): got %q, want %q", c.delta, got, c.expected)
		}
	}
	if got := agentStatus(now, time.Time{}); got != "red" {
		t.Errorf("agentStatus(zero time): got %q, want red", got)
	}
}
