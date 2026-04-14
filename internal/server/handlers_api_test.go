package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/policy"
)

// noopBroadcaster is a no-op SSEBroadcaster for tests.
type noopBroadcaster struct{}

func (noopBroadcaster) Broadcast(string, string) {}
func (noopBroadcaster) Close()                   {}

// newAPITestServer builds a minimal *Server suitable for handleCreateChallenge
// and handlePollChallenge tests. Uses a local ChallengeStore with a temp dir.
func newAPITestServer(t *testing.T, secret string) *Server {
	t.Helper()
	store := challpkg.NewChallengeStore(5*time.Minute, 10*time.Minute, t.TempDir())
	return &Server{
		cfg: &config.ServerConfig{
			SharedSecret: secret,
			ChallengeTTL: 5 * time.Minute,
		},
		store:          store,
		hostRegistry:   NewHostRegistry(""),
		authFailRL:     newAuthFailTracker(),
		mutationRL:     newMutationRateLimiter(),
		sseBroadcaster: noopBroadcaster{},
		policyEngine:   policy.NewEngine(nil),
		notifyCfg:      &notify.NotificationConfig{},
	}
}

// postChallenge is a helper that sends a POST to handleCreateChallenge with
// the given JSON body and shared secret header.
func postChallenge(s *Server, body map[string]string, secret string) *httptest.ResponseRecorder {
	jsonBody, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/challenge", bytes.NewReader(jsonBody))
	r.Header.Set("Content-Type", "application/json")
	if secret != "" {
		r.Header.Set("X-Shared-Secret", secret)
	}
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleCreateChallenge(w, r)
	return w
}

func TestHandleCreateChallenge_MissingUsername(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	w := postChallenge(s, map[string]string{}, secret)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] != "username required" {
		t.Errorf("unexpected error: %q", resp["error"])
	}
}

func TestHandleCreateChallenge_MissingSecret(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	w := postChallenge(s, map[string]string{"username": "alice"}, "" /* no secret */)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleCreateChallenge_InvalidHostname(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	badHostnames := []struct {
		name     string
		hostname string
	}{
		{"comma", "host,name"},
		{"space", "host name"},
		{"slash", "host/name"},
		{"semicolon", "host;name"},
	}

	for _, tc := range badHostnames {
		t.Run(tc.name, func(t *testing.T) {
			w := postChallenge(s, map[string]string{
				"username": "alice",
				"hostname": tc.hostname,
			}, secret)
			if w.Code != http.StatusBadRequest {
				t.Errorf("hostname %q: expected 400, got %d; body: %s", tc.hostname, w.Code, w.Body.String())
			}
		})
	}
}

func TestHandleCreateChallenge_RateLimitedIP(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	// Exhaust the auth fail tracker for this IP.
	ip := "10.0.0.99"
	for i := 0; i < authFailMax+1; i++ {
		s.authFailRL.record(ip)
	}

	body, _ := json.Marshal(map[string]string{"username": "alice"})
	r := httptest.NewRequest(http.MethodPost, "/api/challenge", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = ip + ":12345"
	w := httptest.NewRecorder()
	s.handleCreateChallenge(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleCreateChallenge_Success(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	w := postChallenge(s, map[string]string{
		"username": "alice",
		"hostname": "web01",
	}, secret)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	// Verify required fields exist.
	for _, key := range []string{"challenge_id", "user_code", "verification_url", "expires_in"} {
		if _, ok := resp[key]; !ok {
			t.Errorf("missing key %q in response", key)
		}
	}

	// challenge_id should be 32-char hex.
	if id, ok := resp["challenge_id"].(string); !ok || len(id) != 32 {
		t.Errorf("challenge_id should be 32-char hex, got %q", resp["challenge_id"])
	}
}

func TestHandleCreateChallenge_JustificationRequired(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)
	s.cfg.RequireJustification = true

	// No reason provided.
	w := postChallenge(s, map[string]string{
		"username": "alice",
		"hostname": "web01",
	}, secret)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] != "justification_required" {
		t.Errorf("unexpected error: %q", resp["error"])
	}
	if _, ok := resp["justification_choices"]; !ok {
		t.Error("expected justification_choices in response")
	}
}

// ── handlePollChallenge tests ────────────────────────────────────────────────

func TestHandlePollChallenge_NonExistent(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	// Use a valid-looking but non-existent challenge ID (32 hex chars).
	r := httptest.NewRequest(http.MethodGet, "/api/challenge/deadbeefdeadbeefdeadbeefdeadbeef?hostname=web01", nil)
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handlePollChallenge(w, r)

	if w.Code != http.StatusGone {
		t.Errorf("expected 410, got %d; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "expired" {
		t.Errorf("expected status expired, got %q", resp["status"])
	}
}

func TestHandlePollChallenge_PendingChallenge(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	// Create a challenge first.
	cw := postChallenge(s, map[string]string{
		"username": "alice",
		"hostname": "web01",
	}, secret)
	if cw.Code != http.StatusCreated {
		t.Fatalf("setup: expected 201, got %d", cw.Code)
	}
	var createResp map[string]interface{}
	if err := json.NewDecoder(cw.Body).Decode(&createResp); err != nil {
		t.Fatal(err)
	}
	challengeID := createResp["challenge_id"].(string)

	// Poll for it.
	r := httptest.NewRequest(http.MethodGet, "/api/challenge/"+challengeID+"?hostname=web01", nil)
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handlePollChallenge(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "pending" {
		t.Errorf("expected status pending, got %q", resp["status"])
	}
}

// ── Grace period auto-approve tests ──────────────────────────────────────────

func TestHandleCreateChallenge_GraceAutoApprove(t *testing.T) {
	const secret = "test-secret"
	// Use a store with a 10-minute grace period.
	store := challpkg.NewChallengeStore(5*time.Minute, 10*time.Minute, filepath.Join(t.TempDir(), "state.json"))
	s := &Server{
		cfg: &config.ServerConfig{
			SharedSecret: secret,
			ChallengeTTL: 5 * time.Minute,
			GracePeriod:  10 * time.Minute,
		},
		store:          store,
		hostRegistry:   NewHostRegistry(""),
		authFailRL:     newAuthFailTracker(),
		mutationRL:     newMutationRateLimiter(),
		sseBroadcaster: noopBroadcaster{},
		policyEngine:   policy.NewEngine(nil), // permissive: GraceEligible=true, TimeWindowOK=true
		notifyCfg:      &notify.NotificationConfig{},
	}

	// Step 1: Create first challenge.
	w1 := postChallenge(s, map[string]string{
		"username": "alice",
		"hostname": "web01",
	}, secret)
	if w1.Code != http.StatusCreated {
		t.Fatalf("first challenge: expected 201, got %d; body: %s", w1.Code, w1.Body.String())
	}
	var resp1 map[string]interface{}
	if err := json.NewDecoder(w1.Body).Decode(&resp1); err != nil {
		t.Fatal(err)
	}
	firstID := resp1["challenge_id"].(string)

	// Step 2: Approve first challenge (creates a grace session).
	if err := store.Approve(firstID, "admin"); err != nil {
		t.Fatalf("approving first challenge: %v", err)
	}

	// Step 3: Create second challenge for same user/host — should auto-approve.
	w2 := postChallenge(s, map[string]string{
		"username": "alice",
		"hostname": "web01",
	}, secret)
	if w2.Code != http.StatusCreated {
		t.Fatalf("second challenge: expected 201, got %d; body: %s", w2.Code, w2.Body.String())
	}
	var resp2 map[string]interface{}
	if err := json.NewDecoder(w2.Body).Decode(&resp2); err != nil {
		t.Fatal(err)
	}

	// The second challenge should be auto-approved (grace period).
	if resp2["status"] != "approved" {
		t.Errorf("expected auto-approved status, got %q", resp2["status"])
	}
	if _, ok := resp2["grace_remaining"]; !ok {
		t.Error("expected grace_remaining in auto-approved response")
	}
}

func TestHandleCreateChallenge_GraceAutoApprove_DifferentHost(t *testing.T) {
	const secret = "test-secret"
	store := challpkg.NewChallengeStore(5*time.Minute, 10*time.Minute, filepath.Join(t.TempDir(), "state.json"))
	s := &Server{
		cfg: &config.ServerConfig{
			SharedSecret: secret,
			ChallengeTTL: 5 * time.Minute,
			GracePeriod:  10 * time.Minute,
		},
		store:          store,
		hostRegistry:   NewHostRegistry(""),
		authFailRL:     newAuthFailTracker(),
		mutationRL:     newMutationRateLimiter(),
		sseBroadcaster: noopBroadcaster{},
		policyEngine:   policy.NewEngine(nil),
		notifyCfg:      &notify.NotificationConfig{},
	}

	// Create and approve challenge for web01.
	w1 := postChallenge(s, map[string]string{
		"username": "alice",
		"hostname": "web01",
	}, secret)
	if w1.Code != http.StatusCreated {
		t.Fatalf("setup: expected 201, got %d", w1.Code)
	}
	var resp1 map[string]interface{}
	json.NewDecoder(w1.Body).Decode(&resp1)
	store.Approve(resp1["challenge_id"].(string), "admin")

	// Create challenge for DIFFERENT host — should NOT auto-approve.
	w2 := postChallenge(s, map[string]string{
		"username": "alice",
		"hostname": "db01",
	}, secret)
	if w2.Code != http.StatusCreated {
		t.Fatalf("second challenge: expected 201, got %d", w2.Code)
	}
	var resp2 map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&resp2)

	// Should remain pending (grace is per user+host).
	if _, ok := resp2["status"]; ok {
		t.Errorf("expected no status in pending response, got %q", resp2["status"])
	}
}

// ── Challenge expiry tests ───────────────────────────────────────────────────

func TestHandlePollChallenge_ExpiredChallenge(t *testing.T) {
	const secret = "test-secret"
	// Use a very short TTL so the challenge expires quickly.
	shortTTL := 50 * time.Millisecond
	store := challpkg.NewChallengeStore(shortTTL, 10*time.Minute, filepath.Join(t.TempDir(), "state.json"))
	s := &Server{
		cfg: &config.ServerConfig{
			SharedSecret: secret,
			ChallengeTTL: shortTTL,
		},
		store:          store,
		hostRegistry:   NewHostRegistry(""),
		authFailRL:     newAuthFailTracker(),
		mutationRL:     newMutationRateLimiter(),
		sseBroadcaster: noopBroadcaster{},
		policyEngine:   policy.NewEngine(nil),
		notifyCfg:      &notify.NotificationConfig{},
	}

	// Create a challenge via the store directly.
	c, err := store.Create("alice", "web01", "", "")
	if err != nil {
		t.Fatalf("creating challenge: %v", err)
	}

	// Wait for it to expire.
	time.Sleep(100 * time.Millisecond)

	// Poll — should return 410 Gone.
	r := httptest.NewRequest(http.MethodGet, "/api/challenge/"+c.ID+"?hostname=web01", nil)
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handlePollChallenge(w, r)

	if w.Code != http.StatusGone {
		t.Errorf("expected 410 (expired), got %d; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "expired" {
		t.Errorf("expected status expired, got %q", resp["status"])
	}
}
