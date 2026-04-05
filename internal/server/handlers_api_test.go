package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
