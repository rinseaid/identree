package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/policy"
)

// noopBroadcaster is a no-op SSEBroadcaster for tests.
type noopBroadcaster struct{}

func (noopBroadcaster) Broadcast(string, string)      {}
func (noopBroadcaster) PublishCluster(clusterMessage) {}
func (noopBroadcaster) Close()                        {}

// newAPITestServer builds a minimal *Server suitable for handleCreateChallenge
// and handlePollChallenge tests. Uses a local ChallengeStore with a temp dir.
func newAPITestServer(t *testing.T, secret string) *Server {
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
	store := newTestStore(t, 5*time.Minute, 10*time.Minute)
	s := &Server{
		cfg: &config.ServerConfig{
			SharedSecret:  secret,
			SessionSecret: secret,
			ChallengeTTL:  5 * time.Minute,
			GracePeriod:   10 * time.Minute,
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
	store := newTestStore(t, 5*time.Minute, 10*time.Minute)
	s := &Server{
		cfg: &config.ServerConfig{
			SharedSecret:  secret,
			SessionSecret: secret,
			ChallengeTTL:  5 * time.Minute,
			GracePeriod:   10 * time.Minute,
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

// ── handleGraceStatus tests ──────────────────────────────────────────────────

func TestHandleGraceStatus_MissingAuth(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/api/grace-status?username=alice&hostname=web01", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleGraceStatus(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleGraceStatus_ValidAuth(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/api/grace-status?username=alice&hostname=web01", nil)
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleGraceStatus(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	// grace_remaining should be 0 when no active session.
	if resp["grace_remaining"] != float64(0) {
		t.Errorf("expected grace_remaining=0, got %v", resp["grace_remaining"])
	}
}

func TestHandleGraceStatus_MissingUsername(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/api/grace-status?hostname=web01", nil)
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleGraceStatus(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleGraceStatus_InvalidUsername(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/api/grace-status?username=invalid%20user&hostname=web01", nil)
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleGraceStatus(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleGraceStatus_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	r := httptest.NewRequest(http.MethodPost, "/api/grace-status?username=alice", nil)
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleGraceStatus(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleGraceStatus_WithActiveGrace(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	// Create a grace session.
	s.store.CreateGraceSession("alice", "web01", 10*time.Minute)

	r := httptest.NewRequest(http.MethodGet, "/api/grace-status?username=alice&hostname=web01", nil)
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleGraceStatus(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	remaining, ok := resp["grace_remaining"].(float64)
	if !ok || remaining <= 0 {
		t.Errorf("expected positive grace_remaining, got %v", resp["grace_remaining"])
	}
}

// ── Content-Type enforcement tests ───────────────────────────────────────────

func TestHandleCreateChallenge_WrongContentType(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	body := `{"username":"alice"}`
	r := httptest.NewRequest(http.MethodPost, "/api/challenge", bytes.NewReader([]byte(body)))
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleCreateChallenge(w, r)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleCreateChallenge_FormEncodedRejected(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	r := httptest.NewRequest(http.MethodPost, "/api/challenge", bytes.NewReader([]byte("username=alice")))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleCreateChallenge(w, r)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleCreateChallenge_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/api/challenge", nil)
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleCreateChallenge(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── sanitizeReason tests ─────────────────────────────────────────────────────

func TestSanitizeReason_Valid(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"  simple reason  ", "simple reason"},
		{"with\ttab", "with\ttab"},
		{"", ""},
	}
	for _, tc := range tests {
		got, ok := sanitizeReason(tc.input)
		if !ok {
			t.Errorf("sanitizeReason(%q) returned invalid", tc.input)
		}
		if got != tc.want {
			t.Errorf("sanitizeReason(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSanitizeReason_Invalid(t *testing.T) {
	_, ok := sanitizeReason("has\x00null")
	if ok {
		t.Error("expected sanitizeReason to reject null byte")
	}
	_, ok = sanitizeReason("has\nnewline")
	if ok {
		t.Error("expected sanitizeReason to reject newline")
	}
}

func TestSanitizeReason_TruncatesLong(t *testing.T) {
	long := make([]byte, 600)
	for i := range long {
		long[i] = 'a'
	}
	got, ok := sanitizeReason(string(long))
	if !ok {
		t.Fatal("expected sanitizeReason to accept long string (truncated)")
	}
	if len(got) > 500 {
		t.Errorf("expected truncation to 500 runes, got length %d", len(got))
	}
}

// ── computeStatusHMAC tests ──────────────────────────────────────────────────

func TestComputeStatusHMAC_Deterministic(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	h1 := s.computeStatusHMAC("id1", "alice", "approved", "", "")
	h2 := s.computeStatusHMAC("id1", "alice", "approved", "", "")
	if h1 != h2 {
		t.Errorf("expected deterministic HMAC, got %q and %q", h1, h2)
	}
}

func TestComputeStatusHMAC_DifferentStatus(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	h1 := s.computeStatusHMAC("id1", "alice", "approved", "", "")
	h2 := s.computeStatusHMAC("id1", "alice", "denied", "", "")
	if h1 == h2 {
		t.Error("expected different HMAC for different statuses")
	}
}

func TestComputeStatusHMAC_IncludesRotateBefore(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	h1 := s.computeStatusHMAC("id1", "alice", "approved", "", "")
	h2 := s.computeStatusHMAC("id1", "alice", "approved", "2024-01-01T00:00:00Z", "")
	if h1 == h2 {
		t.Error("expected different HMAC when rotateBefore is set")
	}
}

// ── apiError tests ───────────────────────────────────────────────────────────

func TestAPIError_Format(t *testing.T) {
	w := httptest.NewRecorder()
	apiError(w, http.StatusBadRequest, "test error")

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] != "test error" {
		t.Errorf("expected error %q, got %q", "test error", resp["error"])
	}
}

func TestHandlePollChallenge_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	r := httptest.NewRequest(http.MethodPost, "/api/challenge/deadbeefdeadbeefdeadbeefdeadbeef", nil)
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handlePollChallenge(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandlePollChallenge_MissingAuth(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/api/challenge/deadbeefdeadbeefdeadbeefdeadbeef", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handlePollChallenge(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandlePollChallenge_InvalidIDFormat(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/api/challenge/tooshort", nil)
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handlePollChallenge(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandlePollChallenge_EmptyID(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/api/challenge/", nil)
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handlePollChallenge(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandlePollChallenge_HostnameMismatch(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	// Create a challenge for web01.
	cw := postChallenge(s, map[string]string{
		"username": "alice",
		"hostname": "web01",
	}, secret)
	if cw.Code != http.StatusCreated {
		t.Fatalf("setup: expected 201, got %d", cw.Code)
	}
	var createResp map[string]interface{}
	json.NewDecoder(cw.Body).Decode(&createResp)
	challengeID := createResp["challenge_id"].(string)

	// Poll with wrong hostname.
	r := httptest.NewRequest(http.MethodGet, "/api/challenge/"+challengeID+"?hostname=db01", nil)
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handlePollChallenge(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for hostname mismatch, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandlePollChallenge_ApprovedChallenge(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	// Create and approve.
	cw := postChallenge(s, map[string]string{
		"username": "alice",
		"hostname": "web01",
	}, secret)
	if cw.Code != http.StatusCreated {
		t.Fatalf("setup: expected 201, got %d", cw.Code)
	}
	var createResp map[string]interface{}
	json.NewDecoder(cw.Body).Decode(&createResp)
	challengeID := createResp["challenge_id"].(string)

	s.store.Approve(challengeID, "admin")

	// Poll should return approved.
	r := httptest.NewRequest(http.MethodGet, "/api/challenge/"+challengeID+"?hostname=web01", nil)
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handlePollChallenge(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "approved" {
		t.Errorf("expected status approved, got %v (full response: %v)", resp["status"], resp)
	}
}

func TestHandlePollChallenge_DeniedChallenge(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	cw := postChallenge(s, map[string]string{
		"username": "alice",
		"hostname": "web01",
	}, secret)
	if cw.Code != http.StatusCreated {
		t.Fatalf("setup: expected 201, got %d", cw.Code)
	}
	var createResp map[string]interface{}
	json.NewDecoder(cw.Body).Decode(&createResp)
	challengeID := createResp["challenge_id"].(string)

	s.store.Deny(challengeID, "test reason")

	r := httptest.NewRequest(http.MethodGet, "/api/challenge/"+challengeID+"?hostname=web01", nil)
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handlePollChallenge(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "denied" {
		t.Errorf("expected status denied, got %q", resp["status"])
	}
}

// ── buildClientConfig tests ──────────────────────────────────────────────────

func TestBuildClientConfig_Empty(t *testing.T) {
	s := newAPITestServer(t, "test-secret")
	got := s.buildClientConfig()
	if got != nil {
		t.Errorf("expected nil for no overrides, got %v", got)
	}
}

func TestBuildClientConfig_WithOverrides(t *testing.T) {
	s := newAPITestServer(t, "test-secret")
	boolTrue := true
	s.cfg.ClientPollInterval = 5 * time.Second
	s.cfg.ClientTimeout = 10 * time.Minute
	s.cfg.ClientBreakglassEnabled = &boolTrue
	s.cfg.ClientBreakglassPasswordType = "passphrase"
	s.cfg.ClientBreakglassRotationDays = 7
	s.cfg.ClientTokenCacheEnabled = &boolTrue

	got := s.buildClientConfig()
	if got == nil {
		t.Fatal("expected non-nil config")
	}
	if got["poll_interval"] != "5s" {
		t.Errorf("expected poll_interval=5s, got %v", got["poll_interval"])
	}
	if got["timeout"] != "10m0s" {
		t.Errorf("expected timeout=10m0s, got %v", got["timeout"])
	}
	if got["breakglass_enabled"] != true {
		t.Errorf("expected breakglass_enabled=true, got %v", got["breakglass_enabled"])
	}
	if got["breakglass_password_type"] != "passphrase" {
		t.Errorf("expected breakglass_password_type=passphrase, got %v", got["breakglass_password_type"])
	}
	if got["breakglass_rotation_days"] != 7 {
		t.Errorf("expected breakglass_rotation_days=7, got %v", got["breakglass_rotation_days"])
	}
	if got["token_cache_enabled"] != true {
		t.Errorf("expected token_cache_enabled=true, got %v", got["token_cache_enabled"])
	}
}

// ── computeOneTapToken tests ─────────────────────────────────────────────────

func TestComputeOneTapToken_NonEmpty(t *testing.T) {
	s := newAPITestServer(t, "test-secret")
	token := s.computeOneTapToken("challenge123abc456d", "alice", "web01", time.Now().Add(5*time.Minute))
	if token == "" {
		t.Error("expected non-empty one-tap token")
	}
	// Token format: {challenge_id}.{expires_unix}.{hmac_hex}
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		t.Errorf("expected 3 parts in token, got %d", len(parts))
	}
}

func TestComputeOneTapToken_EmptySecret(t *testing.T) {
	s := newAPITestServer(t, "")
	s.cfg.SharedSecret = ""
	token := s.computeOneTapToken("challenge123abc456d", "alice", "web01", time.Now().Add(5*time.Minute))
	if token != "" {
		t.Errorf("expected empty token for empty secret, got %q", token)
	}
}

func TestHandlePollChallenge_ExpiredChallenge(t *testing.T) {
	const secret = "test-secret"
	// Use a very short TTL so the challenge expires quickly.
	shortTTL := 50 * time.Millisecond
	store := newTestStore(t, shortTTL, 10*time.Minute)
	s := &Server{
		cfg: &config.ServerConfig{
			SharedSecret:  secret,
			SessionSecret: secret,
			ChallengeTTL:  shortTTL,
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
