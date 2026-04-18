package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rinseaid/identree/internal/breakglass"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/escrow"
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

// ── handleBreakglassEscrow tests ─────────────────────────────────────────────

// newBreakglassTestServer returns a server wired with the local escrow backend
// plus a derived AES key so escrow round-trips work end-to-end.
func newBreakglassTestServer(t *testing.T, secret string) *Server {
	t.Helper()
	store := newTestStore(t, 5*time.Minute, 10*time.Minute)
	key, err := escrow.DeriveEscrowKey("test-encryption-key-material", nil)
	if err != nil {
		t.Fatalf("derive escrow key: %v", err)
	}
	notifyCfg := &notify.NotificationConfig{}
	return &Server{
		cfg: &config.ServerConfig{
			SharedSecret:  secret,
			SessionSecret: secret,
			EscrowSecret:  secret,
			EscrowBackend: config.EscrowBackendLocal,
			ChallengeTTL:  5 * time.Minute,
		},
		store:           store,
		hostRegistry:    NewHostRegistry(""),
		authFailRL:      newAuthFailTracker(),
		mutationRL:      newMutationRateLimiter(),
		sseBroadcaster:  noopBroadcaster{},
		policyEngine:    policy.NewEngine(nil),
		notifyCfg:       notifyCfg,
		escrowSemaphore: make(chan struct{}, 5),
		escrowKey:       key,
	}
}

// postEscrow issues a signed POST /api/breakglass/escrow with the canonical
// HMAC token and current timestamp. tsOverride/tokenOverride inject bad values.
func postEscrow(s *Server, body map[string]string, secret, tsOverride, tokenOverride string) *httptest.ResponseRecorder {
	jsonBody, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/breakglass/escrow", bytes.NewReader(jsonBody))
	r.Header.Set("Content-Type", "application/json")
	if secret != "" {
		r.Header.Set("X-Shared-Secret", secret)
	}
	ts := tsOverride
	if ts == "" {
		ts = fmt.Sprintf("%d", time.Now().Unix())
	}
	r.Header.Set("X-Escrow-Ts", ts)
	token := tokenOverride
	if token == "" {
		token = breakglass.ComputeEscrowToken(secret, body["hostname"], ts)
	}
	r.Header.Set("X-Escrow-Token", token)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleBreakglassEscrow(w, r)
	return w
}

func TestHandleBreakglassEscrow_Success(t *testing.T) {
	const secret = "test-secret"
	s := newBreakglassTestServer(t, secret)

	w := postEscrow(s, map[string]string{"hostname": "web01", "password": "supersekret"}, secret, "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if _, ok := s.store.EscrowedHosts()["web01"]; !ok {
		t.Error("expected escrow record for web01")
	}
	ct, ok := s.store.GetEscrowCiphertext("web01")
	if !ok || ct == "" {
		t.Error("expected non-empty ciphertext stored for web01")
	}
}

func TestHandleBreakglassEscrow_MissingSharedSecret(t *testing.T) {
	const secret = "test-secret"
	s := newBreakglassTestServer(t, secret)

	w := postEscrow(s, map[string]string{"hostname": "web01", "password": "p"}, "", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d; body: %s", w.Code, w.Body.String())
	}
	if _, ok := s.store.EscrowedHosts()["web01"]; ok {
		t.Error("escrow record must not exist after unauthorized request")
	}
}

func TestHandleBreakglassEscrow_WrongEscrowToken(t *testing.T) {
	const secret = "test-secret"
	s := newBreakglassTestServer(t, secret)

	w := postEscrow(s, map[string]string{"hostname": "web01", "password": "p"}, secret, "", "deadbeefbad")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid escrow token") {
		t.Errorf("expected 'invalid escrow token' error, got %s", w.Body.String())
	}
	if _, ok := s.store.EscrowedHosts()["web01"]; ok {
		t.Error("escrow record must not exist after bad token")
	}
}

func TestHandleBreakglassEscrow_TokenForDifferentHost(t *testing.T) {
	const secret = "test-secret"
	s := newBreakglassTestServer(t, secret)

	// Token computed for victimhost but body claims web01 — must reject so a
	// compromised host cannot plant passwords for a different target.
	ts := fmt.Sprintf("%d", time.Now().Unix())
	wrongHostToken := breakglass.ComputeEscrowToken(secret, "victimhost", ts)
	w := postEscrow(s, map[string]string{"hostname": "web01", "password": "p"}, secret, ts, wrongHostToken)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleBreakglassEscrow_StaleTimestamp(t *testing.T) {
	const secret = "test-secret"
	s := newBreakglassTestServer(t, secret)

	// Timestamp outside the ±1 minute window — must be rejected to prevent replay.
	staleTs := fmt.Sprintf("%d", time.Now().Add(-10*time.Minute).Unix())
	token := breakglass.ComputeEscrowToken(secret, "web01", staleTs)
	w := postEscrow(s, map[string]string{"hostname": "web01", "password": "p"}, secret, staleTs, token)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "out of window") {
		t.Errorf("expected window error, got %s", w.Body.String())
	}
}

func TestHandleBreakglassEscrow_ReplayAttack(t *testing.T) {
	const secret = "test-secret"
	s := newBreakglassTestServer(t, secret)

	ts := fmt.Sprintf("%d", time.Now().Unix())
	token := breakglass.ComputeEscrowToken(secret, "web01", ts)

	w1 := postEscrow(s, map[string]string{"hostname": "web01", "password": "p"}, secret, ts, token)
	if w1.Code != http.StatusOK {
		t.Fatalf("first: expected 200, got %d; body: %s", w1.Code, w1.Body.String())
	}

	// Replay with identical (hostname, timestamp) within the window — must be rejected.
	w2 := postEscrow(s, map[string]string{"hostname": "web01", "password": "p2"}, secret, ts, token)
	if w2.Code != http.StatusGone {
		t.Errorf("replay: expected 410, got %d; body: %s", w2.Code, w2.Body.String())
	}
}

func TestHandleBreakglassEscrow_MalformedJSON(t *testing.T) {
	const secret = "test-secret"
	s := newBreakglassTestServer(t, secret)

	r := httptest.NewRequest(http.MethodPost, "/api/breakglass/escrow", bytes.NewReader([]byte("{not-json")))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Shared-Secret", secret)
	ts := fmt.Sprintf("%d", time.Now().Unix())
	r.Header.Set("X-Escrow-Ts", ts)
	r.Header.Set("X-Escrow-Token", breakglass.ComputeEscrowToken(secret, "web01", ts))
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleBreakglassEscrow(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleBreakglassEscrow_MissingPassword(t *testing.T) {
	const secret = "test-secret"
	s := newBreakglassTestServer(t, secret)

	w := postEscrow(s, map[string]string{"hostname": "web01"}, secret, "", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "password required") {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}

func TestHandleBreakglassEscrow_RejectsWhenUnconfigured(t *testing.T) {
	// No SharedSecret + no host registry → must 403 before any body processing.
	store := newTestStore(t, 5*time.Minute, 10*time.Minute)
	s := &Server{
		cfg:             &config.ServerConfig{},
		store:           store,
		hostRegistry:    NewHostRegistry(""),
		authFailRL:      newAuthFailTracker(),
		mutationRL:      newMutationRateLimiter(),
		sseBroadcaster:  noopBroadcaster{},
		policyEngine:    policy.NewEngine(nil),
		notifyCfg:       &notify.NotificationConfig{},
		escrowSemaphore: make(chan struct{}, 5),
	}

	body, _ := json.Marshal(map[string]string{"hostname": "web01", "password": "p"})
	r := httptest.NewRequest(http.MethodPost, "/api/breakglass/escrow", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleBreakglassEscrow(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleBreakglassEscrow_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newBreakglassTestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/api/breakglass/escrow", nil)
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleBreakglassEscrow(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── handleBreakglassReveal tests ─────────────────────────────────────────────

// newBreakglassAdminServer prepares a server with local escrow AND the state
// required by verifyJSONAdminAuth (notify store, revokedNonces, removedUsers).
func newBreakglassAdminServer(t *testing.T, secret string) *Server {
	t.Helper()
	s := newBreakglassTestServer(t, secret)
	s.notifyStore = &memConfigStore{cfg: s.notifyCfg}
	s.revokedNonces = make(map[string]time.Time)
	s.removedUsers = make(map[string]time.Time)
	return s
}

// seedEscrow stores a ciphertext for hostname using the local backend so reveal
// has something to retrieve, then records the escrow row.
func seedEscrow(t *testing.T, s *Server, hostname, password string) {
	t.Helper()
	backend := escrow.NewLocalEscrowBackend(s.escrowKey, s.store)
	if _, _, err := backend.Store(context.Background(), hostname, password, ""); err != nil {
		t.Fatalf("seed escrow: %v", err)
	}
	s.store.RecordEscrow(hostname, "", "")
}

func buildAdminReveal(secret, username, hostname string) *http.Request {
	ts := time.Now().Unix()
	csrfTs := fmt.Sprintf("%d", ts)
	csrfToken := computeCSRFToken(secret, username, csrfTs)
	sessionCookie := makeCookie(secret, username, "admin", ts)
	body, _ := json.Marshal(map[string]string{"hostname": hostname})
	r := httptest.NewRequest(http.MethodPost, "/api/breakglass/reveal", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrfToken)
	r.Header.Set("X-CSRF-Ts", csrfTs)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
	r.RemoteAddr = "10.0.0.1:12345"
	return r
}

func TestHandleBreakglassReveal_AdminSuccess(t *testing.T) {
	const secret = "test-secret"
	s := newBreakglassAdminServer(t, secret)
	seedEscrow(t, s, "web01", "rotated-password-123")

	r := buildAdminReveal(secret, "admin-user", "web01")
	w := httptest.NewRecorder()
	s.handleBreakglassReveal(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["password"] != "rotated-password-123" {
		t.Errorf("expected decrypted password, got %q", resp["password"])
	}
	actions := s.store.ActionHistory("admin-user", 10)
	found := false
	for _, a := range actions {
		if a.Hostname == "web01" && strings.Contains(strings.ToLower(string(a.Action)), "breakglass") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected breakglass reveal action in admin audit log, got %+v", actions)
	}
}

func TestHandleBreakglassReveal_NonAdmin(t *testing.T) {
	const secret = "test-secret"
	s := newBreakglassAdminServer(t, secret)
	seedEscrow(t, s, "web01", "secret")

	ts := time.Now().Unix()
	csrfTs := fmt.Sprintf("%d", ts)
	csrfToken := computeCSRFToken(secret, "bob", csrfTs)
	sessionCookie := makeCookie(secret, "bob", "user", ts)
	body, _ := json.Marshal(map[string]string{"hostname": "web01"})
	r := httptest.NewRequest(http.MethodPost, "/api/breakglass/reveal", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrfToken)
	r.Header.Set("X-CSRF-Ts", csrfTs)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleBreakglassReveal(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for non-admin, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleBreakglassReveal_NoEscrowRecord(t *testing.T) {
	const secret = "test-secret"
	s := newBreakglassAdminServer(t, secret)

	r := buildAdminReveal(secret, "admin-user", "ghosthost")
	w := httptest.NewRecorder()
	s.handleBreakglassReveal(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleBreakglassReveal_InvalidHostname(t *testing.T) {
	const secret = "test-secret"
	s := newBreakglassAdminServer(t, secret)

	r := buildAdminReveal(secret, "admin-user", "bad hostname!")
	w := httptest.NewRecorder()
	s.handleBreakglassReveal(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleBreakglassReveal_MultipleRevealsAuditedSeparately(t *testing.T) {
	const secret = "test-secret"
	s := newBreakglassAdminServer(t, secret)
	seedEscrow(t, s, "web01", "pw")

	for i := 0; i < 3; i++ {
		r := buildAdminReveal(secret, "admin-user", "web01")
		w := httptest.NewRecorder()
		s.handleBreakglassReveal(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("reveal %d: expected 200, got %d", i, w.Code)
		}
	}

	actions := s.store.ActionHistory("admin-user", 10)
	count := 0
	for _, a := range actions {
		if a.Hostname == "web01" && strings.Contains(strings.ToLower(string(a.Action)), "breakglass") {
			count++
		}
	}
	if count < 3 {
		t.Errorf("expected at least 3 audit entries for 3 reveals, got %d", count)
	}
}

func TestHandleBreakglassReveal_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newBreakglassAdminServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/api/breakglass/reveal", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleBreakglassReveal(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── handleBreakglassReport tests ─────────────────────────────────────────────

func TestHandleBreakglassReport_Success(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	body, _ := json.Marshal(map[string]interface{}{
		"hostname":  "web01",
		"username":  "alice",
		"timestamp": time.Now().Unix(),
	})
	r := httptest.NewRequest(http.MethodPost, "/api/breakglass/report", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleBreakglassReport(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	actions := s.store.ActionHistory("alice", 10)
	found := false
	for _, a := range actions {
		if a.Hostname == "web01" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected action log entry for alice@web01, got %+v", actions)
	}
}

func TestHandleBreakglassReport_Unauthorized(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	body, _ := json.Marshal(map[string]interface{}{
		"hostname":  "web01",
		"username":  "alice",
		"timestamp": time.Now().Unix(),
	})
	r := httptest.NewRequest(http.MethodPost, "/api/breakglass/report", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	// No X-Shared-Secret.
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleBreakglassReport(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleBreakglassReport_MissingFields(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	body, _ := json.Marshal(map[string]interface{}{
		"hostname": "web01",
		// username missing
	})
	r := httptest.NewRequest(http.MethodPost, "/api/breakglass/report", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleBreakglassReport(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleBreakglassReport_InvalidHostname(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	body, _ := json.Marshal(map[string]interface{}{
		"hostname":  "bad host!",
		"username":  "alice",
		"timestamp": time.Now().Unix(),
	})
	r := httptest.NewRequest(http.MethodPost, "/api/breakglass/report", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleBreakglassReport(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleBreakglassReport_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/api/breakglass/report", nil)
	r.Header.Set("X-Shared-Secret", secret)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleBreakglassReport(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── verifyMTLSClient tests ───────────────────────────────────────────────────

// makeTestCA generates an in-memory self-signed CA for client-cert verification.
func makeTestCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen CA key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("sign CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return cert, key
}

// issueClientCert produces a leaf client cert signed by ca with the given
// hostname (CN + DNS SAN) and validity bounds.
func issueClientCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, hostname string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen client key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	_ = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return leaf
}

func mtlsRequest(peers []*x509.Certificate) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/challenge", nil)
	if peers != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: peers}
	}
	return r
}

func newMTLSServer(t *testing.T, caCert *x509.Certificate) *Server {
	t.Helper()
	return &Server{
		cfg:            &config.ServerConfig{MTLSEnabled: true},
		mtlsCACert:     caCert,
		store:          newTestStore(t, 5*time.Minute, 10*time.Minute),
		hostRegistry:   NewHostRegistry(""),
		authFailRL:     newAuthFailTracker(),
		mutationRL:     newMutationRateLimiter(),
		sseBroadcaster: noopBroadcaster{},
		policyEngine:   policy.NewEngine(nil),
		notifyCfg:      &notify.NotificationConfig{},
	}
}

func TestVerifyMTLSClient_Disabled(t *testing.T) {
	s := &Server{cfg: &config.ServerConfig{MTLSEnabled: false}}
	host, err := s.verifyMTLSClient(mtlsRequest(nil))
	if err != nil || host != "" {
		t.Errorf("expected (\"\", nil) when mTLS disabled, got (%q, %v)", host, err)
	}
}

func TestVerifyMTLSClient_NoPeerCerts(t *testing.T) {
	ca, _ := makeTestCA(t, "test-ca")
	s := newMTLSServer(t, ca)

	if _, err := s.verifyMTLSClient(mtlsRequest(nil)); err == nil {
		t.Error("expected error when no TLS connection")
	}
	if _, err := s.verifyMTLSClient(mtlsRequest([]*x509.Certificate{})); err == nil {
		t.Error("expected error when no peer certs")
	}
}

func TestVerifyMTLSClient_ValidCert(t *testing.T) {
	ca, caKey := makeTestCA(t, "test-ca")
	s := newMTLSServer(t, ca)
	leaf := issueClientCert(t, ca, caKey, "web01", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	host, err := s.verifyMTLSClient(mtlsRequest([]*x509.Certificate{leaf}))
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if host != "web01" {
		t.Errorf("expected hostname web01, got %q", host)
	}
}

func TestVerifyMTLSClient_WrongCA(t *testing.T) {
	trustedCA, _ := makeTestCA(t, "trusted-ca")
	s := newMTLSServer(t, trustedCA)

	attackerCA, attackerKey := makeTestCA(t, "attacker-ca")
	leaf := issueClientCert(t, attackerCA, attackerKey, "web01", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	if _, err := s.verifyMTLSClient(mtlsRequest([]*x509.Certificate{leaf})); err == nil {
		t.Error("expected verification to fail for cert signed by untrusted CA")
	}
}

func TestVerifyMTLSClient_ExpiredCert(t *testing.T) {
	ca, caKey := makeTestCA(t, "test-ca")
	s := newMTLSServer(t, ca)
	leaf := issueClientCert(t, ca, caKey, "web01", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))

	if _, err := s.verifyMTLSClient(mtlsRequest([]*x509.Certificate{leaf})); err == nil {
		t.Error("expected verification to fail for expired cert")
	}
}

func TestVerifyMTLSClient_RegistryRejectsUnregisteredHost(t *testing.T) {
	ca, caKey := makeTestCA(t, "test-ca")
	s := newMTLSServer(t, ca)
	// Register a different host so IsEnabled() is true but web01 is NOT allowed.
	if _, err := s.hostRegistry.AddHost("other01", []string{"*"}, ""); err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	leaf := issueClientCert(t, ca, caKey, "web01", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	if _, err := s.verifyMTLSClient(mtlsRequest([]*x509.Certificate{leaf})); err == nil {
		t.Error("expected rejection when hostname not in registry")
	}
}

// ── authenticateChallenge targeted tests ─────────────────────────────────────

func TestAuthenticateChallenge_SharedSecretAccepted(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	r := httptest.NewRequest(http.MethodPost, "/api/challenge", nil)
	r.Header.Set("X-Shared-Secret", secret)
	ok, msg := s.authenticateChallenge(r, "web01", "alice")
	if !ok {
		t.Errorf("expected success with valid shared secret, got msg=%q", msg)
	}
}

func TestAuthenticateChallenge_WrongSecret(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)

	r := httptest.NewRequest(http.MethodPost, "/api/challenge", nil)
	r.Header.Set("X-Shared-Secret", "wrong")
	ok, msg := s.authenticateChallenge(r, "web01", "alice")
	if ok {
		t.Error("expected failure with wrong shared secret")
	}
	if msg != "unauthorized" {
		t.Errorf("expected 'unauthorized' message, got %q", msg)
	}
}

func TestAuthenticateChallenge_MTLSRejected(t *testing.T) {
	ca, _ := makeTestCA(t, "test-ca")
	s := newMTLSServer(t, ca)

	r := httptest.NewRequest(http.MethodPost, "/api/challenge", nil)
	ok, msg := s.authenticateChallenge(r, "web01", "alice")
	if ok {
		t.Error("expected failure when mTLS enabled and no cert presented")
	}
	if !strings.HasPrefix(msg, "mTLS:") {
		t.Errorf("expected mTLS-prefixed error, got %q", msg)
	}
}

func TestAuthenticateChallenge_MTLSUserNotAuthorized(t *testing.T) {
	ca, caKey := makeTestCA(t, "test-ca")
	s := newMTLSServer(t, ca)
	// Register web01 but only for user bob — alice must be rejected.
	if _, err := s.hostRegistry.AddHost("web01", []string{"bob"}, ""); err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	leaf := issueClientCert(t, ca, caKey, "web01", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	r := mtlsRequest([]*x509.Certificate{leaf})
	r.Method = http.MethodPost

	ok, msg := s.authenticateChallenge(r, "web01", "alice")
	if ok {
		t.Error("expected alice to be rejected (not in host's user list)")
	}
	if !strings.Contains(msg, "not authorized") {
		t.Errorf("expected 'not authorized' message, got %q", msg)
	}
}

func TestAuthenticateChallenge_SharedSecretRequiresHostnameWhenRegistryEnabled(t *testing.T) {
	const secret = "test-secret"
	s := newAPITestServer(t, secret)
	if _, err := s.hostRegistry.AddHost("web01", []string{"*"}, ""); err != nil {
		t.Fatalf("AddHost: %v", err)
	}

	r := httptest.NewRequest(http.MethodPost, "/api/challenge", nil)
	r.Header.Set("X-Shared-Secret", secret)
	// Empty hostname → must reject so a caller cannot sidestep per-host
	// user authorization by omitting the hostname field.
	ok, msg := s.authenticateChallenge(r, "", "alice")
	if ok {
		t.Error("expected rejection when hostname is empty and registry enabled")
	}
	if !strings.Contains(msg, "hostname required") {
		t.Errorf("expected hostname-required error, got %q", msg)
	}
}

func TestAuthenticateChallenge_PerHostSecretAccepted(t *testing.T) {
	// No global SharedSecret — must authenticate via per-host secret in registry.
	store := newTestStore(t, 5*time.Minute, 10*time.Minute)
	s := &Server{
		cfg:            &config.ServerConfig{ChallengeTTL: 5 * time.Minute},
		store:          store,
		hostRegistry:   NewHostRegistry(""),
		authFailRL:     newAuthFailTracker(),
		mutationRL:     newMutationRateLimiter(),
		sseBroadcaster: noopBroadcaster{},
		policyEngine:   policy.NewEngine(nil),
		notifyCfg:      &notify.NotificationConfig{},
	}
	hostSecret, err := s.hostRegistry.AddHost("web01", []string{"alice"}, "")
	if err != nil {
		t.Fatalf("AddHost: %v", err)
	}

	r := httptest.NewRequest(http.MethodPost, "/api/challenge", nil)
	r.Header.Set("X-Shared-Secret", hostSecret)
	ok, _ := s.authenticateChallenge(r, "web01", "alice")
	if !ok {
		t.Error("expected per-host secret to authenticate")
	}

	ok, msg := s.authenticateChallenge(r, "web01", "mallory")
	if ok {
		t.Error("expected user outside host list to be rejected")
	}
	if !strings.Contains(msg, "not authorized") {
		t.Errorf("expected 'not authorized' message, got %q", msg)
	}
}
