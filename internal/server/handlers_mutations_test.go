package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/policy"
)

// newMutationTestServer builds a minimal *Server suitable for mutation handler
// tests with a working session/CSRF system.
func newMutationTestServer(t *testing.T, secret string) *Server {
	t.Helper()
	store := challpkg.NewChallengeStore(5*time.Minute, 10*time.Minute, filepath.Join(t.TempDir(), "state.json"))
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

// buildFormRequest constructs a POST request with form-encoded body, a valid
// session cookie, and a matching CSRF token for the given username and role.
func buildFormRequest(secret, username, role, path string, formValues url.Values) *http.Request {
	ts := time.Now().Unix()
	tsStr := fmt.Sprintf("%d", ts)
	csrfToken := computeCSRFToken(secret, username, tsStr)

	formValues.Set("username", username)
	formValues.Set("csrf_token", csrfToken)
	formValues.Set("csrf_ts", tsStr)

	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(formValues.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "10.0.0.1:12345"

	// Add session cookie.
	cookieVal := makeCookie(secret, username, role, ts)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	return r
}

// createPendingChallenge creates a challenge via the store and returns it.
func createPendingChallenge(t *testing.T, s *Server, username, hostname string) *challpkg.Challenge {
	t.Helper()
	c, err := s.store.Create(username, hostname, "", "")
	if err != nil {
		t.Fatalf("failed to create challenge: %v", err)
	}
	return c
}

// ── handleBulkApprove tests ──────────────────────────────────────────────────

func TestHandleBulkApprove_NonExistentChallenge(t *testing.T) {
	const secret = "test-secret"
	s := newMutationTestServer(t, secret)

	form := url.Values{
		"challenge_id": {"deadbeefdeadbeefdeadbeefdeadbeef"},
	}
	r := buildFormRequest(secret, "alice", "admin", "/api/challenges/approve", form)
	w := httptest.NewRecorder()
	s.handleBulkApprove(w, r)

	// Should render an error page with 404.
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleBulkApprove_NonAdminOnAdminRequired(t *testing.T) {
	const secret = "test-secret"
	s := newMutationTestServer(t, secret)

	// Set a policy that requires admin for this host.
	s.policyEngine = policy.NewEngine([]policy.Policy{
		{Name: "prod", MatchHosts: []string{"prod-*"}, RequireAdmin: true},
	})

	// Use the API handler to create a challenge with policy applied.
	createBody := map[string]string{
		"username": "bob",
		"hostname": "prod-db",
	}
	cw := postChallenge(s, createBody, secret)
	if cw.Code != http.StatusCreated {
		t.Fatalf("setup: expected 201, got %d; body: %s", cw.Code, cw.Body.String())
	}
	var createResp map[string]interface{}
	if err := json.NewDecoder(cw.Body).Decode(&createResp); err != nil {
		t.Fatal(err)
	}
	challengeID := createResp["challenge_id"].(string)

	// Now try to approve as a non-admin user.
	form := url.Values{
		"challenge_id": {challengeID},
	}
	r := buildFormRequest(secret, "bob", "user", "/api/challenges/approve", form)
	w := httptest.NewRecorder()
	s.handleBulkApprove(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ── handleRejectChallenge tests ──────────────────────────────────────────────

func TestHandleRejectChallenge_WithReason(t *testing.T) {
	const secret = "test-secret"
	s := newMutationTestServer(t, secret)

	c := createPendingChallenge(t, s, "alice", "web01")

	form := url.Values{
		"challenge_id": {c.ID},
		"deny_reason":  {"security concern"},
	}
	r := buildFormRequest(secret, "alice", "user", "/api/challenges/reject", form)
	w := httptest.NewRecorder()
	s.handleRejectChallenge(w, r)

	// Should redirect (303) on success.
	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify the challenge is denied.
	ch, ok := s.store.Get(c.ID)
	if !ok {
		t.Fatal("challenge not found after rejection")
	}
	if ch.Status != challpkg.StatusDenied {
		t.Errorf("expected status denied, got %q", ch.Status)
	}
	if ch.DenyReason != "security concern" {
		t.Errorf("expected deny reason 'security concern', got %q", ch.DenyReason)
	}
}

func TestHandleRejectChallenge_WithoutReason(t *testing.T) {
	const secret = "test-secret"
	s := newMutationTestServer(t, secret)

	c := createPendingChallenge(t, s, "alice", "web01")

	form := url.Values{
		"challenge_id": {c.ID},
	}
	r := buildFormRequest(secret, "alice", "user", "/api/challenges/reject", form)
	w := httptest.NewRecorder()
	s.handleRejectChallenge(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	ch, ok := s.store.Get(c.ID)
	if !ok {
		t.Fatal("challenge not found after rejection")
	}
	if ch.Status != challpkg.StatusDenied {
		t.Errorf("expected status denied, got %q", ch.Status)
	}
	if ch.DenyReason != "" {
		t.Errorf("expected empty deny reason, got %q", ch.DenyReason)
	}
}

// ── Multi-approval tests ─────────────────────────────────────────────────────

func TestHandleBulkApprove_MultiApproval_Partial(t *testing.T) {
	const secret = "test-secret"
	s := newMutationTestServer(t, secret)

	// Set a policy that requires 2 approvals.
	s.policyEngine = policy.NewEngine([]policy.Policy{
		{Name: "dual", MatchHosts: []string{"prod-*"}, RequireAdmin: false, MinApprovals: 2},
	})

	// Create challenge via API so policy is applied.
	cw := postChallenge(s, map[string]string{
		"username": "bob",
		"hostname": "prod-web",
	}, secret)
	if cw.Code != http.StatusCreated {
		t.Fatalf("setup: expected 201, got %d; body: %s", cw.Code, cw.Body.String())
	}
	var createResp map[string]interface{}
	if err := json.NewDecoder(cw.Body).Decode(&createResp); err != nil {
		t.Fatal(err)
	}
	challengeID := createResp["challenge_id"].(string)

	// First admin approves → partial (should redirect 303 with partial_approve flash).
	form := url.Values{
		"challenge_id": {challengeID},
	}
	r := buildFormRequest(secret, "admin1", "admin", "/api/challenges/approve", form)
	w := httptest.NewRecorder()
	s.handleBulkApprove(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("first approval: expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify challenge is still pending.
	ch, ok := s.store.Get(challengeID)
	if !ok {
		t.Fatal("challenge not found after partial approval")
	}
	if ch.Status != challpkg.StatusPending {
		t.Errorf("after first approval: expected pending, got %q", ch.Status)
	}
	if len(ch.Approvals) != 1 {
		t.Errorf("expected 1 approval record, got %d", len(ch.Approvals))
	}
}

func TestHandleBulkApprove_MultiApproval_Full(t *testing.T) {
	const secret = "test-secret"
	s := newMutationTestServer(t, secret)

	s.policyEngine = policy.NewEngine([]policy.Policy{
		{Name: "dual", MatchHosts: []string{"prod-*"}, RequireAdmin: false, MinApprovals: 2},
	})

	cw := postChallenge(s, map[string]string{
		"username": "bob",
		"hostname": "prod-web",
	}, secret)
	if cw.Code != http.StatusCreated {
		t.Fatalf("setup: expected 201, got %d; body: %s", cw.Code, cw.Body.String())
	}
	var createResp map[string]interface{}
	json.NewDecoder(cw.Body).Decode(&createResp)
	challengeID := createResp["challenge_id"].(string)

	// First approval (partial).
	form1 := url.Values{"challenge_id": {challengeID}}
	r1 := buildFormRequest(secret, "admin1", "admin", "/api/challenges/approve", form1)
	w1 := httptest.NewRecorder()
	s.handleBulkApprove(w1, r1)
	if w1.Code != http.StatusSeeOther {
		t.Fatalf("first approval: expected 303, got %d", w1.Code)
	}

	// Second approval by a different admin → fully approved.
	form2 := url.Values{"challenge_id": {challengeID}}
	r2 := buildFormRequest(secret, "admin2", "admin", "/api/challenges/approve", form2)
	w2 := httptest.NewRecorder()
	s.handleBulkApprove(w2, r2)
	if w2.Code != http.StatusSeeOther {
		t.Fatalf("second approval: expected 303, got %d; body: %s", w2.Code, w2.Body.String())
	}

	// Verify challenge is now approved.
	ch, ok := s.store.Get(challengeID)
	if !ok {
		t.Fatal("challenge not found after full approval")
	}
	if ch.Status != challpkg.StatusApproved {
		t.Errorf("after second approval: expected approved, got %q", ch.Status)
	}
}

// ── Break-glass override tests ───────────────────────────────────────────────

func TestHandleBreakglassOverride_Allowed(t *testing.T) {
	const secret = "test-secret"
	s := newMutationTestServer(t, secret)

	// Set a policy with break-glass bypass allowed.
	s.policyEngine = policy.NewEngine([]policy.Policy{
		{Name: "critical", MatchHosts: []string{"critical-*"}, RequireAdmin: true, BreakglassBypass: true},
	})

	// Create challenge via API so policy fields are populated.
	cw := postChallenge(s, map[string]string{
		"username": "bob",
		"hostname": "critical-db",
	}, secret)
	if cw.Code != http.StatusCreated {
		t.Fatalf("setup: expected 201, got %d; body: %s", cw.Code, cw.Body.String())
	}
	var createResp map[string]interface{}
	json.NewDecoder(cw.Body).Decode(&createResp)
	challengeID := createResp["challenge_id"].(string)

	// Admin uses break-glass override.
	form := url.Values{"challenge_id": {challengeID}}
	r := buildFormRequest(secret, "admin-user", "admin", "/api/challenges/override", form)
	w := httptest.NewRecorder()
	s.handleBreakglassOverride(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify the challenge is approved and marked as break-glass override.
	ch, ok := s.store.Get(challengeID)
	if !ok {
		t.Fatal("challenge not found after override")
	}
	if ch.Status != challpkg.StatusApproved {
		t.Errorf("expected approved, got %q", ch.Status)
	}
	if !ch.BreakglassOverride {
		t.Error("expected BreakglassOverride to be true")
	}
}

func TestHandleBreakglassOverride_NotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newMutationTestServer(t, secret)

	// Set a policy WITHOUT break-glass bypass.
	s.policyEngine = policy.NewEngine([]policy.Policy{
		{Name: "prod", MatchHosts: []string{"prod-*"}, RequireAdmin: true, BreakglassBypass: false},
	})

	cw := postChallenge(s, map[string]string{
		"username": "bob",
		"hostname": "prod-web",
	}, secret)
	if cw.Code != http.StatusCreated {
		t.Fatalf("setup: expected 201, got %d; body: %s", cw.Code, cw.Body.String())
	}
	var createResp map[string]interface{}
	json.NewDecoder(cw.Body).Decode(&createResp)
	challengeID := createResp["challenge_id"].(string)

	// Admin tries break-glass override → should be rejected.
	form := url.Values{"challenge_id": {challengeID}}
	r := buildFormRequest(secret, "admin-user", "admin", "/api/challenges/override", form)
	w := httptest.NewRecorder()
	s.handleBreakglassOverride(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify challenge is still pending.
	ch, ok := s.store.Get(challengeID)
	if !ok {
		t.Fatal("challenge not found")
	}
	if ch.Status != challpkg.StatusPending {
		t.Errorf("expected pending, got %q", ch.Status)
	}
}

func TestHandleBreakglassOverride_NonAdmin(t *testing.T) {
	const secret = "test-secret"
	s := newMutationTestServer(t, secret)

	s.policyEngine = policy.NewEngine([]policy.Policy{
		{Name: "critical", MatchHosts: []string{"critical-*"}, RequireAdmin: true, BreakglassBypass: true},
	})

	cw := postChallenge(s, map[string]string{
		"username": "bob",
		"hostname": "critical-db",
	}, secret)
	if cw.Code != http.StatusCreated {
		t.Fatalf("setup: expected 201, got %d", cw.Code)
	}
	var createResp map[string]interface{}
	json.NewDecoder(cw.Body).Decode(&createResp)
	challengeID := createResp["challenge_id"].(string)

	// Non-admin tries break-glass → should be rejected.
	form := url.Values{"challenge_id": {challengeID}}
	r := buildFormRequest(secret, "regular-user", "user", "/api/challenges/override", form)
	w := httptest.NewRecorder()
	s.handleBreakglassOverride(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", w.Code, w.Body.String())
	}
}
