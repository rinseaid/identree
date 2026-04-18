package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	challpkg "github.com/rinseaid/identree/internal/challenge"
)

// ── handleExtendSession ──────────────────────────────────────────────────────

func TestHandleExtendSession_Success(t *testing.T) {
	const secret = "s"
	s := newMutationTestServer(t, secret)
	s.cfg.GracePeriod = 10 * time.Minute
	s.store.CreateGraceSession("alice", "web01", 2*time.Minute)

	form := url.Values{"hostname": {"web01"}}
	r := buildFormRequest(secret, "alice", "user", "/api/sessions/extend", form)
	w := httptest.NewRecorder()
	s.handleExtendSession(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleExtendSession_MissingHostname(t *testing.T) {
	const secret = "s"
	s := newMutationTestServer(t, secret)

	r := buildFormRequest(secret, "alice", "user", "/api/sessions/extend", url.Values{})
	w := httptest.NewRecorder()
	s.handleExtendSession(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleExtendSession_InvalidHostname(t *testing.T) {
	const secret = "s"
	s := newMutationTestServer(t, secret)

	form := url.Values{"hostname": {"not a hostname"}}
	r := buildFormRequest(secret, "alice", "user", "/api/sessions/extend", form)
	w := httptest.NewRecorder()
	s.handleExtendSession(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleExtendSession_NoActiveSession(t *testing.T) {
	const secret = "s"
	s := newMutationTestServer(t, secret)

	form := url.Values{"hostname": {"web01"}}
	r := buildFormRequest(secret, "alice", "user", "/api/sessions/extend", form)
	w := httptest.NewRecorder()
	s.handleExtendSession(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleExtendSession_MethodNotAllowed(t *testing.T) {
	s := newMutationTestServer(t, "s")
	r := httptest.NewRequest(http.MethodGet, "/api/sessions/extend", nil)
	w := httptest.NewRecorder()
	s.handleExtendSession(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleExtendSession_WithDuration(t *testing.T) {
	const secret = "s"
	s := newMutationTestServer(t, secret)
	s.cfg.GracePeriod = 10 * time.Minute
	s.store.CreateGraceSession("alice", "web01", time.Minute)

	form := url.Values{"hostname": {"web01"}, "duration": {"300"}}
	r := buildFormRequest(secret, "alice", "user", "/api/sessions/extend", form)
	w := httptest.NewRecorder()
	s.handleExtendSession(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ── handleExtendAll ─────────────────────────────────────────────────────────

func TestHandleExtendAll_NoSessions(t *testing.T) {
	const secret = "s"
	s := newMutationTestServer(t, secret)
	s.cfg.GracePeriod = 10 * time.Minute

	r := buildFormRequest(secret, "alice", "user", "/api/sessions/extend-all", url.Values{})
	w := httptest.NewRecorder()
	s.handleExtendAll(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleExtendAll_ExtendsActive(t *testing.T) {
	const secret = "s"
	s := newMutationTestServer(t, secret)
	s.cfg.GracePeriod = 10 * time.Minute
	s.store.CreateGraceSession("alice", "web01", time.Minute)
	s.store.CreateGraceSession("alice", "web02", time.Minute)

	r := buildFormRequest(secret, "alice", "user", "/api/sessions/extend-all", url.Values{})
	w := httptest.NewRecorder()
	s.handleExtendAll(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ── handleRevokeAll ─────────────────────────────────────────────────────────

func TestHandleRevokeAll_User(t *testing.T) {
	const secret = "s"
	s := newMutationTestServer(t, secret)
	s.store.CreateGraceSession("alice", "web01", 10*time.Minute)
	s.store.CreateGraceSession("alice", "web02", 10*time.Minute)

	r := buildFormRequest(secret, "alice", "user", "/api/sessions/revoke-all", url.Values{})
	w := httptest.NewRecorder()
	s.handleRevokeAll(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}
	// Both alice sessions should be revoked.
	if sessions := s.store.ActiveSessions("alice"); len(sessions) != 0 {
		t.Errorf("expected 0 active sessions, got %d", len(sessions))
	}
}

func TestHandleRevokeAll_AdminGlobal(t *testing.T) {
	const secret = "s"
	s := newMutationTestServer(t, secret)
	s.store.CreateGraceSession("alice", "web01", 10*time.Minute)
	s.store.CreateGraceSession("bob", "web02", 10*time.Minute)

	r := buildFormRequest(secret, "admin", "admin", "/api/sessions/revoke-all", url.Values{})
	w := httptest.NewRecorder()
	s.handleRevokeAll(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}
	if s := s.store.AllActiveSessions(); len(s) != 0 {
		t.Errorf("expected 0 active sessions across users, got %d", len(s))
	}
}

func TestHandleRevokeAll_AdminSpecificUser(t *testing.T) {
	const secret = "s"
	s := newMutationTestServer(t, secret)
	s.store.CreateGraceSession("alice", "web01", 10*time.Minute)
	s.store.CreateGraceSession("bob", "web02", 10*time.Minute)

	form := url.Values{"session_username": {"alice"}}
	r := buildFormRequest(secret, "admin", "admin", "/api/sessions/revoke-all", form)
	w := httptest.NewRecorder()
	s.handleRevokeAll(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}
	if len(s.store.ActiveSessions("alice")) != 0 {
		t.Errorf("alice should have no sessions")
	}
	if len(s.store.ActiveSessions("bob")) == 0 {
		t.Errorf("bob should still have sessions")
	}
}

func TestHandleRevokeAll_NoSessions(t *testing.T) {
	const secret = "s"
	s := newMutationTestServer(t, secret)

	r := buildFormRequest(secret, "alice", "user", "/api/sessions/revoke-all", url.Values{})
	w := httptest.NewRecorder()
	s.handleRevokeAll(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}
}

func TestHandleRevokeAll_MethodNotAllowed(t *testing.T) {
	s := newMutationTestServer(t, "s")
	r := httptest.NewRequest(http.MethodGet, "/api/sessions/revoke-all", nil)
	w := httptest.NewRecorder()
	s.handleRevokeAll(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── handleBulkApproveAll ────────────────────────────────────────────────────

func TestHandleBulkApproveAll_NoPending(t *testing.T) {
	const secret = "s"
	s := newMutationTestServer(t, secret)

	r := buildFormRequest(secret, "alice", "user", "/api/challenges/approve-all", url.Values{})
	w := httptest.NewRecorder()
	s.handleBulkApproveAll(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}
}

func TestHandleBulkApproveAll_ApprovesAll(t *testing.T) {
	const secret = "s"
	s := newMutationTestServer(t, secret)

	c1 := createPendingChallenge(t, s, "alice", "web01")
	c2 := createPendingChallenge(t, s, "alice", "web02")

	r := buildFormRequest(secret, "alice", "user", "/api/challenges/approve-all", url.Values{})
	w := httptest.NewRecorder()
	s.handleBulkApproveAll(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}
	for _, id := range []string{c1.ID, c2.ID} {
		got, ok := s.store.Get(id)
		if !ok {
			t.Fatalf("challenge %s not found", id)
		}
		if got.Status != challpkg.StatusApproved {
			t.Errorf("challenge %s: got %q, want approved", id, got.Status)
		}
	}
}

func TestHandleBulkApproveAll_MethodNotAllowed(t *testing.T) {
	s := newMutationTestServer(t, "s")
	r := httptest.NewRequest(http.MethodGet, "/api/challenges/approve-all", nil)
	w := httptest.NewRecorder()
	s.handleBulkApproveAll(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── handleRejectAll ─────────────────────────────────────────────────────────

func TestHandleRejectAll_NoPending(t *testing.T) {
	const secret = "s"
	s := newMutationTestServer(t, secret)

	r := buildFormRequest(secret, "alice", "user", "/api/challenges/reject-all", url.Values{})
	w := httptest.NewRecorder()
	s.handleRejectAll(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}
}

func TestHandleRejectAll_RejectsAllWithReason(t *testing.T) {
	const secret = "s"
	s := newMutationTestServer(t, secret)

	c1 := createPendingChallenge(t, s, "alice", "web01")
	c2 := createPendingChallenge(t, s, "alice", "web02")

	form := url.Values{"deny_reason": {"all denied by alice"}}
	r := buildFormRequest(secret, "alice", "user", "/api/challenges/reject-all", form)
	w := httptest.NewRecorder()
	s.handleRejectAll(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}
	for _, id := range []string{c1.ID, c2.ID} {
		got, ok := s.store.Get(id)
		if !ok {
			t.Fatalf("challenge %s not found", id)
		}
		if got.Status != challpkg.StatusDenied {
			t.Errorf("challenge %s: got %q, want denied", id, got.Status)
		}
		if !strings.Contains(got.DenyReason, "all denied") {
			t.Errorf("challenge %s: deny reason = %q", id, got.DenyReason)
		}
	}
}

func TestHandleRejectAll_MethodNotAllowed(t *testing.T) {
	s := newMutationTestServer(t, "s")
	r := httptest.NewRequest(http.MethodGet, "/api/challenges/reject-all", nil)
	w := httptest.NewRecorder()
	s.handleRejectAll(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── handleOneTap ─────────────────────────────────────────────────────────────

// newOneTapServer returns a mutation test server configured for one-tap flows.
// OIDC freshness is marked for approver so the handler executes approvals rather
// than redirecting to login.
func newOneTapServer(t *testing.T, secret, approver string) *Server {
	t.Helper()
	s := newMutationTestServer(t, secret)
	s.cfg.OneTapMaxAge = 1 * time.Hour
	s.cfg.ChallengeTTL = 5 * time.Minute
	s.cfg.ExternalURL = "https://pam.example.com"
	s.store.RecordOIDCAuth(approver)
	return s
}

func onetapGetRequest(secret, user, token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/onetap/"+token, nil)
	// Attach a valid session cookie so getSessionUser succeeds for freshness checks.
	ts := time.Now().Unix()
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: makeCookie(secret, user, "user", ts)})
	return r
}

func onetapPostRequest(secret, user, role, token string, extra url.Values) *http.Request {
	if extra == nil {
		extra = url.Values{}
	}
	extra.Set("token", token)
	r := buildFormRequest(secret, user, role, "/api/onetap/"+token, extra)
	return r
}

func TestHandleOneTap_GETRendersConfirmation(t *testing.T) {
	const secret = "onetap-secret"
	s := newOneTapServer(t, secret, "alice")

	c := createPendingChallenge(t, s, "alice", "web01")
	token := s.computeOneTapToken(c.ID, "alice", "web01", c.ExpiresAt)

	r := onetapGetRequest(secret, "alice", token)
	w := httptest.NewRecorder()
	s.handleOneTap(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for GET confirmation, got %d; body: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "Approve sudo access") || !strings.Contains(body, "web01") {
		head := 400
		if len(body) < head {
			head = len(body)
		}
		t.Errorf("confirmation page missing expected content; body head: %s", body[:head])
	}
	// Must not approve on GET.
	got, _ := s.store.Get(c.ID)
	if got.Status != challpkg.StatusPending {
		t.Errorf("GET must not change status; got %q, want pending", got.Status)
	}
}

func TestHandleOneTap_POSTApproves(t *testing.T) {
	const secret = "onetap-secret"
	s := newOneTapServer(t, secret, "alice")

	c := createPendingChallenge(t, s, "alice", "web01")
	token := s.computeOneTapToken(c.ID, "alice", "web01", c.ExpiresAt)

	r := onetapPostRequest(secret, "alice", "user", token, nil)
	w := httptest.NewRecorder()
	s.handleOneTap(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 success page, got %d; body: %s", w.Code, w.Body.String())
	}
	got, _ := s.store.Get(c.ID)
	if got.Status != challpkg.StatusApproved {
		t.Errorf("status after POST: got %q, want approved", got.Status)
	}
	if got.ApprovedBy != "alice" {
		t.Errorf("approver: got %q, want alice", got.ApprovedBy)
	}
}

// TestHandleOneTap_TamperedHMAC verifies a byte-level tamper in the HMAC signature
// is rejected with 403. This is the core one-tap forgery defense.
func TestHandleOneTap_TamperedHMAC(t *testing.T) {
	const secret = "onetap-secret"
	s := newOneTapServer(t, secret, "alice")

	c := createPendingChallenge(t, s, "alice", "web01")
	token := s.computeOneTapToken(c.ID, "alice", "web01", c.ExpiresAt)

	// Flip the last hex character of the HMAC segment.
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("token format unexpected: %s", token)
	}
	last := parts[2]
	flipped := last[:len(last)-1]
	if last[len(last)-1] == 'a' {
		flipped += "b"
	} else {
		flipped += "a"
	}
	tampered := parts[0] + "." + parts[1] + "." + flipped

	r := onetapGetRequest(secret, "alice", tampered)
	w := httptest.NewRecorder()
	s.handleOneTap(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("tampered HMAC: got %d, want 403; body: %s", w.Code, w.Body.String())
	}
	got, _ := s.store.Get(c.ID)
	if got.Status != challpkg.StatusPending {
		t.Errorf("challenge must remain pending after tampered-HMAC reject; got %q", got.Status)
	}
}

// TestHandleOneTap_ExpiredTimestamp verifies the expiry gate returns 410 Gone.
func TestHandleOneTap_ExpiredTimestamp(t *testing.T) {
	const secret = "onetap-secret"
	s := newOneTapServer(t, secret, "alice")

	c := createPendingChallenge(t, s, "alice", "web01")
	// Build token with an already-expired expiry.
	expired := time.Now().Add(-1 * time.Minute)
	token := s.computeOneTapToken(c.ID, "alice", "web01", expired)

	r := onetapGetRequest(secret, "alice", token)
	w := httptest.NewRecorder()
	s.handleOneTap(w, r)

	if w.Code != http.StatusGone {
		t.Errorf("expired timestamp: got %d, want 410", w.Code)
	}
}

// TestHandleOneTap_CrossHostReplay verifies a token issued for a challenge on host A
// cannot be used to approve a challenge on host B, even if the challenge ID is
// swapped — the HMAC binds the challenge's hostname.
func TestHandleOneTap_CrossHostReplay(t *testing.T) {
	const secret = "onetap-secret"
	s := newOneTapServer(t, secret, "alice")

	cA := createPendingChallenge(t, s, "alice", "host-a")
	cB := createPendingChallenge(t, s, "alice", "host-b")

	// Token was legitimately minted for host-a's challenge.
	tokenA := s.computeOneTapToken(cA.ID, "alice", "host-a", cA.ExpiresAt)
	partsA := strings.SplitN(tokenA, ".", 3)

	// Attacker swaps in host-b's challenge ID but keeps host-a's HMAC.
	replay := cB.ID + "." + partsA[1] + "." + partsA[2]

	r := onetapGetRequest(secret, "alice", replay)
	w := httptest.NewRecorder()
	s.handleOneTap(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("cross-host replay: got %d, want 403", w.Code)
	}
	gotB, _ := s.store.Get(cB.ID)
	if gotB.Status != challpkg.StatusPending {
		t.Errorf("host-b challenge must remain pending after replay reject; got %q", gotB.Status)
	}
}

// TestHandleOneTap_StaleOIDCRedirects verifies that when the approver's OIDC
// auth is stale, the handler sets a resume cookie and redirects to login
// rather than burning the single-use token.
func TestHandleOneTap_StaleOIDCRedirects(t *testing.T) {
	const secret = "onetap-secret"
	s := newMutationTestServer(t, secret)
	s.cfg.OneTapMaxAge = 1 * time.Hour
	s.cfg.ChallengeTTL = 5 * time.Minute
	s.cfg.ExternalURL = "https://pam.example.com"
	// Intentionally do NOT record OIDC auth: freshness check must fail.

	c := createPendingChallenge(t, s, "alice", "web01")
	token := s.computeOneTapToken(c.ID, "alice", "web01", c.ExpiresAt)

	r := onetapGetRequest(secret, "alice", token)
	w := httptest.NewRecorder()
	s.handleOneTap(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("stale OIDC: got %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.HasSuffix(loc, "/sessions/login") {
		t.Errorf("stale OIDC location: got %q, want .../sessions/login", loc)
	}
	// Resume cookie must be set so the post-login redirect can continue the flow.
	foundCookie := false
	for _, c := range w.Result().Cookies() {
		if c.Name == "pam_onetap" && c.Value == token {
			foundCookie = true
		}
	}
	if !foundCookie {
		t.Error("stale OIDC: pam_onetap resume cookie not set")
	}
	// Critical: the challenge must still be pending — the token must not be burned.
	got, _ := s.store.Get(c.ID)
	if got.Status != challpkg.StatusPending {
		t.Errorf("stale OIDC redirect must not consume token; status=%q", got.Status)
	}
}

// TestHandleOneTap_AdminRequiredRejected verifies that challenges flagged
// RequireAdmin cannot be approved via one-tap at all — there is no session
// context to verify admin role on the approval URL itself.
func TestHandleOneTap_AdminRequiredRejected(t *testing.T) {
	const secret = "onetap-secret"
	s := newOneTapServer(t, secret, "alice")

	c := createPendingChallenge(t, s, "alice", "web01")
	s.store.SetChallengePolicy(c.ID, "admin-only", 1, true, false)
	reloaded, _ := s.store.Get(c.ID)
	token := s.computeOneTapToken(reloaded.ID, "alice", "web01", reloaded.ExpiresAt)

	r := onetapGetRequest(secret, "alice", token)
	w := httptest.NewRecorder()
	s.handleOneTap(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("admin-required one-tap: got %d, want 403", w.Code)
	}
	got, _ := s.store.Get(c.ID)
	if got.Status != challpkg.StatusPending {
		t.Errorf("admin-required challenge must remain pending; got %q", got.Status)
	}
}

func TestHandleOneTap_MalformedToken(t *testing.T) {
	const secret = "onetap-secret"
	s := newOneTapServer(t, secret, "alice")

	r := onetapGetRequest(secret, "alice", "not-a-valid-token")
	w := httptest.NewRecorder()
	s.handleOneTap(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("malformed token: got %d, want 400", w.Code)
	}
}

func TestHandleOneTap_MethodNotAllowed(t *testing.T) {
	s := newMutationTestServer(t, "s")
	r := httptest.NewRequest(http.MethodDelete, "/api/onetap/x.y.z", nil)
	w := httptest.NewRecorder()
	s.handleOneTap(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── handleElevate ────────────────────────────────────────────────────────────

func TestHandleElevate_AdminCanElevateOtherUser(t *testing.T) {
	const secret = "elev-secret"
	s := newMutationTestServer(t, secret)
	s.cfg.GracePeriod = 4 * time.Hour
	// Register the host with bob authorized so the authz check passes.
	if _, err := s.hostRegistry.AddHost("web01", []string{"bob"}, ""); err != nil {
		t.Fatalf("AddHost: %v", err)
	}

	form := url.Values{
		"hostname":    {"web01"},
		"duration":    {"3600"}, // 1h
		"target_user": {"bob"},
	}
	r := buildFormRequest(secret, "adminer", "admin", "/api/hosts/elevate", form)
	w := httptest.NewRecorder()
	s.handleElevate(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("admin elevate: got %d, want 303; body: %s", w.Code, w.Body.String())
	}
	sessions := s.store.ActiveSessions("bob")
	if len(sessions) != 1 || sessions[0].Hostname != "web01" {
		t.Fatalf("grace session for bob/web01 not created; got %+v", sessions)
	}
}

// TestHandleElevate_NonAdminCannotElevateOther enforces that a non-admin who
// submits a target_user other than themselves is rejected 403.
func TestHandleElevate_NonAdminCannotElevateOther(t *testing.T) {
	const secret = "elev-secret"
	s := newMutationTestServer(t, secret)
	s.cfg.GracePeriod = 4 * time.Hour
	if _, err := s.hostRegistry.AddHost("web01", []string{"alice", "bob"}, ""); err != nil {
		t.Fatalf("AddHost: %v", err)
	}

	form := url.Values{
		"hostname":    {"web01"},
		"duration":    {"3600"},
		"target_user": {"bob"},
	}
	r := buildFormRequest(secret, "alice", "user", "/api/hosts/elevate", form)
	w := httptest.NewRecorder()
	s.handleElevate(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("non-admin elevate other: got %d, want 403", w.Code)
	}
	if len(s.store.ActiveSessions("bob")) != 0 {
		t.Error("non-admin elevate other must not create session")
	}
}

// TestHandleElevate_NonAdminNoRegistryRejected: when the host registry is
// empty, only admins may elevate (no authorization list to consult).
func TestHandleElevate_NonAdminNoRegistryRejected(t *testing.T) {
	const secret = "elev-secret"
	s := newMutationTestServer(t, secret)
	s.cfg.GracePeriod = 4 * time.Hour

	form := url.Values{
		"hostname": {"web01"},
		"duration": {"3600"},
	}
	r := buildFormRequest(secret, "alice", "user", "/api/hosts/elevate", form)
	w := httptest.NewRecorder()
	s.handleElevate(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("non-admin no-registry: got %d, want 403; body: %s", w.Code, w.Body.String())
	}
	if len(s.store.ActiveSessions("alice")) != 0 {
		t.Error("non-admin no-registry must not create grace session")
	}
}

// TestHandleElevate_UnauthorizedForHost: registry is enabled but user is not
// listed in the host's users allowlist → 403.
func TestHandleElevate_UnauthorizedForHost(t *testing.T) {
	const secret = "elev-secret"
	s := newMutationTestServer(t, secret)
	s.cfg.GracePeriod = 4 * time.Hour
	if _, err := s.hostRegistry.AddHost("web01", []string{"bob"}, ""); err != nil {
		t.Fatalf("AddHost: %v", err)
	}

	form := url.Values{
		"hostname": {"web01"},
		"duration": {"3600"},
	}
	r := buildFormRequest(secret, "alice", "user", "/api/hosts/elevate", form)
	w := httptest.NewRecorder()
	s.handleElevate(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("unauthorized for host: got %d, want 403", w.Code)
	}
	if len(s.store.ActiveSessions("alice")) != 0 {
		t.Error("unauthorized elevate must not create session")
	}
}

func TestHandleElevate_InvalidHostname(t *testing.T) {
	const secret = "elev-secret"
	s := newMutationTestServer(t, secret)
	s.cfg.GracePeriod = 4 * time.Hour

	form := url.Values{
		"hostname": {"not a hostname!"},
		"duration": {"3600"},
	}
	r := buildFormRequest(secret, "alice", "admin", "/api/hosts/elevate", form)
	w := httptest.NewRecorder()
	s.handleElevate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid hostname: got %d, want 400", w.Code)
	}
}

// TestHandleElevate_DurationClamped verifies duration < 1h is clamped UP to 1h,
// and > GracePeriod is clamped DOWN to GracePeriod.
func TestHandleElevate_DurationClamped(t *testing.T) {
	const secret = "elev-secret"

	t.Run("below 1h clamps up", func(t *testing.T) {
		s := newMutationTestServer(t, secret)
		s.cfg.GracePeriod = 4 * time.Hour
		if _, err := s.hostRegistry.AddHost("web01", []string{"alice"}, ""); err != nil {
			t.Fatalf("AddHost: %v", err)
		}

		form := url.Values{
			"hostname": {"web01"},
			"duration": {"60"}, // 1 min — below 1h floor
		}
		r := buildFormRequest(secret, "alice", "admin", "/api/hosts/elevate", form)
		w := httptest.NewRecorder()
		s.handleElevate(w, r)

		sessions := s.store.ActiveSessions("alice")
		if len(sessions) != 1 {
			t.Fatalf("want 1 session, got %d", len(sessions))
		}
		remaining := time.Until(sessions[0].ExpiresAt)
		if remaining < 55*time.Minute || remaining > 65*time.Minute {
			t.Errorf("duration clamp up: got ~%v, want ~1h", remaining)
		}
	})

	t.Run("above GracePeriod clamps down", func(t *testing.T) {
		s := newMutationTestServer(t, secret)
		s.cfg.GracePeriod = 2 * time.Hour
		if _, err := s.hostRegistry.AddHost("web01", []string{"alice"}, ""); err != nil {
			t.Fatalf("AddHost: %v", err)
		}

		form := url.Values{
			"hostname": {"web01"},
			"duration": {"43200"}, // 12h — far above 2h ceiling
		}
		r := buildFormRequest(secret, "alice", "admin", "/api/hosts/elevate", form)
		w := httptest.NewRecorder()
		s.handleElevate(w, r)

		sessions := s.store.ActiveSessions("alice")
		if len(sessions) != 1 {
			t.Fatalf("want 1 session, got %d", len(sessions))
		}
		remaining := time.Until(sessions[0].ExpiresAt)
		if remaining > 2*time.Hour+time.Minute {
			t.Errorf("duration clamp down: got %v, want <= GracePeriod (2h)", remaining)
		}
	})
}

func TestHandleElevate_MethodNotAllowed(t *testing.T) {
	s := newMutationTestServer(t, "s")
	r := httptest.NewRequest(http.MethodGet, "/api/hosts/elevate", nil)
	w := httptest.NewRecorder()
	s.handleElevate(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── handleRotateHost ─────────────────────────────────────────────────────────

func TestHandleRotateHost_AdminSuccess(t *testing.T) {
	const secret = "rot-secret"
	s := newMutationTestServer(t, secret)
	if _, err := s.hostRegistry.AddHost("web01", []string{"*"}, ""); err != nil {
		t.Fatalf("AddHost: %v", err)
	}

	before := s.store.HostRotateBefore("web01")
	if !before.IsZero() {
		t.Fatalf("precondition: HostRotateBefore(web01) should be zero, got %v", before)
	}

	form := url.Values{"hostname": {"web01"}}
	r := buildFormRequest(secret, "admin1", "admin", "/api/hosts/rotate", form)
	w := httptest.NewRecorder()
	s.handleRotateHost(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("admin rotate: got %d, want 303; body: %s", w.Code, w.Body.String())
	}
	if got := s.store.HostRotateBefore("web01"); got.IsZero() {
		t.Error("HostRotateBefore(web01) not set after rotate")
	}
}

func TestHandleRotateHost_NonAdminRejected(t *testing.T) {
	const secret = "rot-secret"
	s := newMutationTestServer(t, secret)

	form := url.Values{"hostname": {"web01"}}
	r := buildFormRequest(secret, "alice", "user", "/api/hosts/rotate", form)
	w := httptest.NewRecorder()
	s.handleRotateHost(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("non-admin rotate: got %d, want 403", w.Code)
	}
	if got := s.store.HostRotateBefore("web01"); !got.IsZero() {
		t.Error("non-admin rotate must not set HostRotateBefore")
	}
}

func TestHandleRotateHost_MissingHostname(t *testing.T) {
	const secret = "rot-secret"
	s := newMutationTestServer(t, secret)

	r := buildFormRequest(secret, "admin1", "admin", "/api/hosts/rotate", url.Values{})
	w := httptest.NewRecorder()
	s.handleRotateHost(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("missing hostname: got %d, want 400", w.Code)
	}
}

func TestHandleRotateHost_InvalidHostname(t *testing.T) {
	const secret = "rot-secret"
	s := newMutationTestServer(t, secret)

	form := url.Values{"hostname": {"not a hostname"}}
	r := buildFormRequest(secret, "admin1", "admin", "/api/hosts/rotate", form)
	w := httptest.NewRecorder()
	s.handleRotateHost(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid hostname: got %d, want 400", w.Code)
	}
	if got := s.store.HostRotateBefore("not a hostname"); !got.IsZero() {
		t.Error("invalid hostname must not set HostRotateBefore")
	}
}

func TestHandleRotateHost_MethodNotAllowed(t *testing.T) {
	s := newMutationTestServer(t, "s")
	r := httptest.NewRequest(http.MethodGet, "/api/hosts/rotate", nil)
	w := httptest.NewRecorder()
	s.handleRotateHost(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── handleRotateAllHosts ─────────────────────────────────────────────────────

func TestHandleRotateAllHosts_AdminRotatesAll(t *testing.T) {
	const secret = "rot-secret"
	s := newMutationTestServer(t, secret)
	// Seed several hosts in the registry so KnownHosts + HostsForUser yields something.
	for _, h := range []string{"web01", "web02", "db01"} {
		if _, err := s.hostRegistry.AddHost(h, []string{"admin1"}, ""); err != nil {
			t.Fatalf("AddHost(%s): %v", h, err)
		}
	}

	r := buildFormRequest(secret, "admin1", "admin", "/api/hosts/rotate-all", url.Values{})
	w := httptest.NewRecorder()
	s.handleRotateAllHosts(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("admin rotate-all: got %d, want 303; body: %s", w.Code, w.Body.String())
	}
	for _, h := range []string{"web01", "web02", "db01"} {
		if got := s.store.HostRotateBefore(h); got.IsZero() {
			t.Errorf("HostRotateBefore(%s) not set", h)
		}
	}
}

func TestHandleRotateAllHosts_NonAdminRejected(t *testing.T) {
	const secret = "rot-secret"
	s := newMutationTestServer(t, secret)
	if _, err := s.hostRegistry.AddHost("web01", []string{"alice"}, ""); err != nil {
		t.Fatalf("AddHost: %v", err)
	}

	r := buildFormRequest(secret, "alice", "user", "/api/hosts/rotate-all", url.Values{})
	w := httptest.NewRecorder()
	s.handleRotateAllHosts(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("non-admin rotate-all: got %d, want 403", w.Code)
	}
	if got := s.store.HostRotateBefore("web01"); !got.IsZero() {
		t.Error("non-admin rotate-all must not set HostRotateBefore")
	}
}

func TestHandleRotateAllHosts_MethodNotAllowed(t *testing.T) {
	s := newMutationTestServer(t, "s")
	r := httptest.NewRequest(http.MethodGet, "/api/hosts/rotate-all", nil)
	w := httptest.NewRecorder()
	s.handleRotateAllHosts(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}
