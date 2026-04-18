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
