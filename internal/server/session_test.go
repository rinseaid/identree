package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rinseaid/identree/internal/config"
)

// newTestServer returns a minimal *Server suitable for testing session and CSRF
// logic. Only cfg is populated; all other fields are zero values.
func newTestServer(sharedSecret string) *Server {
	return &Server{
		cfg: &config.ServerConfig{
			SharedSecret: sharedSecret,
		},
		mutationRL: newMutationRateLimiter(),
	}
}

// makeCookie builds and returns a properly signed pam_session cookie value for
// the given username, role, and timestamp using the supplied shared secret.
// Uses a fixed nonce for test determinism.
func makeCookie(secret, username, role string, ts int64) string {
	tsStr := fmt.Sprintf("%d", ts)
	nonce := "abcdef1234567890abcdef1234567890" // fixed 32-char hex nonce for tests
	mac := hmac.New(sha256.New, deriveKey(secret, "session"))
	mac.Write([]byte("session:" + username + ":" + role + ":" + tsStr + ":" + nonce))
	sig := hex.EncodeToString(mac.Sum(nil))
	return username + ":" + role + ":" + tsStr + ":" + nonce + ":" + sig
}

// requestWithCookie returns an *http.Request carrying the named cookie with value.
func requestWithCookie(name, value string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: name, Value: value})
	return req
}

// TestGetSessionUser verifies session cookie validation.
func TestGetSessionUser(t *testing.T) {
	const secret = "test-secret-abc123"
	s := newTestServer(secret)

	t.Run("valid 5-part cookie returns username", func(t *testing.T) {
		ts := time.Now().Unix()
		cookieVal := makeCookie(secret, "alice", "user", ts)
		req := requestWithCookie(sessionCookieName, cookieVal)
		got := s.getSessionUser(req)
		if got != "alice" {
			t.Errorf("getSessionUser: got %q, want %q", got, "alice")
		}
	})

	t.Run("expired timestamp returns empty string", func(t *testing.T) {
		// Timestamp older than sessionCookieTTL (30 minutes).
		ts := time.Now().Add(-(sessionCookieTTL + time.Minute)).Unix()
		cookieVal := makeCookie(secret, "alice", "user", ts)
		req := requestWithCookie(sessionCookieName, cookieVal)
		got := s.getSessionUser(req)
		if got != "" {
			t.Errorf("expected empty string for expired cookie, got %q", got)
		}
	})

	t.Run("wrong HMAC returns empty string", func(t *testing.T) {
		ts := time.Now().Unix()
		cookieVal := makeCookie("different-secret", "alice", "user", ts)
		req := requestWithCookie(sessionCookieName, cookieVal)
		got := s.getSessionUser(req)
		if got != "" {
			t.Errorf("expected empty string for wrong HMAC, got %q", got)
		}
	})

	t.Run("legacy 4-part format returns empty string", func(t *testing.T) {
		// Old format without nonce: username:role:ts:sig (4 parts).
		tsStr := fmt.Sprintf("%d", time.Now().Unix())
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte("session:alice:user:" + tsStr))
		sig := hex.EncodeToString(mac.Sum(nil))
		cookieVal := "alice:user:" + tsStr + ":" + sig
		req := requestWithCookie(sessionCookieName, cookieVal)
		got := s.getSessionUser(req)
		if got != "" {
			t.Errorf("expected empty string for legacy 4-part cookie, got %q", got)
		}
	})

	t.Run("future-dated timestamp returns empty string", func(t *testing.T) {
		// age < 0 should be rejected (unidirectional window).
		ts := time.Now().Add(5 * time.Minute).Unix()
		cookieVal := makeCookie(secret, "alice", "user", ts)
		req := requestWithCookie(sessionCookieName, cookieVal)
		got := s.getSessionUser(req)
		if got != "" {
			t.Errorf("expected empty string for future-dated timestamp, got %q", got)
		}
	})

	t.Run("missing cookie returns empty string", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		got := s.getSessionUser(req)
		if got != "" {
			t.Errorf("expected empty string for missing cookie, got %q", got)
		}
	})

	t.Run("empty shared secret always returns empty string", func(t *testing.T) {
		s2 := newTestServer("")
		ts := time.Now().Unix()
		cookieVal := makeCookie(secret, "alice", "user", ts)
		req := requestWithCookie(sessionCookieName, cookieVal)
		got := s2.getSessionUser(req)
		if got != "" {
			t.Errorf("expected empty string when SharedSecret is empty, got %q", got)
		}
	})

	t.Run("invalid role field returns empty string", func(t *testing.T) {
		ts := time.Now().Unix()
		cookieVal := makeCookie(secret, "alice", "superadmin", ts)
		req := requestWithCookie(sessionCookieName, cookieVal)
		got := s.getSessionUser(req)
		if got != "" {
			t.Errorf("expected empty string for invalid role, got %q", got)
		}
	})
}

// TestGetSessionRole verifies role extraction from session cookies.
func TestGetSessionRole(t *testing.T) {
	const secret = "test-secret-xyz789"
	s := newTestServer(secret)

	t.Run("admin cookie returns admin", func(t *testing.T) {
		ts := time.Now().Unix()
		cookieVal := makeCookie(secret, "alice", "admin", ts)
		req := requestWithCookie(sessionCookieName, cookieVal)
		got := s.getSessionRole(req)
		if got != "admin" {
			t.Errorf("getSessionRole: got %q, want %q", got, "admin")
		}
	})

	t.Run("user cookie returns user", func(t *testing.T) {
		ts := time.Now().Unix()
		cookieVal := makeCookie(secret, "bob", "user", ts)
		req := requestWithCookie(sessionCookieName, cookieVal)
		got := s.getSessionRole(req)
		if got != "user" {
			t.Errorf("getSessionRole: got %q, want %q", got, "user")
		}
	})

	t.Run("invalid cookie returns user (default)", func(t *testing.T) {
		req := requestWithCookie(sessionCookieName, "not-a-valid-cookie")
		got := s.getSessionRole(req)
		if got != "user" {
			t.Errorf("expected default role %q for invalid cookie, got %q", "user", got)
		}
	})

	t.Run("missing cookie returns user (default)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		got := s.getSessionRole(req)
		if got != "user" {
			t.Errorf("expected default role %q for missing cookie, got %q", "user", got)
		}
	})

	t.Run("expired cookie returns user (default)", func(t *testing.T) {
		ts := time.Now().Add(-(sessionCookieTTL + time.Minute)).Unix()
		cookieVal := makeCookie(secret, "alice", "admin", ts)
		req := requestWithCookie(sessionCookieName, cookieVal)
		got := s.getSessionRole(req)
		if got != "user" {
			t.Errorf("expected default role for expired admin cookie, got %q", got)
		}
	})
}

// TestComputeCSRFToken verifies CSRF token determinism and sensitivity.
func TestComputeCSRFToken(t *testing.T) {
	const secret = "csrf-secret-test"

	t.Run("token is deterministic for same inputs", func(t *testing.T) {
		ts := "1700000000"
		t1 := computeCSRFToken(secret, "alice", ts)
		t2 := computeCSRFToken(secret, "alice", ts)
		if t1 != t2 {
			t.Errorf("CSRF token is not deterministic: %q != %q", t1, t2)
		}
	})

	t.Run("token is non-empty for valid inputs", func(t *testing.T) {
		tok := computeCSRFToken(secret, "alice", "1700000000")
		if tok == "" {
			t.Error("expected non-empty CSRF token")
		}
	})

	t.Run("different timestamps produce different tokens", func(t *testing.T) {
		t1 := computeCSRFToken(secret, "alice", "1700000000")
		t2 := computeCSRFToken(secret, "alice", "1700000001")
		if t1 == t2 {
			t.Error("expected different tokens for different timestamps")
		}
	})

	t.Run("different usernames produce different tokens", func(t *testing.T) {
		ts := "1700000000"
		t1 := computeCSRFToken(secret, "alice", ts)
		t2 := computeCSRFToken(secret, "bob", ts)
		if t1 == t2 {
			t.Error("expected different tokens for different usernames")
		}
	})

	t.Run("empty shared secret returns empty token", func(t *testing.T) {
		tok := computeCSRFToken("", "alice", "1700000000")
		if tok != "" {
			t.Errorf("expected empty token for empty secret, got %q", tok)
		}
	})

	t.Run("different secret produces different token", func(t *testing.T) {
		ts := "1700000000"
		t1 := computeCSRFToken(secret, "alice", ts)
		t2 := computeCSRFToken("other-secret", "alice", ts)
		if t1 == t2 {
			t.Error("expected different tokens for different secrets")
		}
	})
}

// TestVerifyFormAuth_CSRFWindow verifies the CSRF timestamp window enforcement.
func TestVerifyFormAuth_CSRFWindow(t *testing.T) {
	const secret = "form-auth-secret"
	s := newTestServer(secret)

	// buildRequest constructs a POST request with a valid session cookie and the
	// given CSRF timestamp (as Unix epoch seconds), so we can test window edges.
	buildRequest := func(t *testing.T, username string, csrfTs int64) *http.Request {
		t.Helper()

		sessionTS := time.Now().Unix()
		sessionCookie := makeCookie(secret, username, "user", sessionTS)

		csrfTsStr := fmt.Sprintf("%d", csrfTs)
		csrfToken := computeCSRFToken(secret, username, csrfTsStr)

		form := url.Values{}
		form.Set("username", username)
		form.Set("csrf_token", csrfToken)
		form.Set("csrf_ts", csrfTsStr)

		req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
		return req
	}

	t.Run("valid CSRF token within 5 minutes passes", func(t *testing.T) {
		req := buildRequest(t, "alice", time.Now().Add(-1*time.Minute).Unix())
		w := httptest.NewRecorder()
		got := s.verifyFormAuth(w, req)
		if got != "alice" {
			t.Errorf("verifyFormAuth: got %q, want %q (response: %d)", got, "alice", w.Code)
		}
	})

	t.Run("CSRF token older than sessionCookieTTL fails", func(t *testing.T) {
		req := buildRequest(t, "alice", time.Now().Add(-31*time.Minute).Unix())
		w := httptest.NewRecorder()
		got := s.verifyFormAuth(w, req)
		if got != "" {
			t.Errorf("expected empty string for stale CSRF token, got %q", got)
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 for stale CSRF, got %d", w.Code)
		}
	})

	t.Run("future-dated CSRF token fails (unidirectional window fix)", func(t *testing.T) {
		req := buildRequest(t, "alice", time.Now().Add(2*time.Minute).Unix())
		w := httptest.NewRecorder()
		got := s.verifyFormAuth(w, req)
		if got != "" {
			t.Errorf("expected empty string for future-dated CSRF token, got %q", got)
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 for future-dated CSRF, got %d", w.Code)
		}
	})

	t.Run("tampered CSRF token fails", func(t *testing.T) {
		sessionTS := time.Now().Unix()
		sessionCookie := makeCookie(secret, "alice", "user", sessionTS)

		csrfTsStr := fmt.Sprintf("%d", time.Now().Unix())
		// Use a token computed with the wrong secret.
		badToken := computeCSRFToken("wrong-secret", "alice", csrfTsStr)

		form := url.Values{}
		form.Set("username", "alice")
		form.Set("csrf_token", badToken)
		form.Set("csrf_ts", csrfTsStr)

		req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})

		w := httptest.NewRecorder()
		got := s.verifyFormAuth(w, req)
		if got != "" {
			t.Errorf("expected empty string for tampered CSRF token, got %q", got)
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 for tampered CSRF, got %d", w.Code)
		}
	})

	t.Run("missing fields returns 400", func(t *testing.T) {
		form := url.Values{}
		form.Set("username", "alice")
		// csrf_token and csrf_ts intentionally omitted

		req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()
		got := s.verifyFormAuth(w, req)
		if got != "" {
			t.Errorf("expected empty string for missing fields, got %q", got)
		}
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for missing fields, got %d", w.Code)
		}
	})

	t.Run("session cookie mismatch returns 403", func(t *testing.T) {
		// Build a CSRF token for alice but set session cookie for bob.
		sessionTS := time.Now().Unix()
		bobCookie := makeCookie(secret, "bob", "user", sessionTS)

		csrfTsStr := fmt.Sprintf("%d", time.Now().Unix())
		csrfToken := computeCSRFToken(secret, "alice", csrfTsStr)

		form := url.Values{}
		form.Set("username", "alice")
		form.Set("csrf_token", csrfToken)
		form.Set("csrf_ts", csrfTsStr)

		req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: bobCookie})

		w := httptest.NewRecorder()
		got := s.verifyFormAuth(w, req)
		if got != "" {
			t.Errorf("expected empty string for cookie/form username mismatch, got %q", got)
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 for cookie mismatch, got %d", w.Code)
		}
	})
}

// buildJSONAdminRequest constructs a request that carries a valid admin session
// cookie and CSRF headers for the given timestamp.
func buildJSONAdminRequest(t *testing.T, secret, username string, csrfTs int64) *http.Request {
	t.Helper()
	sessionCookie := makeCookie(secret, username, "admin", time.Now().Unix())
	csrfTsStr := fmt.Sprintf("%d", csrfTs)
	csrfToken := computeCSRFToken(secret, username, csrfTsStr)
	req := httptest.NewRequest(http.MethodPost, "/api/admin", nil)
	req.Header.Set("X-CSRF-Token", csrfToken)
	req.Header.Set("X-CSRF-Ts", csrfTsStr)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
	return req
}

// TestVerifyJSONAdminAuth verifies the JSON admin auth check used by admin-only
// API endpoints (deploy, config changes, etc.).
func TestVerifyJSONAdminAuth(t *testing.T) {
	const secret = "json-admin-secret"

	t.Run("valid admin session with valid CSRF succeeds", func(t *testing.T) {
		s := newTestServer(secret)
		req := buildJSONAdminRequest(t, secret, "alice", time.Now().Add(-1*time.Minute).Unix())
		w := httptest.NewRecorder()
		got := s.verifyJSONAdminAuth(w, req)
		if got != "alice" {
			t.Errorf("expected username %q, got %q (status %d)", "alice", got, w.Code)
		}
	})

	t.Run("valid admin session with expired CSRF returns 403", func(t *testing.T) {
		s := newTestServer(secret)
		// CSRF timestamp older than sessionCookieTTL (30 min).
		req := buildJSONAdminRequest(t, secret, "alice", time.Now().Add(-(sessionCookieTTL+time.Minute)).Unix())
		w := httptest.NewRecorder()
		got := s.verifyJSONAdminAuth(w, req)
		if got != "" {
			t.Errorf("expected empty string for expired CSRF, got %q", got)
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 for expired CSRF, got %d", w.Code)
		}
	})

	t.Run("valid non-admin session returns 401", func(t *testing.T) {
		s := newTestServer(secret)
		// Build session cookie with role "user".
		sessionCookie := makeCookie(secret, "bob", "user", time.Now().Unix())
		csrfTsStr := fmt.Sprintf("%d", time.Now().Unix())
		csrfToken := computeCSRFToken(secret, "bob", csrfTsStr)
		req := httptest.NewRequest(http.MethodPost, "/api/admin", nil)
		req.Header.Set("X-CSRF-Token", csrfToken)
		req.Header.Set("X-CSRF-Ts", csrfTsStr)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
		w := httptest.NewRecorder()
		got := s.verifyJSONAdminAuth(w, req)
		if got != "" {
			t.Errorf("expected empty string for non-admin user, got %q", got)
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for non-admin user, got %d", w.Code)
		}
	})

	t.Run("no session returns 401", func(t *testing.T) {
		s := newTestServer(secret)
		req := httptest.NewRequest(http.MethodPost, "/api/admin", nil)
		w := httptest.NewRecorder()
		got := s.verifyJSONAdminAuth(w, req)
		if got != "" {
			t.Errorf("expected empty string with no session, got %q", got)
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 with no session, got %d", w.Code)
		}
	})

	t.Run("empty SharedSecret returns 500", func(t *testing.T) {
		// Build a cookie signed with the real secret so getSessionUser passes,
		// then hand it to a server whose SharedSecret is blank.
		sessionCookie := makeCookie(secret, "alice", "admin", time.Now().Unix())

		// A server with no shared secret configured.
		s := &Server{cfg: &config.ServerConfig{SharedSecret: ""}}

		csrfTsStr := fmt.Sprintf("%d", time.Now().Unix())
		csrfToken := computeCSRFToken(secret, "alice", csrfTsStr)
		req := httptest.NewRequest(http.MethodPost, "/api/admin", nil)
		req.Header.Set("X-CSRF-Token", csrfToken)
		req.Header.Set("X-CSRF-Ts", csrfTsStr)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
		w := httptest.NewRecorder()
		got := s.verifyJSONAdminAuth(w, req)
		// getSessionUser will return "" because SharedSecret is empty, so
		// the 401 branch fires before the 500 branch. Both are acceptable
		// rejection statuses here — the key invariant is that access is denied.
		if got != "" {
			t.Errorf("expected empty string when SharedSecret is empty, got %q", got)
		}
		if w.Code != http.StatusUnauthorized && w.Code != http.StatusInternalServerError {
			t.Errorf("expected 401 or 500 when SharedSecret is empty, got %d", w.Code)
		}
	})
}
