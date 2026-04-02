package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rinseaid/identree/internal/randutil"
)

// sessionCookieName is the name of the signed session cookie.
const sessionCookieName = "pam_session"

// sessionCookieTTL is the max-age for the session cookie (30 minutes).
const sessionCookieTTL = 30 * time.Minute

// setSessionCookie sets a signed session cookie on the response.
// role should be "admin" or "user".
// Cookie format: username:role:ts:nonce:sig (5 parts)
// The nonce is a random 16-char hex string that makes each issued token unique.
func (s *Server) setSessionCookie(w http.ResponseWriter, username, role string) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce, err := randutil.Hex(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	mac := hmac.New(sha256.New, []byte(s.cfg.SharedSecret))
	mac.Write([]byte("session:" + username + ":" + role + ":" + ts + ":" + nonce))
	sig := hex.EncodeToString(mac.Sum(nil))
	value := username + ":" + role + ":" + ts + ":" + nonce + ":" + sig
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(sessionCookieTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	if strings.HasPrefix(s.cfg.ExternalURL, "https://") {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
}

// getSessionUser validates the session cookie and returns the username, or "" if invalid/expired.
func (s *Server) getSessionUser(r *http.Request) string {
	if s.cfg.SharedSecret == "" {
		return ""
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	// Only accept the 5-part format: username:role:ts:nonce:sig
	parts := strings.SplitN(cookie.Value, ":", 5)
	if len(parts) == 5 {
		username, role, ts, nonce, sig := parts[0], parts[1], parts[2], parts[3], parts[4]
		if !validUsername.MatchString(username) {
			return ""
		}
		if role != "admin" && role != "user" {
			return ""
		}
		if !isHex(nonce) || len(nonce) != 32 {
			return ""
		}
		tsInt, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			return ""
		}
		if age := time.Since(time.Unix(tsInt, 0)); age < 0 || age > sessionCookieTTL {
			return ""
		}
		mac := hmac.New(sha256.New, []byte(s.cfg.SharedSecret))
		mac.Write([]byte("session:" + username + ":" + role + ":" + ts + ":" + nonce))
		expected := hex.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) != 1 {
			return ""
		}
		return username
	}
	return ""
}

// getSessionRole returns the role embedded in the session cookie: "admin" or "user".
// Returns "user" if the cookie is invalid or expired.
func (s *Server) getSessionRole(r *http.Request) string {
	if s.cfg.SharedSecret == "" {
		return "user"
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "user"
	}
	// Only accept the 5-part format: username:role:ts:nonce:sig
	parts := strings.SplitN(cookie.Value, ":", 5)
	if len(parts) == 5 {
		username, role, ts, nonce, sig := parts[0], parts[1], parts[2], parts[3], parts[4]
		if !validUsername.MatchString(username) {
			return "user"
		}
		if role != "admin" && role != "user" {
			return "user"
		}
		if !isHex(nonce) || len(nonce) != 32 {
			return "user"
		}
		tsInt, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			return "user"
		}
		if age := time.Since(time.Unix(tsInt, 0)); age < 0 || age > sessionCookieTTL {
			return "user"
		}
		mac := hmac.New(sha256.New, []byte(s.cfg.SharedSecret))
		mac.Write([]byte("session:" + username + ":" + role + ":" + ts + ":" + nonce))
		expected := hex.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) != 1 {
			return "user"
		}
		return role
	}
	return "user"
}

// requiresAdminApproval checks if a hostname matches the admin approval policy.
// Patterns use filepath.Match glob syntax (e.g., "*.prod", "bastion-*").
func (s *Server) requiresAdminApproval(hostname string) bool {
	// Snapshot under cfgMu to avoid a data race with applyLiveConfigUpdates.
	s.cfgMu.RLock()
	patterns := s.cfg.AdminApprovalHosts
	s.cfgMu.RUnlock()
	for _, pattern := range patterns {
		matched, err := filepath.Match(pattern, hostname)
		if err != nil {
			// A malformed glob pattern would never match, silently bypassing
			// the intended admin-approval requirement. Log a warning instead.
			slog.Warn("requiresAdminApproval: invalid glob pattern", "pattern", pattern, "err", err)
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

// setFlashCookie sets a short-lived cookie containing a flash message.
// The cookie is read and cleared on the next page load.
func (s *Server) setFlashCookie(w http.ResponseWriter, flash string) {
	cookie := &http.Cookie{
		Name:     "pam_flash",
		Value:    flash,
		Path:     "/",
		MaxAge:   10,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	if strings.HasPrefix(s.cfg.ExternalURL, "https://") {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
}

// getAndClearFlash reads the pam_flash cookie, clears it, and returns the value.
func (s *Server) getAndClearFlash(w http.ResponseWriter, r *http.Request) string {
	cookie, err := r.Cookie("pam_flash")
	if err != nil || cookie.Value == "" {
		return ""
	}
	// Clear the cookie immediately
	c := &http.Cookie{
		Name:     "pam_flash",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if strings.HasPrefix(s.cfg.ExternalURL, "https://") {
		c.Secure = true
	}
	http.SetCookie(w, c)
	return cookie.Value
}

// getTheme reads the pam_theme cookie and returns "light", "dark", or "" (system default).
func getAvatar(r *http.Request) string {
	c, err := r.Cookie("identree_avatar")
	if err != nil || c.Value == "" {
		return ""
	}
	// Re-validate scheme on every read to block javascript:/data: cookies
	// set by an attacker who can write arbitrary cookies.
	if !strings.HasPrefix(c.Value, "https://") && !strings.HasPrefix(c.Value, "http://") {
		return ""
	}
	return c.Value
}

func getTheme(r *http.Request) string {
	c, err := r.Cookie("identree_theme")
	if err != nil || c.Value == "" {
		return "" // system default
	}
	if c.Value == "light" || c.Value == "dark" {
		return c.Value
	}
	return ""
}

// computeCSRFToken creates an HMAC-SHA256 CSRF token for session revocation forms.
// Format: HMAC(shared_secret, username + ":" + timestamp)
func computeCSRFToken(sharedSecret, username, timestamp string) string {
	if sharedSecret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(sharedSecret))
	mac.Write([]byte(username + ":" + timestamp))
	return hex.EncodeToString(mac.Sum(nil))
}

// verifyFormAuth checks the session cookie and CSRF token for form submissions.
// Returns the validated username, or writes a styled error page and returns "".
func (s *Server) verifyFormAuth(w http.ResponseWriter, r *http.Request) string {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := r.ParseForm(); err != nil {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_form")
		return ""
	}

	username := r.FormValue("username")
	csrfToken := r.FormValue("csrf_token")
	csrfTs := r.FormValue("csrf_ts")

	if username == "" || csrfToken == "" || csrfTs == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return ""
	}

	if !validUsername.MatchString(username) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_username_format")
		return ""
	}

	// Check session cookie matches form username
	if sessionUser := s.getSessionUser(r); sessionUser == "" || sessionUser != username {
		revokeErrorPage(w, r, http.StatusForbidden, "session_expired", "session_expired_sign_in")
		return ""
	}

	// Verify CSRF timestamp
	tsInt, err := strconv.ParseInt(csrfTs, 10, 64)
	if err != nil {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_timestamp")
		return ""
	}
	age := time.Since(time.Unix(tsInt, 0))
	if age < 0 || age > sessionCookieTTL {
		revokeErrorPage(w, r, http.StatusForbidden, "form_expired", "form_expired_message")
		return ""
	}

	// Verify CSRF token. When SharedSecret is empty computeCSRFToken returns "".
	// ConstantTimeCompare([]byte{},[]byte{}) == 1, so we must guard explicitly.
	if s.cfg.SharedSecret == "" {
		revokeErrorPage(w, r, http.StatusForbidden, "invalid_request", "invalid_csrf")
		return ""
	}
	expected := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(csrfToken)) != 1 {
		revokeErrorPage(w, r, http.StatusForbidden, "invalid_request", "invalid_csrf")
		return ""
	}

	// Refresh session cookie
	s.setSessionCookie(w, username, s.getSessionRole(r))

	return username
}

// verifyJSONAdminAuth validates a CSRF-protected JSON API call for admin-only endpoints.
// Reads CSRF token and timestamp from X-CSRF-Token / X-CSRF-Ts headers (not form fields)
// since JSON requests cannot include form values. Returns the username on success or writes
// an HTTP error and returns "" on failure.
func (s *Server) verifyJSONAdminAuth(w http.ResponseWriter, r *http.Request) string {
	username := s.getSessionUser(r)
	if username == "" || s.getSessionRole(r) != "admin" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return ""
	}

	if s.cfg.SharedSecret == "" {
		http.Error(w, "server misconfiguration", http.StatusInternalServerError)
		return ""
	}

	csrfToken := r.Header.Get("X-CSRF-Token")
	csrfTs := r.Header.Get("X-CSRF-Ts")
	if csrfToken == "" || csrfTs == "" {
		http.Error(w, "missing CSRF headers", http.StatusForbidden)
		return ""
	}

	tsInt, err := strconv.ParseInt(csrfTs, 10, 64)
	if err != nil {
		http.Error(w, "invalid CSRF timestamp", http.StatusForbidden)
		return ""
	}
	if age := time.Since(time.Unix(tsInt, 0)); age < 0 || age > sessionCookieTTL {
		http.Error(w, "CSRF token expired", http.StatusForbidden)
		return ""
	}

	expected := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(csrfToken)) != 1 {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return ""
	}

	return username
}
