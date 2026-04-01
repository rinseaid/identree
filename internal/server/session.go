package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// sessionCookieName is the name of the signed session cookie.
const sessionCookieName = "pam_session"

// sessionCookieTTL is the max-age for the session cookie (30 minutes).
const sessionCookieTTL = 30 * time.Minute

// setSessionCookie sets a signed session cookie on the response.
// role should be "admin" or "user".
func (s *Server) setSessionCookie(w http.ResponseWriter, username, role string) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(s.cfg.SharedSecret))
	mac.Write([]byte("session:" + username + ":" + role + ":" + ts))
	sig := hex.EncodeToString(mac.Sum(nil))
	value := username + ":" + role + ":" + ts + ":" + sig
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(sessionCookieTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
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
	// Only accept the 4-part format: username:role:ts:sig
	parts := strings.SplitN(cookie.Value, ":", 4)
	if len(parts) == 4 {
		username, role, ts, sig := parts[0], parts[1], parts[2], parts[3]
		if !validUsername.MatchString(username) {
			return ""
		}
		if role != "admin" && role != "user" {
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
		mac.Write([]byte("session:" + username + ":" + role + ":" + ts))
		expected := hex.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) != 1 {
			return ""
		}
		return username
	}
	return ""
}

// getSessionRole returns the role embedded in the session cookie: "admin" or "user".
// Returns "user" if the cookie uses the legacy format or if the role is not "admin".
func (s *Server) getSessionRole(r *http.Request) string {
	if s.cfg.SharedSecret == "" {
		return "user"
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "user"
	}
	parts := strings.SplitN(cookie.Value, ":", 4)
	if len(parts) == 4 {
		username, role, ts, sig := parts[0], parts[1], parts[2], parts[3]
		if !validUsername.MatchString(username) {
			return "user"
		}
		if role != "admin" && role != "user" {
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
		mac.Write([]byte("session:" + username + ":" + role + ":" + ts))
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
	for _, pattern := range s.cfg.AdminApprovalHosts {
		if matched, _ := filepath.Match(pattern, hostname); matched {
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
		SameSite: http.SameSiteLaxMode,
	}
	if strings.HasPrefix(s.cfg.ExternalURL, "https://") {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
}

// getAndClearFlash reads the pam_flash cookie, clears it, and returns the value.
func getAndClearFlash(w http.ResponseWriter, r *http.Request) string {
	cookie, err := r.Cookie("pam_flash")
	if err != nil || cookie.Value == "" {
		return ""
	}
	// Clear the cookie immediately
	http.SetCookie(w, &http.Cookie{
		Name:     "pam_flash",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return cookie.Value
}

// getTheme reads the pam_theme cookie and returns "light", "dark", or "" (system default).
func getAvatar(r *http.Request) string {
	c, err := r.Cookie("identree_avatar")
	if err != nil || c.Value == "" {
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
	if age < 0 || age > 5*time.Minute {
		revokeErrorPage(w, r, http.StatusForbidden, "form_expired", "form_expired_message")
		return ""
	}

	// Verify CSRF token
	expected := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(csrfToken)) != 1 {
		revokeErrorPage(w, r, http.StatusForbidden, "invalid_request", "invalid_csrf")
		return ""
	}

	// Refresh session cookie
	s.setSessionCookie(w, username, s.getSessionRole(r))

	return username
}
