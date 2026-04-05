package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"

	"github.com/rinseaid/identree/internal/policy"
	"strings"
	"time"

	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/randutil"
)

// deriveKey creates a purpose-specific HMAC-SHA256 subkey from sharedSecret.
// Using separate subkeys per purpose prevents an HMAC generated for one context
// (e.g. session signing) from being valid in another (e.g. CSRF protection).
func deriveKey(sharedSecret, purpose string) []byte {
	h := hmac.New(sha256.New, []byte(sharedSecret))
	h.Write([]byte(purpose))
	return h.Sum(nil)
}

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
	mac := hmac.New(sha256.New, deriveKey(s.hmacBase(), "session"))
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

// sessionData holds the validated fields parsed from a session cookie.
type sessionData struct {
	Username string
	Role     string
	TsInt    int64
}

// parseSessionCookie validates the session cookie and returns the parsed data.
// Returns (data, true) on success, or (zero, false) if the cookie is missing,
// malformed, expired, or has a bad HMAC/revoked nonce.
// Callers must check valid == false before using the returned data.
func (s *Server) parseSessionCookie(r *http.Request) (data sessionData, valid bool) {
	if s.hmacBase() == "" {
		return sessionData{}, false
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return sessionData{}, false
	}
	// Only accept the 5-part format: username:role:ts:nonce:sig
	parts := strings.SplitN(cookie.Value, ":", 5)
	if len(parts) != 5 {
		return sessionData{}, false
	}
	username, role, ts, nonce, sig := parts[0], parts[1], parts[2], parts[3], parts[4]
	if !validUsername.MatchString(username) {
		return sessionData{}, false
	}
	if role != "admin" && role != "user" {
		return sessionData{}, false
	}
	if !isHex(nonce) || len(nonce) != 32 {
		return sessionData{}, false
	}
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return sessionData{}, false
	}
	if age := time.Since(time.Unix(tsInt, 0)); age < 0 || age > sessionCookieTTL {
		return sessionData{}, false
	}
	mac := hmac.New(sha256.New, deriveKey(s.hmacBase(), "session"))
	mac.Write([]byte("session:" + username + ":" + role + ":" + ts + ":" + nonce))
	expected := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) != 1 {
		return sessionData{}, false
	}
	s.revokedNoncesMu.Lock()
	_, revoked := s.revokedNonces[nonce]
	s.revokedNoncesMu.Unlock()
	if revoked {
		return sessionData{}, false
	}
	return sessionData{Username: username, Role: role, TsInt: tsInt}, true
}

// getSessionUser validates the session cookie and returns the username, or "" if invalid/expired.
func (s *Server) getSessionUser(r *http.Request) string {
	data, valid := s.parseSessionCookie(r)
	if !valid {
		return ""
	}
	return data.Username
}

// getSessionRole returns the role embedded in the session cookie: "admin" or "user".
// Returns "user" if the cookie is invalid or expired.
func (s *Server) getSessionRole(r *http.Request) string {
	data, valid := s.parseSessionCookie(r)
	if !valid {
		return "user"
	}
	// C5: if the cookie claims admin but the user was removed from admin
	// groups after this cookie was issued, downgrade to "user".
	if data.Role == "admin" {
		if revokedAt, ok := s.revokedAdminSessions.Load(data.Username); ok {
			if t, ok := revokedAt.(time.Time); ok && t.Unix() >= data.TsInt {
				return "user"
			}
		}
	}
	return data.Role
}

// evaluatePolicy evaluates the approval policy engine for the given hostname.
// Returns the policy evaluation result. Thread-safe.
func (s *Server) evaluatePolicy(username, hostname string) policy.EvalResult {
	// Look up host group from registry.
	_, hostGroup, _, _ := s.hostRegistry.GetHost(hostname)
	s.policyCfgMu.RLock()
	engine := s.policyEngine
	s.policyCfgMu.RUnlock()
	return engine.Evaluate(username, hostname, hostGroup)
}

// reloadPolicies reloads the approval policies from disk.
func (s *Server) reloadPolicies() {
	s.cfgMu.RLock()
	path := s.cfg.ApprovalPoliciesFile
	s.cfgMu.RUnlock()

	policies, err := policy.LoadPolicies(path)
	if err != nil {
		slog.Error("policy: failed to reload", "path", path, "err", err)
		return
	}

	s.policyCfgMu.Lock()
	s.policyEngine = policy.NewEngine(policies)
	s.policyCfgMu.Unlock()
	slog.Info("policy: config reloaded", "policies", len(policies))
}

// justificationChoices returns the server-configured justification choices,
// falling back to config.DefaultJustificationChoices when none are configured.
// Must be called with cfgMu already held by the caller, OR after a snapshot.
func (s *Server) justificationChoices() []string {
	if len(s.cfg.JustificationChoices) > 0 {
		return s.cfg.JustificationChoices
	}
	return config.DefaultJustificationChoices
}

// justificationTemplateData returns the current justification choices and
// required flag for embedding in template data maps. Safe to call at any time.
func (s *Server) justificationTemplateData() (choices []string, required bool) {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	choices = s.justificationChoices()
	return choices, s.cfg.RequireJustification
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
		SameSite: http.SameSiteStrictMode,
	}
	if strings.HasPrefix(s.cfg.ExternalURL, "https://") {
		c.Secure = true
	}
	http.SetCookie(w, c)
	return cookie.Value
}

// getAvatar reads the identree_avatar cookie and returns an /api/avatar proxy
// URL, or "" if the cookie is absent or has an invalid scheme.
// Routing the URL through the proxy eliminates the DNS-rebinding TOCTOU present
// when we validate the hostname at cookie-read time but the browser fetches the
// URL independently later.
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
	return "/api/avatar?url=" + url.QueryEscape(c.Value)
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
	mac := hmac.New(sha256.New, deriveKey(sharedSecret, "csrf"))
	mac.Write([]byte("csrf:" + username + ":" + timestamp))
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

	// Verify CSRF token. When hmacBase() is empty computeCSRFToken returns "".
	// ConstantTimeCompare([]byte{},[]byte{}) == 1, so we must guard explicitly.
	if s.hmacBase() == "" {
		revokeErrorPage(w, r, http.StatusForbidden, "invalid_request", "invalid_csrf")
		return ""
	}
	expected := computeCSRFToken(s.hmacBase(), username, csrfTs)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(csrfToken)) != 1 {
		revokeErrorPage(w, r, http.StatusForbidden, "invalid_request", "invalid_csrf")
		return ""
	}

	// Per-user mutation rate limit: reject if user exceeds mutationRateMax/minute.
	if !s.mutationRL.allow(username) {
		revokeErrorPage(w, r, http.StatusTooManyRequests, "rate_limited", "too_many_requests")
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
	jsonErr := func(code int, msg string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
	}

	data, valid := s.parseSessionCookie(r)
	if !valid {
		jsonErr(http.StatusUnauthorized, "unauthorized")
		return ""
	}
	username := data.Username
	role := data.Role
	// Enforce revokedAdminSessions downgrade for recently de-admined users.
	if role == "admin" {
		if revokedAt, ok := s.revokedAdminSessions.Load(username); ok {
			if t, ok := revokedAt.(time.Time); ok && t.Unix() >= data.TsInt {
				role = "user"
			}
		}
	}
	if username == "" || role != "admin" {
		jsonErr(http.StatusUnauthorized, "unauthorized")
		return ""
	}

	if s.hmacBase() == "" {
		jsonErr(http.StatusInternalServerError, "server misconfiguration")
		return ""
	}

	csrfToken := r.Header.Get("X-CSRF-Token")
	csrfTs := r.Header.Get("X-CSRF-Ts")
	if csrfToken == "" || csrfTs == "" {
		jsonErr(http.StatusForbidden, "missing CSRF headers")
		return ""
	}

	tsInt, err := strconv.ParseInt(csrfTs, 10, 64)
	if err != nil {
		jsonErr(http.StatusForbidden, "invalid CSRF timestamp")
		return ""
	}
	if age := time.Since(time.Unix(tsInt, 0)); age < 0 || age > sessionCookieTTL {
		jsonErr(http.StatusForbidden, "CSRF token expired")
		return ""
	}

	expected := computeCSRFToken(s.hmacBase(), username, csrfTs)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(csrfToken)) != 1 {
		jsonErr(http.StatusForbidden, "invalid CSRF token")
		return ""
	}

	return username
}
