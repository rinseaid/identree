package server

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rinseaid/identree/internal/randutil"
	"github.com/rinseaid/identree/internal/sanitize"
	"golang.org/x/oauth2"
)

// oidcExchangeTimeout limits how long we wait for the IdP token exchange.
// Prevents a slow/malicious IdP from holding goroutines indefinitely.
const oidcExchangeTimeout = 15 * time.Second

// loginRateWindow / loginRateMax control per-IP rate limiting on the
// sessions/login endpoint to prevent nonce pool exhaustion.
const (
	loginRateWindow = 60 * time.Second
	loginRateMax    = 10 // max initiations per IP per window
)

// loginRateLimiter is a sliding-window per-IP rate limiter for the login endpoint.
type loginRateLimiter struct {
	mu    sync.Mutex
	seen  map[string][]time.Time // IP → timestamps of recent requests
}

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{seen: make(map[string][]time.Time)}
}

// allow returns true if the given IP has not exceeded loginRateMax requests
// in the past loginRateWindow, and records the attempt.
func (l *loginRateLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-loginRateWindow)
	// Prune old timestamps for this IP
	times := l.seen[ip]
	j := 0
	for _, t := range times {
		if t.After(cutoff) {
			times[j] = t
			j++
		}
	}
	times = times[:j]
	if len(times) >= loginRateMax {
		l.seen[ip] = times
		return false
	}
	l.seen[ip] = append(times, now)
	// Prune IPs not seen in the last window to prevent unbounded map growth.
	for k, ts := range l.seen {
		if k != ip && (len(ts) == 0 || ts[len(ts)-1].Before(cutoff)) {
			delete(l.seen, k)
		}
	}
	return true
}

// handleOIDCCallback processes the OIDC callback after Pocket ID authentication.
// Only handles the sessions-based OIDC flow (state prefix "sessions:").
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state := r.URL.Query().Get("state")

	// Only sessions-based OIDC flow is supported.
	if strings.HasPrefix(state, "sessions:") {
		s.handleSessionsCallback(w, r)
		return
	}

	slog.Warn("SECURITY callback with unexpected state format", "remote_addr", remoteAddr(r))
	revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "auth_state_unrecognized")
}

// cleanExpiredSessionNonces removes expired nonces (>15 min) from the map.
// Must be called under sessionNonceMu lock.
func (s *Server) cleanExpiredSessionNonces() {
	cutoff := time.Now().Add(-15 * time.Minute)
	for nonce, data := range s.sessionNonces {
		if data.issuedAt.Before(cutoff) {
			delete(s.sessionNonces, nonce)
		}
	}
}

// handleSessionsLogin initiates an OIDC flow for the sessions management page.
// GET /sessions/login
func (s *Server) handleSessionsLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Per-IP rate limit: prevent a single client from exhausting the nonce pool.
	if !s.loginRL.allow(remoteAddr(r)) {
		http.Error(w, "too many requests — try again later", http.StatusTooManyRequests)
		return
	}

	nonce, err := randutil.Hex(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	verifier := oauth2.GenerateVerifier()

	s.sessionNonceMu.Lock()
	s.cleanExpiredSessionNonces()
	if len(s.sessionNonces) > 5000 {
		s.sessionNonceMu.Unlock()
		http.Error(w, "too many requests — try again later", http.StatusTooManyRequests)
		return
	}
	s.sessionNonces[nonce] = sessionNonceData{
		issuedAt:     time.Now(),
		codeVerifier: verifier,
		clientIP:     remoteAddr(r),
	}
	s.sessionNonceMu.Unlock()

	state := "sessions:" + nonce
	authURL := s.oidcConfig.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	// When IssuerPublicURL is set (e.g. split internal/external routing in dev),
	// rewrite the auth URL so the browser follows the public hostname while
	// token exchange and discovery continue to use the internal IssuerURL.
	if s.cfg.IssuerPublicURL != "" {
		if parsed, perr := url.Parse(authURL); perr == nil {
			if pub, perr2 := url.Parse(s.cfg.IssuerPublicURL); perr2 == nil {
				parsed.Scheme = pub.Scheme
				parsed.Host = pub.Host
				authURL = parsed.String()
			}
		}
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleSessionsCallback processes the OIDC callback for the sessions management page.
// Called from handleOIDCCallback when state starts with "sessions:".
func (s *Server) handleSessionsCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	stateNonce := strings.TrimPrefix(state, "sessions:")

	// Validate nonce format
	if len(stateNonce) != 32 || !isHex(stateNonce) {
		slog.Warn("SECURITY malformed sessions state", "remote_addr", remoteAddr(r))
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "auth_state_malformed")
		return
	}

	// Verify and consume the nonce
	s.sessionNonceMu.Lock()
	s.cleanExpiredSessionNonces()
	nonceData, nonceValid := s.sessionNonces[stateNonce]
	if nonceValid {
		delete(s.sessionNonces, stateNonce)
	}
	s.sessionNonceMu.Unlock()

	if !nonceValid {
		slog.Warn("SECURITY unknown or expired sessions nonce", "remote_addr", remoteAddr(r))
		revokeErrorPage(w, r, http.StatusBadRequest, "session_expired", "login_session_expired")
		return
	}

	// Reject stale nonces regardless of lazy cleanup timing.
	if time.Since(nonceData.issuedAt) > 15*time.Minute {
		slog.Warn("SECURITY expired sessions nonce presented", "remote_addr", remoteAddr(r))
		revokeErrorPage(w, r, http.StatusBadRequest, "auth_failed", "nonce_expired")
		return
	}

	// Soft-check state binding: warn if the callback IP differs from login IP.
	// This can legitimately differ for users behind load balancers or mobile NAT,
	// so we warn rather than reject.
	if nonceData.clientIP != "" && nonceData.clientIP != remoteAddr(r) {
		slog.Warn("SECURITY sessions callback IP mismatch (possible CSRF)", "login_ip", nonceData.clientIP, "callback_ip", remoteAddr(r))
	}

	// Check for IdP error
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		slog.Warn("OIDC error during sessions login", "remote_addr", remoteAddr(r), "error", sanitize.ForTerminal(errParam))
		loginURL := s.baseURL + "/sessions/login"
		revokeErrorPageWithLink(w, r, http.StatusForbidden, "auth_failed", "idp_auth_incomplete", loginURL, "try_again")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_auth_code")
		return
	}

	// Exchange code for token
	exchangeCtx, cancel := context.WithTimeout(r.Context(), oidcExchangeTimeout)
	defer cancel()
	exchangeCtx = context.WithValue(exchangeCtx, oauth2.HTTPClient, s.oidcHTTPClient)

	exchangeStart := time.Now()
	token, err := s.oidcConfig.Exchange(exchangeCtx, code, oauth2.VerifierOption(nonceData.codeVerifier))
	oidcExchangeDuration.Observe(time.Since(exchangeStart).Seconds())
	if err != nil {
		slog.Error("sessions callback token exchange failed", "remote_addr", remoteAddr(r), "err", err)
		challengesDenied.WithLabelValues("oidc_error").Inc()
		loginURL := s.baseURL + "/sessions/login"
		revokeErrorPageWithLink(w, r, http.StatusInternalServerError, "auth_failed", "token_exchange_failed", loginURL, "try_again")
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		slog.Error("sessions callback no id_token", "remote_addr", remoteAddr(r))
		revokeErrorPage(w, r, http.StatusInternalServerError, "auth_failed", "no_id_token")
		return
	}

	idToken, err := s.verifier.Verify(exchangeCtx, rawIDToken)
	if err != nil {
		slog.Error("sessions callback token verification failed", "remote_addr", remoteAddr(r), "err", err)
		revokeErrorPage(w, r, http.StatusInternalServerError, "auth_failed", "token_verify_failed")
		return
	}

	// Verify OIDC nonce
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(stateNonce)) != 1 {
		slog.Warn("SECURITY sessions callback nonce mismatch", "remote_addr", remoteAddr(r))
		challengesDenied.WithLabelValues("nonce_mismatch").Inc()
		revokeErrorPage(w, r, http.StatusBadRequest, "auth_failed", "nonce_mismatch")
		return
	}

	var claims struct {
		PreferredUsername string   `json:"preferred_username"`
		Picture           string   `json:"picture"`
		Groups            []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		slog.Error("sessions callback claims parsing failed", "remote_addr", remoteAddr(r), "err", err)
		revokeErrorPage(w, r, http.StatusInternalServerError, "auth_failed", "claims_parse_failed")
		return
	}

	username := claims.PreferredUsername
	if username == "" || !validUsername.MatchString(username) {
		slog.Warn("SECURITY sessions callback invalid username", "remote_addr", remoteAddr(r))
		challengesDenied.WithLabelValues("identity_mismatch").Inc()
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_identity", "invalid_idp_username")
		return
	}

	// Determine role based on group membership.
	// Snapshot AdminGroups under cfgMu to avoid a data race with applyLiveConfigUpdates.
	s.cfgMu.RLock()
	adminGroups := s.cfg.AdminGroups
	s.cfgMu.RUnlock()

	role := "user"
	if len(adminGroups) > 0 {
		if len(claims.Groups) == 0 {
			slog.Warn("OIDC groups claim is empty — user will be assigned role=user; check IdP group scope configuration",
				"user", username)
		}
		for _, userGroup := range claims.Groups {
			for _, adminGroup := range adminGroups {
				if userGroup == adminGroup {
					role = "admin"
					break
				}
			}
			if role == "admin" {
				break
			}
		}
	}

	slog.Info("SESSIONS", "user", username, "role", role, "remote_addr", remoteAddr(r))

	// Record OIDC authentication time for one-tap freshness checks.
	s.store.RecordOIDCAuth(username)

	// Set session cookie and avatar cookie, then redirect to dashboard.
	s.setSessionCookie(w, username, role)
	httpsOrigin := strings.HasPrefix(s.cfg.ExternalURL, "https://")
	// Only store avatar URLs with safe schemes to prevent javascript: XSS.
	if p := claims.Picture; p != "" && (strings.HasPrefix(p, "https://") || strings.HasPrefix(p, "http://")) {
		http.SetCookie(w, &http.Cookie{
			Name:  "identree_avatar",
			Value: p,
			Path:  "/",
			MaxAge: 2592000, // 30 days — outlasts session cookie so avatar persists
			// HttpOnly must remain false: the dashboard JS reads this cookie to
			// display the user's avatar image. The risk is mitigated by:
			//   1. Server-side scheme validation (only http/https accepted above).
			//   2. SameSite=Strict, so the cookie is never sent on cross-site
			//      navigations, reducing the SSRF/XSS attack surface.
			//   3. getAvatar() rejects private/loopback hostnames on every read.
			HttpOnly: false,
			SameSite: http.SameSiteStrictMode,
			Secure:   httpsOrigin,
		})
	}

	// Check for pending one-tap approval after OIDC login.
	// If the pam_onetap cookie is present, the user was redirected here from
	// handleOneTap because their OIDC auth was stale. Now that they've
	// re-authenticated, resume the one-tap approval flow.
	if onetapCookie, err := r.Cookie("pam_onetap"); err == nil && onetapCookie.Value != "" {
		http.SetCookie(w, &http.Cookie{Name: "pam_onetap", Value: "", Path: "/", MaxAge: -1, Secure: httpsOrigin, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		// Verify the one-tap token's challenge belongs to the authenticated user.
		// Validate format before constructing a redirect URL: parts[1] must be
		// a decimal integer and parts[2] must be a 64-char lowercase hex HMAC.
		parts := strings.SplitN(onetapCookie.Value, ".", 3)
		if len(parts) == 3 && isDecimal(parts[1]) && isHex(parts[2]) && len(parts[2]) == 64 {
			if challenge, ok := s.store.Get(parts[0]); ok && challenge.Username == username {
				onetapURL := s.baseURL + "/api/onetap/" + onetapCookie.Value
				http.Redirect(w, r, onetapURL, http.StatusSeeOther)
				return
			}
		}
		// Token invalid or challenge not for this user — fall through to dashboard
	}

	http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
}

