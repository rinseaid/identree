package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/rinseaid/identree/internal/breakglass"
	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/escrow"
	"github.com/rinseaid/identree/internal/notify"
)

// sanitizeReason trims whitespace, truncates to 500 runes, rejects control
// characters, and returns the cleaned reason. Returns ("", false) on invalid input.
func sanitizeReason(r string) (string, bool) {
	r = strings.TrimSpace(r)
	const maxLen = 500
	if utf8.RuneCountInString(r) > maxLen {
		count := 0
		for i := range r {
			if count == maxLen {
				r = r[:i]
				break
			}
			count++
		}
	}
	for _, ch := range r {
		if ch < 0x20 && ch != '\t' {
			return "", false
		}
	}
	return r, true
}

// apiError writes a JSON error response {"error": "..."} for /api/ routes.
func apiError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
		slog.Debug("handlers_api: failed to write response", "err", err)
	}
}

// authFailTracker counts per-IP authentication failures in a sliding window.
// After authFailMax failures in authFailWindow, the IP is throttled.
const (
	authFailWindow       = 60 * time.Second
	authFailMax          = 10
	maxUsedEscrowTokens  = 10000
)

type authFailTracker struct {
	mu   sync.Mutex
	seen map[string][]time.Time
}

func newAuthFailTracker() *authFailTracker {
	return &authFailTracker{seen: make(map[string][]time.Time)}
}

// throttled returns true if ip has exceeded authFailMax failures in authFailWindow.
func (a *authFailTracker) throttled(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.recentCount(ip) >= authFailMax
}

// record records a new auth failure from ip.
func (a *authFailTracker) record(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-authFailWindow)
	times := a.seen[ip]
	j := 0
	for _, t := range times {
		if t.After(cutoff) {
			times[j] = t
			j++
		}
	}
	a.seen[ip] = append(times[:j], now)
	// Prune stale IPs.
	for k, ts := range a.seen {
		if k != ip && (len(ts) == 0 || ts[len(ts)-1].Before(cutoff)) {
			delete(a.seen, k)
		}
	}
	// Safety valve: if the map still exceeds 50k entries (e.g. distributed
	// attack from many IPs), force-prune all entries older than the window.
	if len(a.seen) > 50000 {
		for k, ts := range a.seen {
			if len(ts) == 0 || ts[len(ts)-1].Before(cutoff) {
				delete(a.seen, k)
			}
		}
	}
}

// recentCount returns the number of failures from ip in the current window.
// Caller must hold a.mu.
func (a *authFailTracker) recentCount(ip string) int {
	cutoff := time.Now().Add(-authFailWindow)
	times := a.seen[ip]
	count := 0
	for _, t := range times {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

// verifySharedSecret checks the X-Shared-Secret header using constant-time comparison
// to prevent timing attacks that could leak the secret byte-by-byte.
func (s *Server) verifySharedSecret(r *http.Request) bool {
	if s.cfg.SharedSecret == "" {
		return false // fail closed: no secret configured means no access
	}
	provided := r.Header.Get("X-Shared-Secret")
	if provided == "" {
		return false
	}
	// Hash both values before comparison to prevent length leakage.
	// subtle.ConstantTimeCompare returns 0 immediately for different-length
	// inputs, which would leak the secret's length via timing.
	expectedHash := sha256.Sum256([]byte(s.cfg.SharedSecret))
	providedHash := sha256.Sum256([]byte(provided))
	return subtle.ConstantTimeCompare(expectedHash[:], providedHash[:]) == 1
}

// verifyAPISecret checks the X-Shared-Secret header against both the global shared
// secret and any registered host secret. Used for API endpoints (poll, grace-status,
// escrow) where the hostname isn't known at auth time.
func (s *Server) verifyAPISecret(r *http.Request) bool {
	if s.verifySharedSecret(r) {
		return true
	}
	// Check if the provided secret matches any registered host
	if s.hostRegistry.IsEnabled() {
		provided := r.Header.Get("X-Shared-Secret")
		if provided != "" {
			return s.hostRegistry.ValidateAnyHost(provided)
		}
	}
	return false
}

// verifyAPIKey checks the Authorization: Bearer header against configured API keys.
// Returns true only when at least one key is configured and the token matches.
// Both sides are HMAC-SHA256 hashed before comparison so that
// subtle.ConstantTimeCompare always operates on equal-length inputs, preventing
// the length-mismatch early-exit timing leak present in a bare byte comparison.
func (s *Server) verifyAPIKey(r *http.Request) bool {
	if len(s.hashedAPIKeys) == 0 {
		return false
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		return false
	}
	h := hmac.New(sha256.New, []byte("api-key-verification"))
	h.Write([]byte(token))
	hashedToken := h.Sum(nil)

	for _, preHashed := range s.hashedAPIKeys {
		if subtle.ConstantTimeCompare(hashedToken, preHashed) == 1 {
			return true
		}
	}
	return false
}

// authenticateChallenge checks whether a challenge creation request is authorized.
// Tries the global shared secret first, then per-host secrets from the registry.
// Returns (authorized bool, errorMsg string). When authorized is false, errorMsg
// describes why.
func (s *Server) authenticateChallenge(r *http.Request, hostname, username string) (bool, string) {
	// Try global shared secret first
	if s.verifySharedSecret(r) {
		// When the host registry is enabled, require a hostname and check
		// per-user authorization. Without this, omitting hostname bypasses
		// the per-user access list entirely.
		if s.hostRegistry.IsEnabled() {
			if hostname == "" {
				return false, "hostname required when host registry is enabled"
			}
			if !s.hostRegistry.IsUserAuthorized(hostname, username) {
				return false, "user not authorized on this host"
			}
		}
		return true, ""
	}
	// Try per-host secret from registry
	if s.hostRegistry.IsEnabled() && hostname != "" {
		providedSecret := r.Header.Get("X-Shared-Secret")
		if s.hostRegistry.ValidateHost(hostname, providedSecret) {
			if !s.hostRegistry.IsUserAuthorized(hostname, username) {
				return false, "user not authorized on this host"
			}
			return true, ""
		}
	}
	return false, "unauthorized"
}

// remoteAddr extracts the client IP from a request for logging.
func remoteAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// handleCreateChallenge creates a new sudo challenge.
// POST /api/challenge {"username": "jordan"}
func (s *Server) handleCreateChallenge(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		// Pad all responses to a minimum of 5ms to prevent timing side channels
		if elapsed := time.Since(start); elapsed < 5*time.Millisecond {
			time.Sleep(5*time.Millisecond - elapsed)
		}
	}()

	if r.Method != http.MethodPost {
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Per-IP auth-failure backoff: an IP that has failed too many times recently
	// is throttled before we even attempt shared-secret verification.
	if s.authFailRL.throttled(remoteAddr(r)) {
		apiError(w, http.StatusTooManyRequests, "too many failed attempts — try again later")
		return
	}

	// Verify Content-Type to prevent cross-origin form submission
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		apiError(w, http.StatusUnsupportedMediaType, "content-type must be application/json")
		return
	}

	// Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req struct {
		Username string `json:"username"`
		Hostname string `json:"hostname"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		io.Copy(io.Discard, r.Body) //nolint:errcheck // best-effort drain for keep-alive
		apiError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Username == "" {
		apiError(w, http.StatusBadRequest, "username required")
		return
	}

	// Validate username to prevent log injection and other input-based attacks
	if !validUsername.MatchString(req.Username) {
		apiError(w, http.StatusBadRequest, "invalid username format")
		return
	}

	// Validate hostname to prevent log injection (hostname is optional, empty is OK).
	// Normalize to lowercase and strip any trailing dot before all downstream checks
	// so that admin approval patterns (e.g. *.prod) can never be bypassed via
	// case manipulation (WEB01.PROD) or FQDN trailing dots (web01.prod.).
	if req.Hostname != "" {
		req.Hostname = strings.ToLower(strings.TrimSuffix(req.Hostname, "."))
		if !validHostname.MatchString(req.Hostname) {
			apiError(w, http.StatusBadRequest, "invalid hostname format")
			return
		}
	}

	// Sanitize reason: strip whitespace, truncate to 500 runes, reject control chars.
	if req.Reason != "" {
		clean, ok := sanitizeReason(req.Reason)
		if !ok {
			apiError(w, http.StatusBadRequest, "reason contains invalid characters")
			return
		}
		req.Reason = clean
	}

	// If justification is required and none was provided, return 422 with the
	// available choices so the client can prompt the user and retry.
	s.cfgMu.RLock()
	requireJust := s.cfg.RequireJustification
	justChoices := s.justificationChoices()
	s.cfgMu.RUnlock()
	if requireJust && req.Reason == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":                  "justification_required",
			"justification_choices":  justChoices,
		})
		return
	}

	// Authenticate: try global shared secret, then per-host secret from registry.
	// We parse the body first so we have the hostname for per-host auth.
	authorized, errMsg := s.authenticateChallenge(r, req.Hostname, req.Username)
	if !authorized {
		authFailures.Inc()
		s.authFailRL.record(remoteAddr(r))
		slog.Warn("AUTH_FAILURE", "reason", errMsg, "remote_addr", remoteAddr(r), "host", req.Hostname, "user", req.Username)
		apiError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Snapshot the rotation signal under cfgMu before creating the challenge
	// so the value is set on the struct before it enters the store's map (avoids
	// data race with concurrent Get() calls that copy the struct under RLock).
	s.cfgMu.RLock()
	rotateBefore := ""
	if !s.cfg.BreakglassRotateBefore.IsZero() {
		rotateBefore = s.cfg.BreakglassRotateBefore.Format(time.RFC3339)
	}
	s.cfgMu.RUnlock()

	challenge, err := s.store.Create(req.Username, req.Hostname, rotateBefore, req.Reason)
	if err != nil {
		// Rate limit errors are returned by the store when too many challenges exist
		if errors.Is(err, challpkg.ErrTooManyChallenges) || errors.Is(err, challpkg.ErrTooManyPerUser) {
			rateLimitRejections.Inc()
			slog.Warn("RATE_LIMIT", "user", req.Username, "remote_addr", remoteAddr(r), "host", req.Hostname)
			apiError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		slog.Error("creating challenge", "err", err, "user", req.Username, "host", req.Hostname, "remote_addr", remoteAddr(r))
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}

	challengesCreated.Inc()
	challpkg.ActiveChallenges.Inc()
	slog.Info("CHALLENGE created", "challenge", challenge.ID[:8], "user", req.Username, "remote_addr", remoteAddr(r), "host", req.Hostname)
	s.sseBroadcaster.Broadcast(req.Username, "challenge_created")

	// Build client_config if any server-side client overrides are set
	clientCfg := s.buildClientConfig()

	// Snapshot live-updated config fields under read lock before use in response.
	s.cfgMu.RLock()
	challengeTTL := s.cfg.ChallengeTTL
	s.cfgMu.RUnlock()

	// Auto-approve if within grace period, but only for hosts that don't require admin approval.
	// AutoApproveIfWithinGracePeriod performs the check and approval atomically,
	// eliminating the TOCTOU race between a separate WithinGracePeriod + AutoApprove pair.
	// AutoApproveIfWithinGracePeriod performs the grace-period check and approval
	// atomically under a single write lock, eliminating the TOCTOU race between
	// a separate WithinGracePeriod check and AutoApprove call.
	if !s.requiresAdminApproval(req.Hostname) && s.store.AutoApproveIfWithinGracePeriod(req.Username, req.Hostname, challenge.ID) {
		challengesAutoApproved.Inc()
		challpkg.ActiveChallenges.Dec()
		challengeDuration.Observe(0)
		slog.Info("GRACE auto-approved", "user", req.Username, "challenge", challenge.ID[:8])
		hostname := req.Hostname
		if hostname == "" {
			hostname = "(unknown)"
		}
		s.store.LogActionWithReason(req.Username, challpkg.ActionAutoApproved, hostname, challenge.UserCode, "", challenge.Reason)
		s.dispatchNotification(notify.WebhookData{
			Event:     "auto_approved",
			Username:  req.Username,
			Actor:     req.Username,
			Hostname:  hostname,
			UserCode:  challenge.UserCode,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Reason:    challenge.Reason,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		resp := map[string]interface{}{
			"challenge_id":    challenge.ID,
			"user_code":       challenge.UserCode,
			"expires_in":      int(challengeTTL.Seconds()),
			"status":          "approved",
			"grace_remaining": int(s.store.GraceRemaining(req.Username, req.Hostname).Seconds()),
		}
		if s.cfg.SharedSecret != "" {
			resp["approval_token"] = s.computeStatusHMAC(challenge.ID, req.Username, "approved", challenge.BreakglassRotateBefore, challenge.RevokeTokensBefore)
		}
		if challenge.BreakglassRotateBefore != "" {
			resp["rotate_breakglass_before"] = challenge.BreakglassRotateBefore
		}
		if challenge.RevokeTokensBefore != "" {
			resp["revoke_tokens_before"] = challenge.RevokeTokensBefore
		}
		if clientCfg != nil {
			resp["client_config"] = clientCfg
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			slog.Error("writing JSON response", "err", err)
		}
		return
	}

	approvalURL := fmt.Sprintf("%s/approve/%s", s.baseURL, challenge.UserCode)

	oneTapToken := s.computeOneTapToken(challenge.ID, challenge.Username, challenge.Hostname, challenge.ExpiresAt)
	oneTapURL := ""
	if oneTapToken != "" {
		oneTapURL = s.baseURL + "/api/onetap/" + oneTapToken
	}

	// Fire push notification asynchronously (no-op if no channels configured).
	s.sendChallengeNotification(challenge, approvalURL, oneTapURL)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	resp := map[string]interface{}{
		"challenge_id":     challenge.ID,
		"user_code":        challenge.UserCode,
		"verification_url": approvalURL,
		"expires_in":       int(challengeTTL.Seconds()),
	}
	if len(s.notifyRoutes()) > 0 {
		resp["notification_queued"] = true
	}
	if challenge.BreakglassRotateBefore != "" {
		resp["rotate_breakglass_before"] = challenge.BreakglassRotateBefore
	}
	if challenge.RevokeTokensBefore != "" {
		resp["revoke_tokens_before"] = challenge.RevokeTokensBefore
	}
	if clientCfg != nil {
		resp["client_config"] = clientCfg
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("writing JSON response", "err", err)
	}
}

// handlePollChallenge checks challenge status.
// GET /api/challenge/{id}
func (s *Server) handlePollChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ip := remoteAddr(r)
	if s.authFailRL.throttled(ip) {
		apiError(w, http.StatusTooManyRequests, "too many auth failures")
		return
	}
	if !s.verifyAPISecret(r) {
		authFailures.Inc()
		s.authFailRL.record(ip)
		slog.Warn("AUTH_FAILURE invalid shared secret", "path", "GET /api/challenge/", "remote_addr", ip)
		apiError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/challenge/")
	if id == "" {
		apiError(w, http.StatusBadRequest, "challenge ID required")
		return
	}

	// Validate challenge ID format (hex string, 32 chars for 16 bytes)
	if len(id) != 32 || !isHex(id) {
		apiError(w, http.StatusBadRequest, "invalid challenge ID")
		return
	}

	// Read hostname from the request query string so we can verify it matches
	// the challenge's origin host (Fix C1).
	reqHostname := strings.ToLower(strings.TrimSuffix(r.URL.Query().Get("hostname"), "."))

	challenge, ok := s.store.Get(id)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGone)
		if err := json.NewEncoder(w).Encode(map[string]string{"status": string(challpkg.StatusExpired)}); err != nil {
			slog.Error("writing JSON response", "err", err)
		}
		return
	}

	// Enforce hostname binding: the polling client's hostname MUST match the
	// challenge's origin hostname, regardless of whether the global shared secret
	// or a per-host credential was used for authentication. This prevents a PAM
	// client on host-B from polling and consuming an approval meant for host-A.
	if challenge.Hostname != reqHostname {
		slog.Warn("AUTH_FAILURE poll hostname mismatch", "challenge_host", challenge.Hostname, "req_host", reqHostname, "remote_addr", remoteAddr(r))
		apiError(w, http.StatusForbidden, "hostname mismatch")
		return
	}

	// When using per-host credentials, ensure the caller's secret matches the
	// challenge's origin host. This prevents a compromised host B from polling
	// host A's challenge and receiving host A's user OIDC ID token.
	if s.hostRegistry.IsEnabled() && !s.verifySharedSecret(r) {
		provided := r.Header.Get("X-Shared-Secret")
		if !s.hostRegistry.ValidateHost(challenge.Hostname, provided) {
			slog.Warn("AUTH_FAILURE poll credential does not match challenge hostname", "host", challenge.Hostname, "remote_addr", remoteAddr(r))
			apiError(w, http.StatusForbidden, "credential does not match challenge hostname")
			return
		}
	}

	resp := map[string]interface{}{
		"status":     challenge.Status,
		"expires_in": int(time.Until(challenge.ExpiresAt).Seconds()),
	}
	// Include HMAC status tokens so the PAM client can verify the response
	// is genuine and not injected by a MITM
	if s.cfg.SharedSecret != "" {
		switch challenge.Status {
		case challpkg.StatusApproved:
			resp["approval_token"] = s.computeStatusHMAC(id, challenge.Username, "approved", challenge.BreakglassRotateBefore, challenge.RevokeTokensBefore)
			// Forward the raw ID token so the PAM client can cache it locally
			// for subsequent authentication without a full device flow.
			if challenge.RawIDToken != "" {
				resp["id_token"] = challenge.RawIDToken
			}
			// Include grace period remaining so the client can show the
			// effective re-auth window (max of token expiry and grace period).
			if gr := s.store.GraceRemaining(challenge.Username, challenge.Hostname); gr > 0 {
				resp["grace_remaining"] = int(gr.Seconds())
			}
		case challpkg.StatusDenied:
			resp["denial_token"] = s.computeStatusHMAC(id, challenge.Username, "denied", challenge.BreakglassRotateBefore, challenge.RevokeTokensBefore)
			if challenge.DenyReason != "" {
				resp["deny_reason"] = challenge.DenyReason
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("writing JSON response", "err", err)
	}
}

// handleGraceStatus returns the grace period remaining for a user@host.
// GET /api/grace-status?username=X&hostname=Y
// Used by the PAM client to get the accurate grace time on cache hits.
func (s *Server) handleGraceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ip := remoteAddr(r)
	if s.authFailRL.throttled(ip) {
		apiError(w, http.StatusTooManyRequests, "too many auth failures")
		return
	}
	if !s.verifyAPISecret(r) {
		authFailures.Inc()
		s.authFailRL.record(ip)
		slog.Warn("AUTH_FAILURE grace-status invalid shared secret", "remote_addr", ip)
		apiError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	username := r.URL.Query().Get("username")
	hostname := strings.ToLower(strings.TrimSuffix(r.URL.Query().Get("hostname"), "."))
	if username == "" {
		apiError(w, http.StatusBadRequest, "username required")
		return
	}
	if !validUsername.MatchString(username) {
		apiError(w, http.StatusBadRequest, "invalid username")
		return
	}
	if hostname != "" && !validHostname.MatchString(hostname) {
		apiError(w, http.StatusBadRequest, "invalid hostname")
		return
	}
	// Enforce hostname binding: the requesting client's hostname MUST match the
	// queried hostname regardless of whether the global shared secret or a
	// per-host credential was used. This prevents a PAM client on host-B from
	// querying grace-period state for host-A (Fix C1).
	if s.hostRegistry.IsEnabled() && !s.verifySharedSecret(r) {
		provided := r.Header.Get("X-Shared-Secret")
		if !s.hostRegistry.ValidateHost(hostname, provided) {
			slog.Warn("AUTH_FAILURE grace-status hostname mismatch", "host", hostname, "remote_addr", remoteAddr(r))
			apiError(w, http.StatusForbidden, "hostname mismatch")
			return
		}
	}
	remaining := s.store.GraceRemaining(username, hostname)
	resp := map[string]interface{}{
		"grace_remaining": int(remaining.Seconds()),
	}
	if t := s.store.RevokeTokensBefore(username); !t.IsZero() {
		resp["revoke_tokens_before"] = t.Format(time.RFC3339)
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("writing JSON response", "err", err)
	}
}

// computeStatusHMAC creates an HMAC-SHA256 token binding a challenge status to the
// specific challengeID, username, status, rotateBefore, and revokeTokensBefore.
// Uses length-prefixed fields to prevent field injection.
// The rotateBefore and revokeTokensBefore parameters are the per-challenge snapshots
// stored at challenge creation, ensuring HMAC consistency even if the server config
// changes between creation and poll. Empty optional fields are omitted for
// backward compatibility.
func (s *Server) computeStatusHMAC(challengeID, username, status, rotateBefore, revokeTokensBefore string) string {
	mac := hmac.New(sha256.New, deriveKey(s.hmacBase(), "approval_status"))
	fmt.Fprintf(mac, "%d:%s%d:%s%d:%s", len(challengeID), challengeID, len(status), status, len(username), username)
	// Include rotate_breakglass_before in the HMAC so a MITM cannot inject
	// a rotation signal without invalidating the token.
	if rotateBefore != "" {
		fmt.Fprintf(mac, "%d:%s", len(rotateBefore), rotateBefore)
	}
	// Include revoke_tokens_before in the HMAC so a MITM cannot inject
	// a revocation signal without invalidating the token.
	if revokeTokensBefore != "" {
		fmt.Fprintf(mac, "%d:%s", len(revokeTokensBefore), revokeTokensBefore)
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// computeOneTapToken creates a time-limited, single-use HMAC token for one-tap approval.
// Format: {challenge_id}.{expires_unix}.{hmac_hex}
// The token is bound to the challenge's hostname to prevent a token issued for a
// challenge on host-a from being used to approve a challenge on host-b.
func (s *Server) computeOneTapToken(challengeID, username, hostname string, expiresAt time.Time) string {
	if s.hmacBase() == "" {
		return ""
	}
	expires := strconv.FormatInt(expiresAt.Unix(), 10)
	mac := hmac.New(sha256.New, deriveKey(s.hmacBase(), "onetap"))
	mac.Write([]byte("onetap:" + challengeID + ":" + username + ":" + expires + ":" + hostname))
	sig := hex.EncodeToString(mac.Sum(nil))
	return challengeID + "." + expires + "." + sig
}

// buildClientConfig returns a client config override map if any fields are set,
// or nil if no overrides are configured.
// All fields read here are live-updated by applyLiveConfigUpdates, so we
// snapshot them under cfgMu.RLock before use.
func (s *Server) buildClientConfig() map[string]interface{} {
	s.cfgMu.RLock()
	pollInterval := s.cfg.ClientPollInterval
	timeout := s.cfg.ClientTimeout
	var breakglassEnabled *bool
	if s.cfg.ClientBreakglassEnabled != nil {
		v := *s.cfg.ClientBreakglassEnabled
		breakglassEnabled = &v
	}
	breakglassPasswordType := s.cfg.ClientBreakglassPasswordType
	breakglassRotationDays := s.cfg.ClientBreakglassRotationDays
	var tokenCacheEnabled *bool
	if s.cfg.ClientTokenCacheEnabled != nil {
		v := *s.cfg.ClientTokenCacheEnabled
		tokenCacheEnabled = &v
	}
	s.cfgMu.RUnlock()

	cfg := make(map[string]interface{})
	if pollInterval > 0 {
		cfg["poll_interval"] = pollInterval.String()
	}
	if timeout > 0 {
		cfg["timeout"] = timeout.String()
	}
	if breakglassEnabled != nil {
		cfg["breakglass_enabled"] = *breakglassEnabled
	}
	if breakglassPasswordType != "" {
		cfg["breakglass_password_type"] = breakglassPasswordType
	}
	if breakglassRotationDays > 0 {
		cfg["breakglass_rotation_days"] = breakglassRotationDays
	}
	if tokenCacheEnabled != nil {
		cfg["token_cache_enabled"] = *tokenCacheEnabled
	}
	if len(cfg) == 0 {
		return nil
	}
	return cfg
}

// handleBreakglassEscrow receives a break-glass password from a client and
// passes it to the configured escrow command.
// POST /api/breakglass/escrow
func (s *Server) handleBreakglassEscrow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Escrow endpoint ALWAYS requires authentication — even with IDENTREE_INSECURE=true.
	// Unlike the challenge API, this endpoint executes a shell command with caller-provided
	// data on stdin, so unauthenticated access would be a command execution vector.
	if s.cfg.SharedSecret == "" && !s.hostRegistry.IsEnabled() {
		apiError(w, http.StatusForbidden, "escrow endpoint requires shared secret authentication")
		return
	}

	ip := remoteAddr(r)
	if s.authFailRL.throttled(ip) {
		apiError(w, http.StatusTooManyRequests, "too many authentication failures")
		return
	}
	if !s.verifyAPISecret(r) {
		authFailures.Inc()
		s.authFailRL.record(ip)
		slog.Warn("AUTH_FAILURE invalid shared secret", "path", "POST /api/breakglass/escrow", "remote_addr", ip)
		apiError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		apiError(w, http.StatusUnsupportedMediaType, "content-type must be application/json")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req struct {
		Hostname string `json:"hostname"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		io.Copy(io.Discard, r.Body) //nolint:errcheck // best-effort drain for keep-alive
		apiError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Password == "" {
		apiError(w, http.StatusBadRequest, "password required")
		return
	}
	// Hostname is required for escrow (used for per-host token verification
	// and as the key in the escrow command's BREAKGLASS_HOSTNAME env var).
	if req.Hostname == "" {
		apiError(w, http.StatusBadRequest, "hostname required")
		return
	}
	if !validHostname.MatchString(req.Hostname) {
		apiError(w, http.StatusBadRequest, "invalid hostname format")
		return
	}

	// Verify per-host escrow authorization to prevent a compromised host from
	// planting a known password for a different host.
	//
	// When using a global SharedSecret: verify HMAC(shared_secret, "escrow:"+hostname).
	// When using host registry (no global SharedSecret): re-validate that the
	// caller's credential specifically matches req.Hostname, not just any host.
	if s.hostRegistry.IsEnabled() {
		// When the host registry is enabled (with or without a global SharedSecret),
		// require that the caller's per-host credential specifically matches the
		// target hostname. Using HMAC escrow tokens here would let any host holding
		// the global SharedSecret plant a password for any other host.
		provided := r.Header.Get("X-Shared-Secret")
		if !s.hostRegistry.ValidateHost(req.Hostname, provided) {
			slog.Warn("AUTH_FAILURE escrow credential does not match target hostname", "host", req.Hostname, "remote_addr", remoteAddr(r))
			apiError(w, http.StatusForbidden, "invalid credential for hostname")
			return
		}
	} else if s.cfg.SharedSecret != "" {
		// No host registry: use HMAC escrow token tied to the specific hostname and timestamp.
		// Validate the timestamp is within ±5 minutes to prevent replay attacks.
		tsHeader := r.Header.Get("X-Escrow-Ts")
		if tsHeader == "" {
			slog.Warn("AUTH_FAILURE missing escrow timestamp", "host", req.Hostname, "remote_addr", remoteAddr(r))
			apiError(w, http.StatusForbidden, "missing escrow timestamp")
			return
		}
		tsUnix, err := strconv.ParseInt(tsHeader, 10, 64)
		if err != nil {
			slog.Warn("AUTH_FAILURE invalid escrow timestamp format", "host", req.Hostname, "remote_addr", remoteAddr(r))
			apiError(w, http.StatusForbidden, "invalid escrow timestamp")
			return
		}
		tsDiff := time.Since(time.Unix(tsUnix, 0))
		if tsDiff > time.Minute || tsDiff < -time.Minute {
			slog.Warn("AUTH_FAILURE escrow timestamp out of window", "host", req.Hostname, "remote_addr", remoteAddr(r), "diff", tsDiff)
			apiError(w, http.StatusForbidden, "escrow timestamp out of window")
			return
		}
		expectedToken := breakglass.ComputeEscrowToken(s.cfg.SharedSecret, req.Hostname, tsHeader)
		providedToken := r.Header.Get("X-Escrow-Token")
		if subtle.ConstantTimeCompare([]byte(expectedToken), []byte(providedToken)) != 1 {
			slog.Warn("AUTH_FAILURE invalid escrow token", "host", req.Hostname, "remote_addr", remoteAddr(r))
			apiError(w, http.StatusForbidden, "invalid escrow token for hostname")
			return
		}
		// Replay protection: reject tokens that have already been redeemed.
		// Key on hostname+timestamp; each unique (hostname, timestamp) pair can
		// only be accepted once within the 5-minute validity window.
		// The challenge store persists used tokens across restarts to prevent replay
		// during the validity window even after a server restart.
		tokenKey := req.Hostname + ":" + tsHeader
		if s.store.UsedEscrowTokenCount() >= maxUsedEscrowTokens {
			apiError(w, http.StatusTooManyRequests, "escrow rate limit exceeded")
			return
		}
		if s.store.CheckAndRecordEscrowToken(tokenKey) {
			slog.Warn("REPLAY escrow token already used", "host", req.Hostname, "remote_addr", remoteAddr(r))
			apiError(w, http.StatusGone, "escrow token already used")
			return
		}
	}

	// Snapshot live-updated escrow config fields under read lock.
	s.cfgMu.RLock()
	escrowBackend := s.cfg.EscrowBackend
	escrowPath := s.cfg.EscrowPath
	s.cfgMu.RUnlock()

	hasNativeEscrow := escrowBackend != ""
	if s.cfg.EscrowCommand == "" && !hasNativeEscrow {
		slog.Warn("BREAKGLASS escrow received but not configured, password discarded", "host", req.Hostname)
		apiError(w, http.StatusNotImplemented, "escrow not configured on server")
		return
	}

	// Limit concurrent escrow operations
	select {
	case s.escrowSemaphore <- struct{}{}:
		defer func() { <-s.escrowSemaphore }()
	default:
		apiError(w, http.StatusServiceUnavailable, "too many concurrent escrow operations")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), escrowTimeout)
	defer cancel()

	var itemID, vaultID string

	if hasNativeEscrow {
		var backend escrow.Backend
		if escrowBackend == config.EscrowBackendLocal {
			backend = escrow.NewLocalEscrowBackend(s.escrowKey, s.store)
		} else {
			backend = escrow.NewEscrowBackend(s.cfg)
		}
		vault := escrow.ResolveEscrowVault(req.Hostname, s.cfg.EscrowVaultMap, escrowPath)
		var err error
		itemID, vaultID, err = backend.Store(ctx, req.Hostname, req.Password, vault)
		if err != nil {
			breakglassEscrowTotal.WithLabelValues("failure").Inc()
			slog.Error("BREAKGLASS escrow failed", "backend", escrowBackend, "host", req.Hostname, "err", err)
			apiError(w, http.StatusInternalServerError, "escrow failed")
			return
		}
		breakglassEscrowTotal.WithLabelValues("success").Inc()
	} else {
		// Execute escrow command with password on stdin and hostname as env var.
		// Password is NOT passed as an argument to avoid /proc/cmdline exposure.
		// Use a minimal environment to avoid leaking server secrets (CLIENT_SECRET,
		// SHARED_SECRET, etc.) to the escrow command.
		cmd := exec.CommandContext(ctx, "sh", "-c", s.cfg.EscrowCommand)
		cmd.Stdin = strings.NewReader(req.Password)
		// Start with minimal env, then add configured passthrough prefixes.
		// This prevents leaking server secrets while allowing cloud CLI tools
		// (AWS, Vault, etc.) to function when explicitly configured via
		// IDENTREE_ESCROW_ENV=AWS_,VAULT_,OP_
		cmdEnv := []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + os.Getenv("HOME"),
			"BREAKGLASS_HOSTNAME=" + req.Hostname,
		}
		if len(s.cfg.EscrowEnvPassthrough) > 0 {
			for _, env := range os.Environ() {
				// Skip vars that are already in the baseline to prevent shadowing
				if strings.HasPrefix(env, "PATH=") || strings.HasPrefix(env, "HOME=") || strings.HasPrefix(env, "BREAKGLASS_HOSTNAME=") {
					continue
				}
				for _, prefix := range s.cfg.EscrowEnvPassthrough {
					if prefix != "" && strings.HasPrefix(env, prefix) {
						cmdEnv = append(cmdEnv, env)
						break
					}
				}
			}
		}
		cmd.Env = cmdEnv

		// Use separate capped buffers instead of CombinedOutput() to prevent
		// memory exhaustion from a verbose or malicious escrow command.
		var stdoutBuf, stderrBuf bytes.Buffer
		cmd.Stdout = &limitedWriter{w: &stdoutBuf, n: escrowMaxOutput}
		cmd.Stderr = &limitedWriter{w: &stderrBuf, n: escrowMaxOutput}

		if err := cmd.Run(); err != nil {
			breakglassEscrowTotal.WithLabelValues("failure").Inc()
			combined := truncateOutput(stdoutBuf.String() + stderrBuf.String())
			slog.Error("BREAKGLASS escrow command failed", "host", req.Hostname, "err", err, "output", combined)
			apiError(w, http.StatusInternalServerError, "escrow command failed")
			return
		}
		breakglassEscrowTotal.WithLabelValues("success").Inc()

		// Parse item ID from escrow command stdout (format: "item_id=xxx")
		for _, line := range strings.Split(stdoutBuf.String(), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "item_id=") {
				itemID = strings.TrimPrefix(line, "item_id=")
				break
			}
		}
	}

	s.store.RecordEscrow(req.Hostname, itemID, vaultID)
	// Log the escrow as a "rotated_breakglass" action visible in the history page.
	// Since escrow is a machine-level operation (no user session), log it for all
	// users who have activity on this host so it appears in their history.
	for _, user := range s.store.UsersWithHostActivity(req.Hostname) {
		s.store.LogAction(user, challpkg.ActionRotatedBreakglass, req.Hostname, "", "")
	}
	slog.Info("BREAKGLASS password escrowed", "host", req.Hostname)
	// H9: prominent audit log for breakglass token issuance capturing all
	// relevant fields for incident investigation.
	backendName := string(escrowBackend)
	if backendName == "" {
		backendName = "command"
	}
	slog.Warn("BREAKGLASS_ESCROWED", "host", req.Hostname, "backend", backendName, "timestamp", time.Now().UTC().Format(time.RFC3339), "remote_addr", remoteAddr(r))
	s.dispatchNotification(notify.WebhookData{
		Event:     "breakglass_escrowed",
		Username:  req.Hostname,
		Hostname:  req.Hostname,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		slog.Error("writing JSON response", "err", err)
	}
}

// handleBreakglassReveal retrieves an escrowed break-glass password for a host
// and returns it to an authenticated admin. The reveal is logged to the action log.
// POST /api/breakglass/reveal
func (s *Server) handleBreakglassReveal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Verify admin session via JSON auth (reads CSRF from X-CSRF-Token / X-CSRF-Ts headers).
	actor := s.verifyJSONAdminAuth(w, r)
	if actor == "" {
		return
	}

	// Per-user mutation rate limit.
	if !s.mutationRL.allow(actor) {
		apiError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req struct {
		Hostname string `json:"hostname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		io.Copy(io.Discard, r.Body) //nolint:errcheck // best-effort drain for keep-alive
		apiError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	hostname := req.Hostname
	if hostname == "" || !validHostname.MatchString(hostname) {
		apiError(w, http.StatusBadRequest, "invalid hostname")
		return
	}

	// Confirm this host has an escrow record.
	escrowed := s.store.EscrowedHosts()
	record, ok := escrowed[hostname]
	if !ok {
		apiError(w, http.StatusNotFound, "no escrow record for host")
		return
	}

	// Snapshot live-updated escrow backend under read lock.
	s.cfgMu.RLock()
	revealEscrowBackend := s.cfg.EscrowBackend
	s.cfgMu.RUnlock()

	if revealEscrowBackend == "" {
		apiError(w, http.StatusNotImplemented, "no escrow backend configured")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), escrowTimeout)
	defer cancel()

	var backend escrow.Backend
	if revealEscrowBackend == config.EscrowBackendLocal {
		backend = escrow.NewLocalEscrowBackend(s.escrowKey, s.store)
	} else {
		backend = escrow.NewEscrowBackend(s.cfg)
	}

	password, err := backend.Retrieve(ctx, hostname, record.ItemID, record.VaultID)
	if err != nil {
		slog.Error("BREAKGLASS reveal failed", "host", hostname, "admin", actor, "err", err)
		apiError(w, http.StatusInternalServerError, "failed to retrieve password")
		return
	}

	// Log the reveal for every user with activity on this host so it is
	// visible in their history, with the admin as actor.
	for _, user := range s.store.UsersWithHostActivity(hostname) {
		s.store.LogAction(user, challpkg.ActionRevealedBreakglass, hostname, "", actor)
	}
	// Also log against the actor themselves so it always appears in their history.
	s.store.LogAction(actor, challpkg.ActionRevealedBreakglass, hostname, "", actor)
	slog.Warn("BREAKGLASS password revealed", "host", hostname, "admin", actor, "remote_addr", remoteAddr(r))

	s.dispatchNotification(notify.WebhookData{
		Event:     "revealed_breakglass",
		Username:  actor,
		Hostname:  hostname,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Actor:     actor,
	})

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"password":    password,
		"escrowed_at": record.Timestamp.UTC().Format(time.RFC3339),
	}); err != nil {
		slog.Error("writing reveal JSON response", "err", err)
	}
}
