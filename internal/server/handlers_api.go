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
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/rinseaid/identree/internal/breakglass"
	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/escrow"
	"github.com/rinseaid/identree/internal/notify"
)

// verifySharedSecret checks the X-Shared-Secret header using constant-time comparison
// to prevent timing attacks that could leak the secret byte-by-byte.
func (s *Server) verifySharedSecret(r *http.Request) bool {
	if s.cfg.SharedSecret == "" {
		return true
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
	if len(s.cfg.APIKeys) == 0 {
		return false
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		return false
	}
	tokenHash := hmac.New(sha256.New, []byte("api-key-verification"))
	tokenHash.Write([]byte(token))
	hashedToken := tokenHash.Sum(nil)

	for _, key := range s.cfg.APIKeys {
		h := hmac.New(sha256.New, []byte("api-key-verification"))
		h.Write([]byte(key))
		if subtle.ConstantTimeCompare(hashedToken, h.Sum(nil)) == 1 {
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
		// Check user authorization if registry is enabled
		if s.hostRegistry.IsEnabled() && hostname != "" {
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
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify Content-Type to prevent cross-origin form submission
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	// Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req struct {
		Username string `json:"username"`
		Hostname string `json:"hostname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	// Validate username to prevent log injection and other input-based attacks
	if !validUsername.MatchString(req.Username) {
		http.Error(w, "invalid username format", http.StatusBadRequest)
		return
	}

	// Validate hostname to prevent log injection (hostname is optional, empty is OK)
	if req.Hostname != "" && !validHostname.MatchString(req.Hostname) {
		http.Error(w, "invalid hostname format", http.StatusBadRequest)
		return
	}

	// Authenticate: try global shared secret, then per-host secret from registry.
	// We parse the body first so we have the hostname for per-host auth.
	authorized, errMsg := s.authenticateChallenge(r, req.Hostname, req.Username)
	if !authorized {
		authFailures.Inc()
		slog.Warn("AUTH_FAILURE", "reason", errMsg, "remote_addr", remoteAddr(r), "host", req.Hostname, "user", req.Username)
		if errMsg == "user not authorized on this host" {
			http.Error(w, errMsg, http.StatusForbidden)
		} else {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
		return
	}

	// Snapshot the rotation signal BEFORE creating the challenge so the value
	// is set on the struct before it enters the store's map (avoids data race
	// with concurrent Get() calls that copy the struct under RLock).
	var rotateBefore string
	if !s.cfg.BreakglassRotateBefore.IsZero() {
		rotateBefore = s.cfg.BreakglassRotateBefore.Format(time.RFC3339)
	}

	challenge, err := s.store.Create(req.Username, req.Hostname, rotateBefore)
	if err != nil {
		// Rate limit errors are returned by the store when too many challenges exist
		if errors.Is(err, challpkg.ErrTooManyChallenges) || errors.Is(err, challpkg.ErrTooManyPerUser) {
			rateLimitRejections.Inc()
			slog.Warn("RATE_LIMIT", "user", req.Username, "remote_addr", remoteAddr(r), "host", req.Hostname)
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		slog.Error("creating challenge", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	challengesCreated.Inc()
	challpkg.ActiveChallenges.Inc()
	slog.Info("CHALLENGE created", "challenge", challenge.ID[:8], "user", req.Username, "remote_addr", remoteAddr(r), "host", req.Hostname)
	s.broadcastSSE(req.Username, "challenge_created")

	// Build client_config if any server-side client overrides are set
	clientCfg := s.buildClientConfig()

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
		s.store.LogAction(req.Username, challpkg.ActionAutoApproved, hostname, challenge.UserCode, "")
		s.sendEventNotification(notify.WebhookData{
			Event:     "auto_approved",
			Username:  req.Username,
			Hostname:  hostname,
			UserCode:  challenge.UserCode,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"challenge_id":    challenge.ID,
			"user_code":       challenge.UserCode,
			"expires_in":      int(s.cfg.ChallengeTTL.Seconds()),
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

	oneTapToken := s.computeOneTapToken(challenge.ID, challenge.ExpiresAt)
	oneTapURL := ""
	if oneTapToken != "" {
		oneTapURL = s.baseURL + "/api/onetap/" + oneTapToken
	}

	// Fire push notification asynchronously (no-op if not configured).
	s.sendNotification(challenge, approvalURL, oneTapURL)

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"challenge_id":     challenge.ID,
		"user_code":        challenge.UserCode,
		"verification_url": approvalURL,
		"expires_in":       int(s.cfg.ChallengeTTL.Seconds()),
	}
	if s.cfg.NotifyBackend != "" {
		resp["notification_sent"] = true
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
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.verifyAPISecret(r) {
		authFailures.Inc()
		slog.Warn("AUTH_FAILURE invalid shared secret", "path", "GET /api/challenge/", "remote_addr", remoteAddr(r))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/challenge/")
	if id == "" {
		http.Error(w, "challenge ID required", http.StatusBadRequest)
		return
	}

	// Validate challenge ID format (hex string, 32 chars for 16 bytes)
	if len(id) != 32 || !isHex(id) {
		http.Error(w, "invalid challenge ID", http.StatusBadRequest)
		return
	}

	challenge, ok := s.store.Get(id)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		if err := json.NewEncoder(w).Encode(map[string]string{"status": string(challpkg.StatusExpired)}); err != nil {
			slog.Error("writing JSON response", "err", err)
		}
		return
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
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.verifyAPISecret(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	username := r.URL.Query().Get("username")
	hostname := r.URL.Query().Get("hostname")
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}
	if !validUsername.MatchString(username) {
		http.Error(w, "invalid username", http.StatusBadRequest)
		return
	}
	if hostname != "" && !validHostname.MatchString(hostname) {
		http.Error(w, "invalid hostname", http.StatusBadRequest)
		return
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
	mac := hmac.New(sha256.New, []byte(s.cfg.SharedSecret))
	fmt.Fprintf(mac, "%d:%s%d:%s%d:%s", len(challengeID), challengeID, len(status), status, len(username), username)
	// Include rotate_breakglass_before in the HMAC so a MITM cannot inject
	// a rotation signal without invalidating the token.
	if rotateBefore != "" {
		fmt.Fprintf(mac, "%d:%s", len(rotateBefore), rotateBefore)
	}
	// Include revoke_tokens_before in the HMAC so a MITM cannot inject
	// a revocation signal without invalidating the token.
	if revokeTokensBefore != "" {
		fmt.Fprintf(mac, "r%d:%s", len(revokeTokensBefore), revokeTokensBefore)
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// computeOneTapToken creates a time-limited, single-use HMAC token for one-tap approval.
// Format: {challenge_id}.{expires_unix}.{hmac_hex}
func (s *Server) computeOneTapToken(challengeID string, expiresAt time.Time) string {
	if s.cfg.SharedSecret == "" {
		return ""
	}
	expires := strconv.FormatInt(expiresAt.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(s.cfg.SharedSecret))
	mac.Write([]byte("onetap:" + challengeID + ":" + expires))
	sig := hex.EncodeToString(mac.Sum(nil))
	return challengeID + "." + expires + "." + sig
}

// buildClientConfig returns a client config override map if any fields are set,
// or nil if no overrides are configured.
func (s *Server) buildClientConfig() map[string]interface{} {
	cfg := make(map[string]interface{})
	if s.cfg.ClientPollInterval > 0 {
		cfg["poll_interval"] = s.cfg.ClientPollInterval.String()
	}
	if s.cfg.ClientTimeout > 0 {
		cfg["timeout"] = s.cfg.ClientTimeout.String()
	}
	if s.cfg.ClientBreakglassEnabled != nil {
		cfg["breakglass_enabled"] = *s.cfg.ClientBreakglassEnabled
	}
	if s.cfg.ClientBreakglassPasswordType != "" {
		cfg["breakglass_password_type"] = s.cfg.ClientBreakglassPasswordType
	}
	if s.cfg.ClientBreakglassRotationDays > 0 {
		cfg["breakglass_rotation_days"] = s.cfg.ClientBreakglassRotationDays
	}
	if s.cfg.ClientTokenCacheEnabled != nil {
		cfg["token_cache_enabled"] = *s.cfg.ClientTokenCacheEnabled
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
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Escrow endpoint ALWAYS requires authentication — even with IDENTREE_INSECURE=true.
	// Unlike the challenge API, this endpoint executes a shell command with caller-provided
	// data on stdin, so unauthenticated access would be a command execution vector.
	if s.cfg.SharedSecret == "" && !s.hostRegistry.IsEnabled() {
		http.Error(w, "escrow endpoint requires shared secret authentication", http.StatusForbidden)
		return
	}

	if !s.verifyAPISecret(r) {
		authFailures.Inc()
		slog.Warn("AUTH_FAILURE invalid shared secret", "path", "POST /api/breakglass/escrow", "remote_addr", remoteAddr(r))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req struct {
		Hostname string `json:"hostname"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Password == "" {
		http.Error(w, "password required", http.StatusBadRequest)
		return
	}
	// Hostname is required for escrow (used for per-host token verification
	// and as the key in the escrow command's BREAKGLASS_HOSTNAME env var).
	if req.Hostname == "" {
		http.Error(w, "hostname required", http.StatusBadRequest)
		return
	}
	if !validHostname.MatchString(req.Hostname) {
		http.Error(w, "invalid hostname format", http.StatusBadRequest)
		return
	}

	// Verify per-host escrow authorization to prevent a compromised host from
	// planting a known password for a different host.
	//
	// When using a global SharedSecret: verify HMAC(shared_secret, "escrow:"+hostname).
	// When using host registry (no global SharedSecret): re-validate that the
	// caller's credential specifically matches req.Hostname, not just any host.
	if s.cfg.SharedSecret != "" {
		expectedToken := breakglass.ComputeEscrowToken(s.cfg.SharedSecret, req.Hostname)
		providedToken := r.Header.Get("X-Escrow-Token")
		if subtle.ConstantTimeCompare([]byte(expectedToken), []byte(providedToken)) != 1 {
			slog.Warn("AUTH_FAILURE invalid escrow token", "host", req.Hostname, "remote_addr", remoteAddr(r))
			http.Error(w, "invalid escrow token for hostname", http.StatusForbidden)
			return
		}
	} else if s.hostRegistry.IsEnabled() {
		// Without a global SharedSecret, verifyAPISecret above only checked that
		// the credential matches *some* host in the registry. Re-check here that
		// it specifically matches the target hostname, so a host can only escrow
		// for itself.
		provided := r.Header.Get("X-Shared-Secret")
		if !s.hostRegistry.ValidateHost(req.Hostname, provided) {
			slog.Warn("AUTH_FAILURE escrow credential does not match target hostname", "host", req.Hostname, "remote_addr", remoteAddr(r))
			http.Error(w, "invalid credential for hostname", http.StatusForbidden)
			return
		}
	}

	hasNativeEscrow := s.cfg.EscrowBackend != ""
	if s.cfg.EscrowCommand == "" && !hasNativeEscrow {
		slog.Warn("BREAKGLASS escrow received but not configured, password discarded", "host", req.Hostname)
		http.Error(w, "escrow not configured on server", http.StatusNotImplemented)
		return
	}

	// Limit concurrent escrow operations
	select {
	case escrowSemaphore <- struct{}{}:
		defer func() { <-escrowSemaphore }()
	default:
		http.Error(w, "too many concurrent escrow operations", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), escrowTimeout)
	defer cancel()

	var itemID, vaultID string

	if hasNativeEscrow {
		var backend escrow.Backend
		if s.cfg.EscrowBackend == config.EscrowBackendLocal {
			backend = escrow.NewLocalEscrowBackend(s.escrowKey, s.store)
		} else {
			backend = escrow.NewEscrowBackend(s.cfg)
		}
		vault := escrow.ResolveEscrowVault(req.Hostname, s.cfg.EscrowVaultMap, s.cfg.EscrowPath)
		var err error
		itemID, vaultID, err = backend.Store(ctx, req.Hostname, req.Password, vault)
		if err != nil {
			breakglassEscrowTotal.WithLabelValues("failure").Inc()
			slog.Error("BREAKGLASS escrow failed", "backend", s.cfg.EscrowBackend, "host", req.Hostname, "err", err)
			http.Error(w, "escrow failed", http.StatusInternalServerError)
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
			http.Error(w, "escrow command failed", http.StatusInternalServerError)
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
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify admin session via form auth (includes CSRF check).
	actor := s.verifyFormAuth(w, r)
	if actor == "" {
		return
	}
	if s.getSessionRole(r) != "admin" {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}

	hostname := r.FormValue("hostname")
	if hostname == "" || !validHostname.MatchString(hostname) {
		http.Error(w, "invalid hostname", http.StatusBadRequest)
		return
	}

	// Confirm this host has an escrow record.
	escrowed := s.store.EscrowedHosts()
	record, ok := escrowed[hostname]
	if !ok {
		http.Error(w, "no escrow record for host", http.StatusNotFound)
		return
	}

	if s.cfg.EscrowBackend == "" {
		http.Error(w, "no escrow backend configured", http.StatusNotImplemented)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), escrowTimeout)
	defer cancel()

	var backend escrow.Backend
	if s.cfg.EscrowBackend == config.EscrowBackendLocal {
		backend = escrow.NewLocalEscrowBackend(s.escrowKey, s.store)
	} else {
		backend = escrow.NewEscrowBackend(s.cfg)
	}

	password, err := backend.Retrieve(ctx, hostname, record.ItemID, record.VaultID)
	if err != nil {
		slog.Error("BREAKGLASS reveal failed", "host", hostname, "admin", actor, "err", err)
		http.Error(w, "failed to retrieve password", http.StatusInternalServerError)
		return
	}

	// Log the reveal for every user with activity on this host so it is
	// visible in their history, with the admin as actor.
	for _, user := range s.store.UsersWithHostActivity(hostname) {
		s.store.LogAction(user, challpkg.ActionRevealedBreakglass, hostname, "", actor)
	}
	// Also log against the actor themselves so it always appears in their history.
	s.store.LogAction(actor, challpkg.ActionRevealedBreakglass, hostname, "", actor)
	slog.Info("BREAKGLASS password revealed", "host", hostname, "admin", actor, "remote_addr", remoteAddr(r))

	s.sendEventNotification(notify.WebhookData{
		Event:     "revealed_breakglass",
		Username:  actor,
		Hostname:  hostname,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"password":    password,
		"escrowed_at": record.Timestamp.UTC().Format(time.RFC3339),
	}); err != nil {
		slog.Error("writing reveal JSON response", "err", err)
	}
}
