package pam

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/rinseaid/identree/internal/breakglass"
	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/i18n"
	"github.com/rinseaid/identree/internal/sanitize"
)

// MessageWriter is where PAM messages are written. pam_exec sends stdout to
// the user's terminal. Overridable for testing.
var MessageWriter io.Writer = os.Stdout

// validChallengeID validates that a challenge ID from the server is a 32-char hex string,
// preventing path traversal or query injection when used in poll URLs.
var validChallengeID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// PAMClient is the helper that runs under pam_exec, creates a challenge,
// displays the approval URL, and polls until approved/denied/expired.
type PAMClient struct {
	cfg        *config.ClientConfig
	client     *http.Client
	tokenCache *TokenCache
	hostname   string // resolved once at construction; avoids repeated syscalls
}

// maxResponseSize limits how much of a server response we will read (64KB).
// Prevents a malicious/compromised server from causing OOM in the PAM helper.
const maxResponseSize = 64 * 1024

// serverHTTPError is an alias for breakglass.ServerHTTPError.
type serverHTTPError = breakglass.ServerHTTPError

// NewPAMClient creates a new PAM helper client.
// Returns an error if cfg.ServerURL uses plain HTTP, which would transmit the
// shared secret in cleartext.
// hostname should be resolved once by the caller (e.g. runPAMHelper) and
// passed in so that it is consistent with the hostname stored in the token
// cache; passing an empty string is safe and results in hostname being omitted
// from challenge requests.
func NewPAMClient(cfg *config.ClientConfig, tokenCache *TokenCache, hostname string) (*PAMClient, error) {
	if strings.HasPrefix(cfg.ServerURL, "http://") {
		return nil, fmt.Errorf("identree: ServerURL must use https://, not http:// (shared secret would be sent in cleartext)")
	}

	return &PAMClient{
		cfg:        cfg,
		tokenCache: tokenCache,
		hostname:   hostname,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				// Never use proxy env vars — prevents an attacker from routing
				// requests through a malicious proxy via HTTP_PROXY/HTTPS_PROXY.
				Proxy: nil,
				// Explicit dial timeout (shorter than client Timeout) ensures that
				// connection-phase failures (SYN dropped by firewall) always produce
				// net.OpError{Op:"dial"} rather than racing with the client-level
				// timeout. This makes isServerUnreachable detection reliable.
				DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			},
			// Do not follow redirects. The PAM client talks to a known API server;
			// following redirects could enable SSRF if the server URL is misconfigured
			// or if a MITM redirects to internal services.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// clientConfigResponse is the server-side client config override.
type clientConfigResponse struct {
	PollInterval           string `json:"poll_interval,omitempty"`            // Go duration string, e.g. "2s"
	Timeout                string `json:"timeout,omitempty"`                  // Go duration string, e.g. "120s"
	BreakglassEnabled      *bool  `json:"breakglass_enabled,omitempty"`
	BreakglassPasswordType string `json:"breakglass_password_type,omitempty"`
	BreakglassRotationDays int    `json:"breakglass_rotation_days,omitempty"`
	TokenCacheEnabled      *bool  `json:"token_cache_enabled,omitempty"`
}

// challengeResponse is the response from POST /api/challenge.
type challengeResponse struct {
	ChallengeID            string                `json:"challenge_id"`
	UserCode               string                `json:"user_code"`
	VerificationURL        string                `json:"verification_url"`
	ExpiresIn              int                   `json:"expires_in"`
	Status                 string                `json:"status,omitempty"`
	ApprovalToken          string                `json:"approval_token,omitempty"`
	RotateBreakglassBefore string                `json:"rotate_breakglass_before,omitempty"`
	RevokeTokensBefore     string                `json:"revoke_tokens_before,omitempty"`
	NotificationSent       bool                  `json:"notification_sent,omitempty"`
	GraceRemaining         int                   `json:"grace_remaining,omitempty"`
	ClientConfig           *clientConfigResponse  `json:"client_config,omitempty"`
}

// pollResponse is the response from GET /api/challenge/{id}.
type pollResponse struct {
	Status         string `json:"status"`
	ExpiresIn      int    `json:"expires_in"`
	ApprovalToken  string `json:"approval_token,omitempty"`
	DenialToken    string `json:"denial_token,omitempty"`
	IDToken        string `json:"id_token,omitempty"`
	GraceRemaining int    `json:"grace_remaining,omitempty"`

	// serverExpired is set locally when the server returns 404 (not from JSON).
	// Used to distinguish server-reported expiry from HMAC-verified status.
	serverExpired bool `json:"-"`
}

// Authenticate runs the full PAM authentication flow for the given username.
// Returns nil on success (sudo approved), non-nil on failure.
func (p *PAMClient) Authenticate(username string) error {
	// Reject usernames that could cause path traversal in the token cache.
	// Valid Unix usernames never contain '/' or null bytes; this is defence-in-depth
	// since the PAM subsystem already enforces OS-level username constraints.
	if strings.ContainsAny(username, "/\x00") {
		return fmt.Errorf("identree: invalid username")
	}
	// Detect terminal language for user-facing messages
	t := i18n.T(i18n.TerminalLang())
	// Set up signal handling so Ctrl+C exits cleanly.
	// Write to stderr (not stdout/MessageWriter) because the PAM conversation
	// pipe on stdout may have a full buffer, causing fmt.Fprintf to block
	// indefinitely and preventing os.Exit from ever being reached.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			fmt.Fprintln(os.Stderr, "identree: interrupted")
			os.Exit(1)
		case <-ctx.Done():
		}
	}()
	defer signal.Stop(sigCh)

	// 0. Check token cache — if a cached id_token is valid, grant access.
	// Also check the server for revocation signals — a revoked session takes
	// precedence over the token cache.
	if p.tokenCache != nil {
		if tokenRemaining, cacheMtime, err := p.tokenCache.Check(username); err == nil {
			// Check server for revocation and grace period (required — fail-closed on error).
			graceStatus, graceErr := p.queryGraceStatus(username)
			if graceErr != nil {
				// Cannot verify grace period with the server — fail-closed rather
				// than silently approving from cache with a potentially stale token.
				return fmt.Errorf("could not verify grace period with server — please retry")
			}

			// If the server reports a revocation that postdates our cache, invalidate it.
			// cacheMtime comes from Check()'s open-fd Stat, avoiding a TOCTOU race.
			// Fail-closed: if mtime is before revocation time, treat as revoked.
			skipCache := false
			if graceStatus.revoked {
				if cacheMtime.Before(graceStatus.revokeTime) {
					p.tokenCache.Delete(username)
					skipCache = true
				}
			}

			if !skipCache {
				// Show the effective remaining time (max of token and grace)
				effective := tokenRemaining
				if graceStatus.graceRemaining > effective {
					effective = graceStatus.graceRemaining
				}
				fmt.Fprintf(MessageWriter, "  "+t("terminal_sudo_approved")+"\n", formatDuration(t, effective))
				// Still run break-glass age-based rotation check (no server signal
				// available since we didn't contact the server, so rotateBefore is zero).
				breakglass.MaybeRotateBreakglass(p.cfg, time.Time{})
				return nil
			}
		}
		// Cache miss, invalid, or revoked — fall through to device flow
	}

	// 1. Create challenge
	challenge, err := p.createChallenge(username)
	if err != nil {
		// Break-glass fallback: if the server is unreachable and a break-glass
		// hash file exists, fall back to local password authentication.
		if p.cfg.BreakglassEnabled && breakglass.BreakglassFileExists(p.cfg.BreakglassFile) && breakglass.IsServerUnreachable(err) {
			return breakglass.AuthenticateBreakglass(username, p.cfg.BreakglassFile)
		}
		// Map HTTP status codes to human-readable terminal messages.
		var httpErr *serverHTTPError
		if errors.As(err, &httpErr) {
			switch {
			case httpErr.StatusCode == http.StatusTooManyRequests:
				return fmt.Errorf("too many pending requests — please wait before trying again")
			case httpErr.StatusCode == http.StatusUnauthorized || httpErr.StatusCode == http.StatusForbidden:
				return fmt.Errorf("authentication failed — check identree configuration")
			case httpErr.StatusCode >= 500:
				return fmt.Errorf("authentication server error — contact your admin")
			default:
				return fmt.Errorf("creating challenge: server returned %d", httpErr.StatusCode)
			}
		}
		return fmt.Errorf("creating challenge: %w", err)
	}

	// Parse server-requested rotation timestamp (if any).
	// Only acted on after HMAC verification (the field is included in the HMAC),
	// so a MITM cannot inject a rotation signal without invalidating the token.
	var rotateBefore time.Time
	if challenge.RotateBreakglassBefore != "" {
		if t, err := time.Parse(time.RFC3339, challenge.RotateBreakglassBefore); err == nil {
			rotateBefore = t
		}
	}

	// 2. Check if auto-approved via grace period
	if challenge.Status == string(challpkg.StatusApproved) {
		if p.cfg.SharedSecret != "" {
			if !p.verifyStatusToken(challenge.ChallengeID, username, "approved", challenge.ApprovalToken, challenge.RotateBreakglassBefore, challenge.RevokeTokensBefore) {
				return fmt.Errorf("auto-approval token verification failed (possible MITM attack)")
			}
		}

		// Handle cache invalidation BEFORE applying client config overrides.
		// applyClientConfig can set p.tokenCache = nil if the (unverified)
		// client_config injects token_cache_enabled=false; doing so before
		// handleCacheInvalidation would suppress a legitimate revocation signal.
		handleCacheInvalidation(p, challenge, username)

		// Apply server-side client config overrides AFTER cache invalidation.
		// client_config is not HMAC-protected, so a MITM could inject values.
		// Capture breakglass_enabled before applyClientConfig so an injected
		// "breakglass_enabled: false" cannot suppress a server-requested rotation
		// that was signalled via the HMAC-protected rotateBefore field.
		origBreakglassEnabled := p.cfg.BreakglassEnabled
		applyClientConfig(p, challenge)
		if challenge.GraceRemaining > 0 {
			fmt.Fprintf(MessageWriter, "  "+t("terminal_sudo_approved")+"\n", formatDuration(t, time.Duration(challenge.GraceRemaining)*time.Second))
		} else {
			fmt.Fprintf(MessageWriter, "  %s\n", t("terminal_sudo_approved_short"))
		}
		// Use the pre-client-config breakglass_enabled so a MITM-injected
		// "breakglass_enabled: false" cannot block an HMAC-verified rotation.
		cfgForRotate := *p.cfg
		cfgForRotate.BreakglassEnabled = origBreakglassEnabled
		breakglass.MaybeRotateBreakglass(&cfgForRotate, rotateBefore)
		return nil
	}

	// 3. Display approval info to user.
	// Sanitize all server-provided values before terminal display to prevent
	// ANSI escape injection from a compromised server.
	fmt.Fprintf(MessageWriter, "  %s\n", t("terminal_requires_approval"))
	if challenge.VerificationURL != "" {
		fmt.Fprintf(MessageWriter, "  %s %s\n", t("terminal_approve_at"), sanitize.ForTerminal(challenge.VerificationURL))
	}
	fmt.Fprintf(MessageWriter, "  %s %s", t("terminal_code"), sanitize.ForTerminal(challenge.UserCode))
	if challenge.NotificationSent {
		fmt.Fprintf(MessageWriter, " %s", t("terminal_notification_sent"))
	}
	fmt.Fprintf(MessageWriter, "\n")

	// 4. Poll until resolved
	if p.cfg.SharedSecret == "" {
		fmt.Fprintf(os.Stderr, "identree: WARNING: no shared secret configured — HMAC verification disabled\n")
	}

	var consecutiveErrors int
	deadline := time.Now().Add(p.cfg.Timeout)

	// pollBackoff is the current exponential-backoff sleep duration used on
	// poll errors.  It starts at 1s, doubles on each consecutive error, and is
	// capped at 30s.  It resets to 1s on any successful (non-error) response,
	// regardless of the challenge status (pending/approved/denied).
	pollBackoff := time.Second
	const pollBackoffMax = 30 * time.Second

	// Initial delay before first poll — the challenge was just created,
	// give the user a moment to start the approval flow.
	if err := sleepWithContext(ctx, p.cfg.PollInterval); err != nil {
		return err
	}

	ppid := os.Getppid()
	for time.Now().Before(deadline) {
		// Check if parent process died (e.g., sudo killed by Ctrl+C).
		// On Linux, PR_SET_PDEATHSIG handles this faster, but this
		// is a portable fallback for macOS and other systems.
		if os.Getppid() != ppid {
			fmt.Fprintln(os.Stderr, "identree: parent process died, exiting")
			os.Exit(1)
		}

		status, err := p.pollChallenge(challenge.ChallengeID)
		if err != nil {
			consecutiveErrors++
			// Log first error and every 10th to avoid flooding
			if consecutiveErrors == 1 || consecutiveErrors%10 == 0 {
				fmt.Fprintf(os.Stderr, "identree: poll error (%d consecutive): %v\n", consecutiveErrors, err)
			}
			// Break-glass fallback: if server becomes unreachable during polling
			if consecutiveErrors > 5 && breakglass.IsServerUnreachable(err) &&
				p.cfg.BreakglassEnabled && breakglass.BreakglassFileExists(p.cfg.BreakglassFile) {
				fmt.Fprintf(MessageWriter, "  %s\n", t("terminal_server_unreachable"))
				return breakglass.AuthenticateBreakglass(username, p.cfg.BreakglassFile)
			}
			// Exponential backoff on error: sleep for pollBackoff, then double it.
			if err := sleepWithContext(ctx, pollBackoff); err != nil {
				return err
			}
			pollBackoff *= 2
			if pollBackoff > pollBackoffMax {
				pollBackoff = pollBackoffMax
			}
			continue
		}
		// Successful (non-error) response — reset error counter and backoff.
		consecutiveErrors = 0
		pollBackoff = time.Second

		switch challpkg.ChallengeStatus(status.Status) {
		case challpkg.StatusApproved:
			// Verify HMAC approval token to prevent MITM forgery
			if p.cfg.SharedSecret != "" {
				if !p.verifyStatusToken(challenge.ChallengeID, username, "approved", status.ApprovalToken, challenge.RotateBreakglassBefore, challenge.RevokeTokensBefore) {
					return fmt.Errorf("approval token verification failed (possible MITM attack)")
				}
			}
			// Cache the id_token for future authentication without device flow
			if p.tokenCache != nil && status.IDToken != "" {
				if err := p.tokenCache.Write(username, status.IDToken); err != nil {
					fmt.Fprintf(os.Stderr, "identree: WARNING: failed to cache token: %v\n", err)
				}
			}
			fmt.Fprintf(MessageWriter, "  %s\n", t("terminal_approved"))
			breakglass.MaybeRotateBreakglass(p.cfg, rotateBefore)
			return nil
		case challpkg.StatusDenied:
			// Verify HMAC denial token to prevent MITM injecting fake denials.
			// If verification fails, treat as a forged response and keep polling.
			// We never accept unverified denials — a MITM should not be able to
			// deny sudo requests by injecting fake denial responses.
			if p.cfg.SharedSecret != "" {
				if !p.verifyStatusToken(challenge.ChallengeID, username, "denied", status.DenialToken, challenge.RotateBreakglassBefore, challenge.RevokeTokensBefore) {
					fmt.Fprintf(os.Stderr, "identree: WARNING: denial token verification failed — ignoring possible forged denial\n")
					if err := sleepWithContext(ctx, p.cfg.PollInterval); err != nil {
						return err
					}
					continue
				}
			}
			fmt.Fprintf(MessageWriter, "  %s\n", t("terminal_denied"))
			return fmt.Errorf("sudo request denied")
		case challpkg.StatusExpired:
			// When HMAC is configured, don't trust ANY unverified expiry.
			// A MITM could inject 404 or {"status":"expired"} as a 200
			// response to block sudo approvals. Keep polling until our
			// own client-side timeout (cfg.Timeout) expires instead.
			if p.cfg.SharedSecret != "" {
				fmt.Fprintf(os.Stderr, "identree: WARNING: ignoring unverified expiry — continuing to poll until client timeout\n")
				if err := sleepWithContext(ctx, p.cfg.PollInterval); err != nil {
					return err
				}
				continue
			}
			fmt.Fprintf(MessageWriter, "  %s\n", t("terminal_expired"))
			return fmt.Errorf("sudo request expired")
		case challpkg.StatusPending:
			// Poll again after interval
		default:
			return fmt.Errorf("unexpected status: %s", sanitize.ForTerminal(status.Status))
		}

		if err := sleepWithContext(ctx, p.cfg.PollInterval); err != nil {
			return err
		}
	}

	fmt.Fprintf(MessageWriter, "  %s\n", t("terminal_expired"))
	return fmt.Errorf("timed out waiting for approval")
}

// sleepWithContext sleeps for the given duration but returns early if ctx is cancelled.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// graceStatusResult holds the response from the grace status endpoint.
type graceStatusResult struct {
	graceRemaining time.Duration
	revoked        bool
	revokeTime     time.Time
}

// queryGraceStatus makes a quick call to the server to get the grace period
// remaining and any revocation signal. Returns a non-nil error on any failure
// (server unreachable, timeout, non-200 response, decode error). On cache hits,
// a revocation signal takes precedence over the cached token — the cache is
// deleted and the client falls through to the device flow.
func (p *PAMClient) queryGraceStatus(username string) (graceStatusResult, error) {
	if p.cfg.ServerURL == "" {
		return graceStatusResult{}, fmt.Errorf("no server URL configured")
	}
	u := fmt.Sprintf("%s/api/grace-status", p.cfg.ServerURL)
	params := "?username=" + neturl.QueryEscape(username) + "&hostname=" + neturl.QueryEscape(p.hostname)
	url := u + params
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return graceStatusResult{}, err
	}
	if p.cfg.SharedSecret != "" {
		req.Header.Set("X-Shared-Secret", p.cfg.SharedSecret)
	}
	// Short timeout — revocation check is critical but must not block sudo indefinitely.
	// Hardened like the main client: no proxy, no redirect following.
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			Proxy:       nil,
			DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return graceStatusResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return graceStatusResult{}, fmt.Errorf("grace status returned HTTP %d", resp.StatusCode)
	}
	var result struct {
		GraceRemaining     int    `json:"grace_remaining"`
		RevokeTokensBefore string `json:"revoke_tokens_before,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512)).Decode(&result); err != nil {
		return graceStatusResult{}, fmt.Errorf("decoding grace status: %w", err)
	}
	gs := graceStatusResult{
		graceRemaining: time.Duration(result.GraceRemaining) * time.Second,
	}
	if result.RevokeTokensBefore != "" {
		if t, err := time.Parse(time.RFC3339, result.RevokeTokensBefore); err == nil {
			gs.revoked = true
			gs.revokeTime = t
		}
	}
	return gs, nil
}

// applyClientConfig applies server-side config overrides to the PAM client.
// Called AFTER HMAC verification to prevent MITM injection of config values.
func applyClientConfig(p *PAMClient, challenge *challengeResponse) {
	if challenge.ClientConfig == nil {
		return
	}
	if challenge.ClientConfig.PollInterval != "" {
		if d, err := time.ParseDuration(challenge.ClientConfig.PollInterval); err == nil {
			p.cfg.PollInterval = d
		}
	}
	if p.cfg.PollInterval <= 0 || p.cfg.PollInterval < time.Second {
		p.cfg.PollInterval = time.Second
	}
	if challenge.ClientConfig.Timeout != "" {
		if d, err := time.ParseDuration(challenge.ClientConfig.Timeout); err == nil {
			p.cfg.Timeout = d
		}
	}
	if p.cfg.Timeout != 0 && p.cfg.Timeout < 5*time.Second {
		p.cfg.Timeout = 5 * time.Second
	}
	const maxTimeout = 10 * time.Minute
	if p.cfg.Timeout > maxTimeout {
		fmt.Fprintf(os.Stderr, "identree: WARNING: server-provided timeout %v exceeds maximum (%v), clamping\n", p.cfg.Timeout, maxTimeout)
		p.cfg.Timeout = maxTimeout
	}
	if challenge.ClientConfig.BreakglassEnabled != nil {
		p.cfg.BreakglassEnabled = *challenge.ClientConfig.BreakglassEnabled
	}
	if challenge.ClientConfig.BreakglassPasswordType != "" {
		p.cfg.BreakglassPasswordType = challenge.ClientConfig.BreakglassPasswordType
	}
	if challenge.ClientConfig.BreakglassRotationDays > 0 {
		p.cfg.BreakglassRotationDays = challenge.ClientConfig.BreakglassRotationDays
	}
	if challenge.ClientConfig.TokenCacheEnabled != nil {
		p.cfg.TokenCacheEnabled = *challenge.ClientConfig.TokenCacheEnabled
		if !p.cfg.TokenCacheEnabled {
			p.tokenCache = nil
		}
	}
}

// handleCacheInvalidation deletes the token cache if the server sent a revocation signal.
func handleCacheInvalidation(p *PAMClient, challenge *challengeResponse, username string) {
	if challenge.RevokeTokensBefore == "" || p.tokenCache == nil {
		return
	}
	if revokeTime, err := time.Parse(time.RFC3339, challenge.RevokeTokensBefore); err == nil {
		if mtime, err := p.tokenCache.ModTime(username); err == nil {
			if mtime.Before(revokeTime) {
				p.tokenCache.Delete(username)
			}
		}
	}
}

// verifyStatusToken verifies an HMAC-SHA256 status token from the server.
// The status parameter must match what the server used (e.g., "approved", "denied").
// Uses length-prefixed fields to match the server's computeStatusHMAC format.
// rotateBefore and revokeTokensBefore are included in the HMAC to prevent a MITM
// from injecting these signals without invalidating the token.
func (p *PAMClient) verifyStatusToken(challengeID, username, status, token, rotateBefore, revokeTokensBefore string) bool {
	if token == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(p.cfg.SharedSecret))
	fmt.Fprintf(mac, "%d:%s%d:%s%d:%s", len(challengeID), challengeID, len(status), status, len(username), username)
	if rotateBefore != "" {
		fmt.Fprintf(mac, "%d:%s", len(rotateBefore), rotateBefore)
	}
	if revokeTokensBefore != "" {
		fmt.Fprintf(mac, "r%d:%s", len(revokeTokensBefore), revokeTokensBefore)
	}
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(token))
}

func (p *PAMClient) createChallenge(username string) (*challengeResponse, error) {
	payload := map[string]string{"username": username}
	if p.hostname != "" {
		payload["hostname"] = p.hostname
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, p.cfg.ServerURL+"/api/challenge", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.cfg.SharedSecret != "" {
		req.Header.Set("X-Shared-Secret", p.cfg.SharedSecret)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to auth server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Limit how much of the error response we read and sanitize for terminal safety
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		safe := sanitize.ForTerminal(string(b))
		return nil, &serverHTTPError{StatusCode: resp.StatusCode, Body: safe}
	}

	var cr challengeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&cr); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	// Validate challenge ID format to prevent path traversal or query injection
	// if a compromised server returns a malicious challenge ID.
	if !validChallengeID.MatchString(cr.ChallengeID) {
		return nil, fmt.Errorf("server returned invalid challenge ID format")
	}

	return &cr, nil
}

func (p *PAMClient) pollChallenge(challengeID string) (*pollResponse, error) {
	pollURL := p.cfg.ServerURL + "/api/challenge/" + challengeID
	if p.hostname != "" {
		pollURL += "?hostname=" + neturl.QueryEscape(p.hostname)
	}
	req, err := http.NewRequest(http.MethodGet, pollURL, nil)
	if err != nil {
		return nil, err
	}
	if p.cfg.SharedSecret != "" {
		req.Header.Set("X-Shared-Secret", p.cfg.SharedSecret)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check HTTP status before trusting response body
	switch resp.StatusCode {
	case http.StatusOK:
		// normal — decode below
	case http.StatusNotFound, http.StatusGone:
		// When HMAC is configured, treat 404/410 as an unverified response.
		// A MITM could inject 404s/410s to prevent the client from ever seeing
		// an "approved" response. Mark as server-expired (distinct from
		// client-side timeout) so the caller can handle it appropriately.
		// 410 Gone is returned when the challenge has been explicitly deleted/expired.
		return &pollResponse{Status: string(challpkg.StatusExpired), serverExpired: true}, nil
	default:
		return nil, fmt.Errorf("poll returned HTTP %d", resp.StatusCode)
	}

	var pr pollResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&pr); err != nil {
		return nil, err
	}
	return &pr, nil
}

// formatDuration formats a duration as a human-readable string like "3h 12m" or "47m".
// t is a translation lookup function; if nil, English suffixes are used.
func formatDuration(t func(string) string, d time.Duration) string {
	lookup := func(key, fallback string) string {
		if t != nil {
			if v := t(key); v != key && v != "" {
				return v
			}
		}
		return fallback
	}
	if d <= 0 {
		return "0s"
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	hSuffix := lookup("hour_abbr", "h")
	mSuffix := lookup("minute_abbr", "m")
	if h > 0 && m > 0 {
		return fmt.Sprintf("%d%s %d%s", h, hSuffix, m, mSuffix)
	}
	if h > 0 {
		return fmt.Sprintf("%d%s", h, hSuffix)
	}
	if m > 0 {
		return fmt.Sprintf("%d%s", m, mSuffix)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}
