package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/oauth2"

	"github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/escrow"
	"github.com/rinseaid/identree/internal/pocketid"
	"github.com/rinseaid/identree/internal/randutil"
	"github.com/rinseaid/identree/internal/sudorules"
)

var serverStartTime = time.Now()

// serverHealthzState holds the cached health-check results for the filesystem
// and external connectivity probes. Embedding in Server promotes all fields.
type serverHealthzState struct {
	healthzMu      sync.Mutex
	healthzLast    time.Time
	healthzStateOK bool

	healthzConnMu     sync.Mutex
	healthzConnLast   time.Time
	healthzPocketIDOK bool
	healthzOIDCOK     bool
}

// serverLDAPErrorState holds the most recent LDAP refresh failure.
// Embedding in Server promotes all fields.
type serverLDAPErrorState struct {
	ldapLastError   error
	ldapLastErrorAt time.Time
	ldapLastErrorMu sync.Mutex
}

// sessionNonceData holds state for an in-flight OIDC login.
type sessionNonceData struct {
	issuedAt     time.Time
	codeVerifier string // PKCE code verifier; empty for legacy sessions
	clientIP     string // client IP at login initiation for state binding
}

// revokedNoncesRetentionDur is how long we keep revoked nonces before pruning.
// Must exceed sessionCookieTTL (30 min) to cover cookies near their expiry.
const revokedNoncesRetentionDur = 35 * time.Minute

const escrowTimeout = 30 * time.Second
const escrowMaxOutput = 1 << 20 // 1 MB
const maxRequestBodySize = 1024

const oidcDiscoveryTimeout = 30 * time.Second

// Server is the identree auth server.
// It bridges PAM challenges to the OIDC provider, serves the admin UI,
// and exposes a webhook endpoint for real-time directory invalidation.
type Server struct {
	cfg    *config.ServerConfig
	cfgMu  sync.RWMutex // protects concurrent reads/writes of cfg slice fields during live updates
	baseURL      string // cfg.ExternalURL with trailing slashes stripped; precomputed once
	store        *challenge.ChallengeStore
	hostRegistry *HostRegistry
	oidcConfig   oauth2.Config
	verifier     *oidc.IDTokenVerifier
	mux          *http.ServeMux
	notifyWg     sync.WaitGroup
	notifyMu     sync.Mutex // guards notifyShutdown + notifyWg.Add to prevent TOCTOU

	sessionNonces  map[string]sessionNonceData
	sessionNonceMu sync.Mutex

	sseClients map[string][]chan string
	sseMu      sync.RWMutex

	// ldapLastSync tracks the last successful LDAP refresh time for healthz.
	ldapLastSync   time.Time
	ldapLastSyncMu sync.RWMutex

	pocketIDClient *pocketid.PocketIDClient

	// escrowSemaphore limits concurrent escrow operations.
	escrowSemaphore chan struct{}

	// escrowKey is the 32-byte AES key for the local escrow backend.
	// Only set when EscrowBackend == "local".
	escrowKey []byte

	// sudoRules is non-nil in bridge mode (APIKey == "").
	sudoRules *sudorules.Store

	// LDAP refresh channel — send a value to trigger an immediate reload.
	// Buffered so a webhook can fire without blocking the HTTP handler.
	ldapRefreshCh chan struct{}

	// Auto-deploy
	deployJobs map[string]*deployJob
	deployMu   sync.Mutex
	deployRL   *deployRateLimiter
	loginRL    *loginRateLimiter
	approveRL  *loginRateLimiter  // per-IP limit on /approve/{code}
	callbackRL *loginRateLimiter  // per-IP limit on /callback (OIDC callback)
	authFailRL *authFailTracker   // per-IP auth-failure backoff on /api/challenge

	// healthz and ldap error state are in embedded structs for field-count reduction.
	serverHealthzState
	serverLDAPErrorState

	// ldapBound is set to true once the LDAP listener goroutine has started.
	// It is never reset to false (a stopped listener causes the process to exit).
	ldapBound atomic.Bool

	// notifyShutdown is set to true (under notifyMu) before WaitForNotifications
	// calls notifyWg.Wait(). sendNotification and sendEventNotification hold
	// notifyMu while checking this flag and calling notifyWg.Add(1) to prevent
	// a TOCTOU panic from Add-after-Wait.
	notifyShutdown atomic.Bool

	// stopCh is closed by Stop() to cancel background goroutines.
	stopCh chan struct{}

	// Recently-removed users: excluded from PocketID merge until cleared.
	removedUsers   map[string]time.Time
	removedUsersMu sync.Mutex

	// oidcHTTPClient is the HTTP client used for OIDC discovery and token exchange.
	// When OIDCInsecureSkipVerify is set it uses InsecureSkipVerify (test only).
	oidcHTTPClient *http.Client

	// webhookClient is the hardened HTTP client for outbound notifications.
	// Initialised in NewServer with the configured NotifyTimeout.
	webhookClient *http.Client

	// hashedAPIKeys and hashedMetricsToken are pre-computed at startup to avoid
	// re-hashing on every request in verifyAPIKey / handleMetrics.
	hashedAPIKeys      [][]byte
	hashedMetricsToken [sha256.Size]byte

	// revokedNonces tracks nonces of server-side-revoked session cookies.
	// Entries are keyed by nonce and hold the revocation time; they are pruned
	// once sessionCookieTTL has elapsed (the cookie would have expired anyway).
	revokedNonces   map[string]time.Time
	revokedNoncesMu sync.Mutex

	// revokedAdminSessions maps username → time.Time of the most recent admin
	// role revocation. getSessionRole() uses this to downgrade "admin" cookies
	// that were issued before the revocation time. Entries are pruned
	// periodically once sessionCookieTTL has elapsed.
	revokedAdminSessions sync.Map

	// prevAdminUsernames holds the set of usernames that were members of an
	// AdminGroups-matching group as of the last successful directory refresh or
	// live config update.  Protected by cfgMu.
	prevAdminUsernames map[string]bool
}

var validUsername = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)
var validHostname = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,253}$`)

func NewServer(cfg *config.ServerConfig, store *sudorules.Store) (*Server, error) {
	var oidcConfig oauth2.Config
	var verifier *oidc.IDTokenVerifier

	oidcTransport := http.DefaultTransport
	if cfg.OIDCInsecureSkipVerify {
		if strings.HasPrefix(cfg.ExternalURL, "https://") {
			slog.Error("SECURITY IDENTREE_OIDC_INSECURE_SKIP_VERIFY=true on an HTTPS deployment — TLS certificate verification is disabled; this must not be used in production")
		}
		oidcTransport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test environments with self-signed certs only
		}
	}
	// When IssuerPublicURL is set, the OIDC discovery document advertises all
	// endpoints (token, JWKS, etc.) using the public hostname. Server-side calls
	// (token exchange, JWKS key fetches) must use the internal hostname instead.
	// Wrap the transport to transparently rewrite public→internal on outgoing requests.
	if cfg.IssuerPublicURL != "" && cfg.IssuerURL != "" {
		pub, perr := url.Parse(cfg.IssuerPublicURL)
		internal, ierr := url.Parse(cfg.IssuerURL)
		if perr == nil && ierr == nil && pub.Host != internal.Host {
			oidcTransport = &rewriteHostTransport{
				wrapped:      oidcTransport,
				fromHost:     pub.Host,
				fromScheme:   pub.Scheme,
				toHost:       internal.Host,
				toScheme:     internal.Scheme,
			}
		}
	}
	oidcHTTPClient := &http.Client{
		Timeout:   oidcExchangeTimeout,
		Transport: oidcTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if cfg.IssuerURL != "" && cfg.ClientID != "" {
		if cfg.IssuerPublicURL != "" {
			slog.Warn("InsecureIssuerURLContext: OIDC issuer URL mismatch validation is DISABLED — ID token issuer claim will not be verified against configured IssuerURL; only use IssuerPublicURL in controlled split-routing environments")
		}

		discoveryClient := &http.Client{
			Timeout:   oidcDiscoveryTimeout,
			Transport: oidcTransport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		// H5: retry OIDC discovery up to 5 times with exponential backoff (2, 4, 8, 16, 32 s).
		oidcRetryDelays := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second}
		var provider *oidc.Provider
		for attempt := 0; attempt <= len(oidcRetryDelays); attempt++ {
			if attempt > 0 {
				delay := oidcRetryDelays[attempt-1]
				slog.Info("OIDC discovery failed, retrying", "attempt", attempt, "delay", delay)
				time.Sleep(delay)
			}
			ctx, cancel := context.WithTimeout(context.Background(), oidcDiscoveryTimeout)
			ctx = context.WithValue(ctx, oauth2.HTTPClient, discoveryClient)

			// When IssuerPublicURL is set, PocketID's APP_URL (and thus OIDC issuer) is
			// the public hostname (e.g. localhost) while IssuerURL is the internal Docker
			// hostname used for network reachability. Tell go-oidc to accept the public
			// issuer in tokens while still fetching discovery from the internal URL.
			if cfg.IssuerPublicURL != "" {
				ctx = oidc.InsecureIssuerURLContext(ctx, cfg.IssuerPublicURL)
			}
			var err error
			provider, err = oidc.NewProvider(ctx, cfg.IssuerURL)
			cancel()
			if err == nil {
				break
			}
			if attempt == len(oidcRetryDelays) {
				return nil, fmt.Errorf("OIDC discovery: %w", err)
			}
			slog.Warn("OIDC discovery attempt failed", "attempt", attempt+1, "err", err)
		}

		endpoint := provider.Endpoint()
		// When IssuerPublicURL is set, PocketID's discovery document advertises
		// its token endpoint using the public hostname (e.g. localhost:1411).
		// The server-side token exchange must reach PocketID via the internal
		// Docker hostname instead, so rewrite the token URL back to IssuerURL.
		if cfg.IssuerPublicURL != "" {
			if pub, perr := url.Parse(cfg.IssuerPublicURL); perr == nil {
				if internal, ierr := url.Parse(cfg.IssuerURL); ierr == nil {
					if tok, terr := url.Parse(endpoint.TokenURL); terr == nil && tok.Host == pub.Host {
						tok.Scheme = internal.Scheme
						tok.Host = internal.Host
						endpoint.TokenURL = tok.String()
					}
				}
			}
		}
		oidcConfig = oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     endpoint,
			RedirectURL:  strings.TrimRight(cfg.ExternalURL, "/") + "/callback",
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
		}
		verifier = provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	}

	s := &Server{
		cfg:           cfg,
		baseURL:       strings.TrimRight(cfg.ExternalURL, "/"),
		store:         challenge.NewChallengeStore(cfg.ChallengeTTL, cfg.GracePeriod, cfg.SessionStateFile),
		hostRegistry:  NewHostRegistry(cfg.HostRegistryFile),
		oidcConfig:    oidcConfig,
		verifier:      verifier,
		mux:           http.NewServeMux(),
		sessionNonces: make(map[string]sessionNonceData),
		sseClients:    make(map[string][]chan string),
		deployJobs:    make(map[string]*deployJob),
		deployRL:      newDeployRateLimiter(),
		loginRL:       newLoginRateLimiter(),
		approveRL:     newLoginRateLimiter(),
		callbackRL:    newLoginRateLimiter(),
		authFailRL:    newAuthFailTracker(),
		removedUsers:       make(map[string]time.Time),
		revokedNonces:      make(map[string]time.Time),
		prevAdminUsernames: make(map[string]bool),
		escrowSemaphore: make(chan struct{}, 5),
		ldapRefreshCh:  make(chan struct{}, 1),
		stopCh:         make(chan struct{}),
		oidcHTTPClient: oidcHTTPClient,
		pocketIDClient: pocketid.NewPocketIDClient(cfg.APIURL, cfg.APIKey),
		sudoRules:      store,
		webhookClient: &http.Client{
			Timeout:   cfg.NotifyTimeout,
			Transport: &http.Transport{Proxy: nil},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	// Pre-hash API keys and the metrics token at startup.
	for _, key := range cfg.APIKeys {
		h := hmac.New(sha256.New, []byte("api-key-verification"))
		h.Write([]byte(key))
		s.hashedAPIKeys = append(s.hashedAPIKeys, h.Sum(nil))
	}
	if cfg.MetricsToken != "" {
		s.hashedMetricsToken = sha256.Sum256([]byte(cfg.MetricsToken))
	}

	if cfg.EscrowBackend == config.EscrowBackendLocal {
		if cfg.EscrowEncryptionKey == "" {
			return nil, fmt.Errorf("IDENTREE_ESCROW_ENCRYPTION_KEY must be set when using the local escrow backend")
		}
		// Decode the configured HKDF salt, or fall back to the legacy static salt.
		// Warn operators who have not configured a deployment-specific salt, since
		// all deployments sharing the same EscrowEncryptionKey would otherwise derive
		// identical subkeys.
		var hkdfSalt []byte
		if cfg.EscrowHKDFSalt != "" {
			var err error
			hkdfSalt, err = hex.DecodeString(cfg.EscrowHKDFSalt)
			if err != nil {
				return nil, fmt.Errorf("decoding IDENTREE_ESCROW_HKDF_SALT: %w", err)
			}
		} else {
			slog.Warn("IDENTREE_ESCROW_HKDF_SALT is not set — using static legacy salt; set a random hex salt for cross-deployment key diversification")
		}
		key, err := escrow.DeriveEscrowKey(cfg.EscrowEncryptionKey, hkdfSalt)
		if err != nil {
			return nil, fmt.Errorf("deriving escrow encryption key: %w", err)
		}
		s.escrowKey = key
	}

	if cfg.WebhookSecret == "" {
		slog.Error("IDENTREE_WEBHOOK_SECRET is not set — incoming PocketID webhooks are unauthenticated; this is a DoS vector in production")
	}

	// Periodically prune revokedNonces entries that have outlived revokedNoncesRetentionDur.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cutoff := time.Now().Add(-revokedNoncesRetentionDur)

				s.revokedNoncesMu.Lock()
				for nonce, revokedAt := range s.revokedNonces {
					if revokedAt.Before(cutoff) {
						delete(s.revokedNonces, nonce)
					}
				}
				s.revokedNoncesMu.Unlock()

				// Prune revokedAdminSessions entries older than revokedNoncesRetentionDur.
				// Any cookie issued before that point has already expired naturally.
				s.revokedAdminSessions.Range(func(k, v any) bool {
					if revokedAt, ok := v.(time.Time); ok && revokedAt.Before(cutoff) {
						s.revokedAdminSessions.Delete(k)
					}
					return true
				})

			case <-s.stopCh:
				return
			}
		}
	}()

	// Periodically prune sessionNonces entries older than 15 minutes.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cutoff := time.Now().Add(-15 * time.Minute)
				s.sessionNonceMu.Lock()
				for nonce, data := range s.sessionNonces {
					if data.issuedAt.Before(cutoff) {
						delete(s.sessionNonces, nonce)
					}
				}
				s.sessionNonceMu.Unlock()
			case <-s.stopCh:
				return
			}
		}
	}()

	s.registerRoutes()
	return s, nil
}

// pocketIDSyncAge returns a human-readable string describing how long ago the
// PocketID user cache was last successfully refreshed, or "" in bridge mode.
func (s *Server) pocketIDSyncAge() string {
	if s.isBridgeMode() {
		return ""
	}
	exp := s.pocketIDClient.AdminUsersCacheExpiry()
	if exp.IsZero() {
		return "never"
	}
	// cacheTTL is 5 minutes; subtract it from expiry to get the last-refresh time.
	const pocketIDCacheTTL = 5 * time.Minute
	lastRefresh := exp.Add(-pocketIDCacheTTL)
	return formatDuration(nil, time.Since(lastRefresh)) + " ago"
}

// ldapSyncError returns a non-empty error string if the last LDAP refresh
// failed, formatted with timestamp. Returns "" when LDAP is healthy.
func (s *Server) ldapSyncError() string {
	s.ldapLastErrorMu.Lock()
	defer s.ldapLastErrorMu.Unlock()
	if s.ldapLastError == nil {
		return ""
	}
	return fmt.Sprintf("%s (at %s)", s.ldapLastError.Error(), s.ldapLastErrorAt.Format("15:04:05"))
}

// updateAdminRevocations compares newAdminUsernames against the previously-known
// admin set (s.prevAdminUsernames) and records a revocation timestamp for any
// username that has been removed. It also updates s.prevAdminUsernames.
//
// Callers MUST hold s.cfgMu (write lock) before calling this method because
// both prevAdminUsernames and AdminGroups are protected by that mutex.
func (s *Server) updateAdminRevocations(newAdminUsernames map[string]bool) {
	now := time.Now()
	for username := range s.prevAdminUsernames {
		if !newAdminUsernames[username] {
			s.revokedAdminSessions.Store(username, now)
			s.store.PersistRevokedAdminSession(username, now)
			slog.Info("admin role revoked for user removed from admin groups", "user", username)
		}
	}
	s.prevAdminUsernames = newAdminUsernames
}

// adminUsernamesFromDirectory returns the set of usernames that belong to at
// least one group whose name matches an entry in adminGroups.
// adminGroups must be a snapshot taken under cfgMu.
func adminUsernamesFromDirectory(dir *pocketid.UserDirectory, adminGroups []string) map[string]bool {
	if dir == nil || len(adminGroups) == 0 {
		return map[string]bool{}
	}
	adminGroupSet := make(map[string]bool, len(adminGroups))
	for _, g := range adminGroups {
		adminGroupSet[g] = true
	}
	result := make(map[string]bool)
	for i := range dir.Groups {
		g := &dir.Groups[i]
		if !adminGroupSet[g.Name] {
			continue
		}
		for _, m := range g.Members {
			if u, ok := dir.ByUserID[m.ID]; ok && u.Username != "" {
				result[u.Username] = true
			}
		}
	}
	return result
}

// removedUsersSnapshot returns a snapshot of recently-removed usernames for use
// as an LDAP refresh exclusion list. Entries older than 1 hour are pruned.
func (s *Server) removedUsersSnapshot() map[string]bool {
	s.removedUsersMu.Lock()
	defer s.removedUsersMu.Unlock()
	cutoff := time.Now().Add(-time.Hour)
	for u, t := range s.removedUsers {
		if t.Before(cutoff) {
			delete(s.removedUsers, u)
		}
	}
	out := make(map[string]bool, len(s.removedUsers))
	for u := range s.removedUsers {
		out[u] = true
	}
	return out
}

func (s *Server) registerRoutes() {
	// Challenge / PAM flow
	s.mux.HandleFunc("/api/challenge", s.handleCreateChallenge)
	s.mux.HandleFunc("/api/challenge/", s.handlePollChallenge)
	s.mux.HandleFunc("/api/challenges/approve", s.handleBulkApprove)
	s.mux.HandleFunc("/api/challenges/approve-all", s.handleBulkApproveAll)
	s.mux.HandleFunc("/api/challenges/reject", s.handleRejectChallenge)
	s.mux.HandleFunc("/api/challenges/reject-all", s.handleRejectAll)
	s.mux.HandleFunc("/api/grace-status", s.handleGraceStatus)
	s.mux.HandleFunc("/api/client/provision", s.handleClientProvision)

	// Break-glass escrow
	s.mux.HandleFunc("/api/breakglass/escrow", s.handleBreakglassEscrow)
	s.mux.HandleFunc("/api/breakglass/reveal", s.handleBreakglassReveal)

	// Session management
	s.mux.HandleFunc("/api/sessions/revoke", s.handleRevokeSession)
	s.mux.HandleFunc("/api/sessions/revoke-all", s.handleRevokeAll)
	s.mux.HandleFunc("/api/sessions/extend", s.handleExtendSession)
	s.mux.HandleFunc("/api/sessions/extend-all", s.handleExtendAll)

	// History
	s.mux.HandleFunc("/api/history/export", s.handleHistoryExport)

	// SSE
	s.mux.HandleFunc("/api/events", s.handleSSEEvents)

	// Avatar proxy — fetches avatar images server-side to eliminate DNS-rebinding TOCTOU
	s.mux.HandleFunc("/api/avatar", s.handleAvatarProxy)

	// Access page
	s.mux.HandleFunc("/access", s.handleAccess)

	// OIDC flow
	s.mux.HandleFunc("/approve/", s.handleApprovalPage)
	s.mux.HandleFunc("/callback", s.handleOIDCCallback)
	s.mux.HandleFunc("/sessions", s.handleSessionsRedirect)
	s.mux.HandleFunc("/sessions/login", s.handleSessionsLogin)
	s.mux.HandleFunc("/api/onetap/", s.handleOneTap)

	// Admin UI
	s.mux.HandleFunc("/history", s.handleHistoryPage)
	s.mux.HandleFunc("/admin/history", s.handleHistoryPage)
	s.mux.HandleFunc("/admin", s.handleAdmin)
	s.mux.HandleFunc("/admin/info", s.handleAdminInfo)
	s.mux.HandleFunc("/admin/config", s.handleAdminConfig)
	s.mux.HandleFunc("/admin/users", s.handleAdminUsers)
	s.mux.HandleFunc("/admin/groups", s.handleAdminGroups)
	s.mux.HandleFunc("/admin/hosts", s.handleAdminHosts)
	s.mux.HandleFunc("/api/users/remove", s.handleRemoveUser)
	s.mux.HandleFunc("/api/admin/groups/claims", s.handleUpdateGroupClaims)
	s.mux.HandleFunc("/api/admin/users/claims", s.handleUpdateUserClaims)
	s.mux.HandleFunc("/api/admin/users/claims-json", s.handleGetUserClaims)
	s.mux.HandleFunc("/api/admin/restart", s.handleAdminRestart)
	s.mux.HandleFunc("/api/admin/test-notification", s.handleAdminTestNotification)

	// Sudo rules (bridge mode only)
	s.mux.HandleFunc("/admin/sudo-rules", s.handleAdminSudoRules)
	s.mux.HandleFunc("/api/sudo-rules/add", s.handleSudoRuleAdd)
	s.mux.HandleFunc("/api/sudo-rules/update", s.handleSudoRuleUpdate)
	s.mux.HandleFunc("/api/sudo-rules/delete", s.handleSudoRuleDelete)

	// Host management
	s.mux.HandleFunc("/api/hosts/elevate", s.handleElevate)
	s.mux.HandleFunc("/api/hosts/rotate", s.handleRotateHost)
	s.mux.HandleFunc("/api/hosts/rotate-all", s.handleRotateAllHosts)

	// Webhook receiver: PocketID → identree for real-time directory refresh
	s.mux.HandleFunc("/api/webhook/pocketid", s.handlePocketIDWebhook)

	// Misc
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/metrics", s.handleMetrics)
	s.mux.HandleFunc("/theme", s.handleThemeToggle)
	s.mux.HandleFunc("/signout", s.handleSignOut)
	s.mux.HandleFunc("/install.sh", s.handleInstallScript)

	// Self-hosted binary distribution
	s.mux.HandleFunc("/download/version", s.handleDownloadVersion)
	s.mux.HandleFunc("/download/identree-linux-amd64", s.handleDownloadBinary)
	s.mux.HandleFunc("/download/identree-linux-arm64", s.handleDownloadBinary)
	s.mux.HandleFunc("/download/identree-linux-amd64.sha256", s.handleDownloadBinaryChecksum)
	s.mux.HandleFunc("/download/identree-linux-arm64.sha256", s.handleDownloadBinaryChecksum)
	s.mux.HandleFunc("/download/systemd/", s.handleDownloadSystemd)

	// Deploy
	s.mux.HandleFunc("/api/deploy/users", s.handleDeployUsers)
	s.mux.HandleFunc("/api/deploy/pubkey", s.handleDeployPubkey)
	s.mux.HandleFunc("/api/deploy/uninstall-script", s.handleUninstallScript)
	s.mux.HandleFunc("/api/deploy/stream/", s.handleDeployStream)
	s.mux.HandleFunc("/api/deploy", s.handleDeploy)
	s.mux.HandleFunc("/api/hosts/remove-host", s.handleRemoveHost)
	s.mux.HandleFunc("/api/deploy/remove", s.handleRemoveDeploy)

	// Legacy redirects
	s.mux.HandleFunc("/hosts", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/hosts", http.StatusMovedPermanently)
	})
	s.mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/info", http.StatusMovedPermanently)
	})

	// Dev login bypass (IDENTREE_DEV_LOGIN=true only — never for production).
	if s.cfg.DevLoginEnabled {
		s.mux.HandleFunc("/dev/login", s.handleDevLogin)
		s.mux.HandleFunc("/dev/seed-session", s.handleDevSeedSession)
		s.mux.HandleFunc("/dev/seed-history", s.handleDevSeedHistory)
	}

	// Dashboard is the catch-all — must be registered last.
	s.mux.HandleFunc("/", s.handleDashboard)
}

// handleMetrics serves Prometheus metrics, optionally protected by a bearer token.
// When MetricsToken is empty, metrics are served unauthenticated (compatible with
// Prometheus scrapers that don't support authentication).
// When MetricsToken is set, the request must include "Authorization: Bearer <token>"
// or "?token=<token>" query parameter.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.cfg.MetricsToken != "" {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		tokenHash := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(tokenHash[:], s.hashedMetricsToken[:]) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	promhttp.Handler().ServeHTTP(w, r)
}

// isBridgeMode returns true when running without a PocketID API key.
func (s *Server) isBridgeMode() bool {
	return s.cfg.APIKey == ""
}

// isUserDisabled returns true if the named user is marked disabled in the
// PocketID directory cache. Returns false in bridge mode (no remote directory),
// and false on cache errors (fail open to avoid blocking approvals on transient
// PocketID outages).
func (s *Server) isUserDisabled(username string) bool {
	if s.isBridgeMode() {
		return false
	}
	users, err := s.pocketIDClient.CachedAdminUsers()
	if err != nil {
		slog.Warn("isUserDisabled: failed to fetch user cache, failing open", "err", err)
		return false
	}
	for i := range users {
		if users[i].Username == username {
			return users[i].Disabled
		}
	}
	return false
}

// hmacBase returns HMACSecret when set, falling back to SharedSecret.
// All HMAC signing (session, CSRF, onetap, approval_status) must use this so
// that operators can rotate HMAC keys independently from the PAM shared secret.
func (s *Server) hmacBase() string {
	if s.cfg.HMACSecret != "" {
		return s.cfg.HMACSecret
	}
	return s.cfg.SharedSecret
}

// buildDisabledMap returns a set of disabled usernames for O(1) batch lookup.
// Returns nil in bridge mode or on cache errors (fail open).
func (s *Server) buildDisabledMap() map[string]bool {
	if s.isBridgeMode() {
		return nil
	}
	users, err := s.pocketIDClient.CachedAdminUsers()
	if err != nil {
		slog.Warn("buildDisabledMap: failed to fetch user cache, failing open", "err", err)
		return nil
	}
	m := make(map[string]bool, len(users))
	for i := range users {
		if users[i].Disabled {
			m[users[i].Username] = true
		}
	}
	return m
}

// Stop cleanly shuts down background resources.
func (s *Server) Stop() {
	close(s.stopCh)
	s.store.Stop()
}

// ServeHTTP implements http.Handler with security headers and panic recovery.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rv := recover(); rv != nil {
			buf := make([]byte, 64<<10)
			n := runtime.Stack(buf, false)
			slog.Error("panic in handler", "remote", remoteAddr(r), "method", r.Method, "path", r.URL.Path, "value", rv, "stack", string(buf[:n]))
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}()

	// Redirect HTTP→HTTPS when the server is behind a TLS-terminating proxy
	// that sets X-Forwarded-Proto: http on plain-HTTP requests.
	if strings.HasPrefix(s.cfg.ExternalURL, "https://") && r.Header.Get("X-Forwarded-Proto") == "http" {
		// Use the configured external host, not r.Host, to prevent host header injection.
		externalHost := strings.TrimPrefix(strings.TrimPrefix(s.cfg.ExternalURL, "https://"), "http://")
		if idx := strings.IndexByte(externalHost, '/'); idx != -1 {
			externalHost = externalHost[:idx]
		}
		target := "https://" + externalHost + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
		return
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
	w.Header().Set("Cache-Control", "no-store")
	if s.cfg.ExternalURL != "" && strings.HasPrefix(s.cfg.ExternalURL, "https://") {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}

	// Only HTML-rendering handlers need a CSP nonce. API endpoints never serve
	// HTML, so skip the crypto/rand call and use a restrictive no-nonce CSP.
	var ctx context.Context
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		ctx = r.Context()
	} else {
		nonce, err := randutil.Hex(16)
		if err != nil {
			slog.Error("CSP nonce generation failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Security-Policy", fmt.Sprintf(
			"default-src 'self'; script-src 'nonce-%s'; style-src 'unsafe-inline'; img-src 'self' https:; frame-ancestors 'none'",
			nonce,
		))
		ctx = context.WithValue(r.Context(), ctxKeyCSPNonce, nonce)
	}

	s.mux.ServeHTTP(w, r.WithContext(ctx))
}

// ctxKeyCSPNonce is the context key for the per-request CSP nonce.
type ctxKeyType string

const ctxKeyCSPNonce ctxKeyType = "csp-nonce"

// cspNonce retrieves the per-request CSP nonce from the context.
func cspNonce(r *http.Request) string {
	v, _ := r.Context().Value(ctxKeyCSPNonce).(string)
	return v
}

// ── Webhook receiver ──────────────────────────────────────────────────────────

// handlePocketIDWebhook receives webhook events from PocketID (user/group changes)
// and triggers an immediate LDAP directory refresh.
func (s *Server) handlePocketIDWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	// Webhook secret is required; reject requests when none is configured.
	// PocketID signs requests with HMAC-SHA256 in the X-Webhook-Signature header.
	if s.cfg.WebhookSecret == "" {
		http.Error(w, "webhook not configured", http.StatusForbidden)
		return
	}
	sig := r.Header.Get("X-Webhook-Signature")
	if !verifyWebhookSignature(r, s.cfg.WebhookSecret, sig) {
		slog.Warn("AUTH_FAILURE webhook signature mismatch", "remote_addr", remoteAddr(r))
		http.Error(w, "invalid signature", http.StatusForbidden)
		return
	}

	// Non-blocking send: if a refresh is already queued, drop the duplicate.
	select {
	case s.ldapRefreshCh <- struct{}{}:
		slog.Info("webhook: LDAP refresh queued")
	default:
		slog.Debug("webhook: refresh already queued, skipping")
	}

	w.WriteHeader(http.StatusNoContent)
}

// ── Utility ───────────────────────────────────────────────────────────────────

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// rewriteHostTransport rewrites outgoing requests whose host matches fromHost
// to use toHost instead. Used to redirect OIDC server-side calls (token exchange,
// JWKS fetches) from the public hostname back to the internal Docker hostname.
type rewriteHostTransport struct {
	wrapped    http.RoundTripper
	fromScheme string
	fromHost   string
	toScheme   string
	toHost     string
}

func (t *rewriteHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == t.fromHost && req.URL.Scheme == t.fromScheme {
		// Clone the request before mutating the URL.
		r2 := req.Clone(req.Context())
		r2.URL.Host = t.toHost
		r2.URL.Scheme = t.toScheme
		return t.wrapped.RoundTrip(r2)
	}
	return t.wrapped.RoundTrip(req)
}
