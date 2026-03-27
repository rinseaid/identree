package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/oauth2"

	"github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/pocketid"
	"github.com/rinseaid/identree/internal/sudorules"
)

var serverStartTime = time.Now()

const escrowTimeout = 30 * time.Second
const escrowMaxOutput = 1 << 20 // 1 MB
const maxRequestBodySize = 1024

var escrowSemaphore = make(chan struct{}, 5)

const oidcDiscoveryTimeout = 30 * time.Second

// Server is the identree auth server.
// It bridges PAM challenges to the OIDC provider, serves the admin UI,
// and exposes a webhook endpoint for real-time directory invalidation.
type Server struct {
	cfg          *config.ServerConfig
	store        *challenge.ChallengeStore
	hostRegistry *HostRegistry
	oidcConfig   oauth2.Config
	verifier     *oidc.IDTokenVerifier
	mux          *http.ServeMux
	notifyWg     sync.WaitGroup

	sessionNonces  map[string]time.Time
	sessionNonceMu sync.Mutex

	sseClients map[string][]chan string
	sseMu      sync.Mutex

	pocketIDClient *pocketid.PocketIDClient

	// sudoRules is non-nil in bridge mode (APIKey == "").
	sudoRules *sudorules.Store

	// LDAP refresh channel — send a value to trigger an immediate reload.
	// Buffered so a webhook can fire without blocking the HTTP handler.
	ldapRefreshCh chan struct{}

	// Auto-deploy
	deployJobs map[string]*deployJob
	deployMu   sync.Mutex
	deployRL   *deployRateLimiter
}

var validUsername = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)
var validHostname = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,253}$`)

func NewServer(cfg *config.ServerConfig, store *sudorules.Store) (*Server, error) {
	discoveryClient := &http.Client{
		Timeout: oidcDiscoveryTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), oidcDiscoveryTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, discoveryClient)

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}

	oidcConfig := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  strings.TrimRight(cfg.ExternalURL, "/") + "/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	s := &Server{
		cfg:           cfg,
		store:         challenge.NewChallengeStore(cfg.ChallengeTTL, cfg.GracePeriod, cfg.SessionStateFile),
		hostRegistry:  NewHostRegistry(cfg.HostRegistryFile),
		oidcConfig:    oidcConfig,
		verifier:      provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		mux:           http.NewServeMux(),
		sessionNonces: make(map[string]time.Time),
		sseClients:    make(map[string][]chan string),
		deployJobs:    make(map[string]*deployJob),
		deployRL:      newDeployRateLimiter(),
		ldapRefreshCh:  make(chan struct{}, 1),
		pocketIDClient: pocketid.NewPocketIDClient(cfg.APIURL, cfg.APIKey),
		sudoRules:      store,
	}

	s.registerRoutes()
	return s, nil
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

	// Break-glass escrow
	s.mux.HandleFunc("/api/breakglass/escrow", s.handleBreakglassEscrow)

	// Session management
	s.mux.HandleFunc("/api/sessions/revoke", s.handleRevokeSession)
	s.mux.HandleFunc("/api/sessions/revoke-all", s.handleRevokeAll)
	s.mux.HandleFunc("/api/sessions/extend", s.handleExtendSession)
	s.mux.HandleFunc("/api/sessions/extend-all", s.handleExtendAll)

	// History
	s.mux.HandleFunc("/api/history/export", s.handleHistoryExport)

	// SSE
	s.mux.HandleFunc("/api/events", s.handleSSEEvents)

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
	s.mux.HandleFunc("/admin/users", s.handleAdminUsers)
	s.mux.HandleFunc("/admin/groups", s.handleAdminGroups)
	s.mux.HandleFunc("/admin/hosts", s.handleAdminHosts)
	s.mux.HandleFunc("/api/users/remove", s.handleRemoveUser)

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
	s.mux.Handle("/metrics", promhttp.Handler())
	s.mux.HandleFunc("/theme", s.handleThemeToggle)
	s.mux.HandleFunc("/signout", s.handleSignOut)
	s.mux.HandleFunc("/install.sh", s.handleInstallScript)

	// Deploy
	s.mux.HandleFunc("/api/deploy/users", s.handleDeployUsers)
	s.mux.HandleFunc("/api/deploy/pubkey", s.handleDeployPubkey)
	s.mux.HandleFunc("/api/deploy/stream/", s.handleDeployStream)
	s.mux.HandleFunc("/api/deploy", s.handleDeploy)

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
	}

	// Dashboard is the catch-all — must be registered last.
	s.mux.HandleFunc("/", s.handleDashboard)
}

// isBridgeMode returns true when running without a PocketID API key.
func (s *Server) isBridgeMode() bool {
	return s.cfg.APIKey == ""
}

// Stop cleanly shuts down background resources.
func (s *Server) Stop() {
	s.store.Stop()
}

// ServeHTTP implements http.Handler with security headers and panic recovery.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rv := recover(); rv != nil {
			slog.Error("panic in handler", "remote", remoteAddr(r), "value", rv)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}()

	nonce, err := randomHex(16)
	if err != nil {
		slog.Error("CSP nonce generation failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", fmt.Sprintf(
		"default-src 'self'; script-src 'nonce-%s'; style-src 'unsafe-inline'; img-src 'self' https:; frame-ancestors 'none'",
		nonce,
	))
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	if s.cfg.ExternalURL != "" && strings.HasPrefix(s.cfg.ExternalURL, "https://") {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}

	ctx := context.WithValue(r.Context(), ctxKeyCSPNonce, nonce)
	s.mux.ServeHTTP(w, r.WithContext(ctx))
}

// ctxKeyCSPNonce is the context key for the per-request CSP nonce.
type ctxKeyType string

const ctxKeyCSPNonce ctxKeyType = "csp-nonce"

// ── Webhook receiver ──────────────────────────────────────────────────────────

// handlePocketIDWebhook receives webhook events from PocketID (user/group changes)
// and triggers an immediate LDAP directory refresh.
func (s *Server) handlePocketIDWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// If a webhook secret is configured, validate the signature.
	// PocketID signs requests with HMAC-SHA256 in the X-Webhook-Signature header.
	if s.cfg.WebhookSecret != "" {
		sig := r.Header.Get("X-Webhook-Signature")
		if !verifyWebhookSignature(r, s.cfg.WebhookSecret, sig) {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
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
