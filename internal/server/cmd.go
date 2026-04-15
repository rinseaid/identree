package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/rinseaid/identree/internal/breakglass"
	"github.com/rinseaid/identree/internal/config"
	ldapserver "github.com/rinseaid/identree/internal/ldap"
	"github.com/rinseaid/identree/internal/pam"
	"github.com/rinseaid/identree/internal/setup"
	"github.com/rinseaid/identree/internal/signing"
	"github.com/rinseaid/identree/internal/sudorules"
	"github.com/rinseaid/identree/internal/uidmap"
)

func init() {
	// Configure slog from IDENTREE_LOG_LEVEL (debug|info|warn|error, default: info).
	level := slog.LevelInfo
	v := strings.ToLower(os.Getenv("IDENTREE_LOG_LEVEL"))
	switch v {
	case "debug":
		level = slog.LevelDebug
	case "", "info":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		// Invalid value: keep info level and warn below after handler is set.
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	if v != "" && v != "debug" && v != "info" && v != "warn" && v != "warning" && v != "error" {
		slog.Warn("IDENTREE_LOG_LEVEL: unrecognised value, defaulting to info", "value", os.Getenv("IDENTREE_LOG_LEVEL"))
	}
}

// version and commit are set at build time:
//
//	-ldflags "-X github.com/rinseaid/identree/internal/server.version=v0.1.0 -X github.com/rinseaid/identree/internal/server.commit=abc12345"
var version = "dev"
var commit = ""

// safeUsername validates PAM_USER to prevent injection.
// Requires an alphanumeric or underscore first character to exclude ".", "..",
// and leading-dot names that would traverse or alias the token cache directory,
// while allowing underscore-prefixed system accounts (e.g. _apt, _www).
var safeUsername = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,63}$`)

func Main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-v", "version":
			if commit != "" {
				fmt.Printf("%s (%s)\n", version, commit)
			} else {
				fmt.Println(version)
			}
			os.Exit(0)
		case "--help", "-h", "help":
			printHelp()
			os.Exit(0)
		case "serve":
			runServer()
			return
		case "rotate-breakglass":
			runRotateBreakglass()
			return
		case "verify-breakglass":
			runVerifyBreakglass()
			return
		case "add-host":
			runAddHost()
			return
		case "remove-host":
			runRemoveHost()
			return
		case "list-hosts":
			runListHosts()
			return
		case "rotate-host-secret":
			runRotateHostSecret()
			return
		case "setup":
			runSetup()
			return
		case "renew-cert":
			runRenewCert()
			return
		case "verify-install":
			runVerifyInstall()
			return
		case "sign-script":
			runSignScript()
			return
		}
	}

	if len(os.Args) > 1 {
		known := map[string]bool{
			"--version": true, "-v": true, "version": true,
			"--help": true, "-h": true, "help": true,
			"serve": true,
			"rotate-breakglass": true, "verify-breakglass": true,
			"add-host": true, "remove-host": true, "list-hosts": true,
			"rotate-host-secret": true,
			"setup": true, "renew-cert": true,
			"verify-install": true, "sign-script": true,
		}
		if !strings.HasPrefix(os.Args[1], "-") && !known[os.Args[1]] {
			fmt.Fprintf(os.Stderr, "unknown command: %s\nRun 'identree --help' for usage.\n", os.Args[1])
			os.Exit(1)
		}
	}
	runPAMHelper()
}

func printHelp() {
	fmt.Printf("identree %s — OIDC identity bridge with embedded LDAP and PAM authentication\n\n", version)
	fmt.Print(`Server commands:
  identree serve                         Run the server (HTTP + LDAP)

PAM client commands (run on managed hosts):
  identree                               PAM authentication helper (called by pam_exec)
  identree rotate-breakglass [--force]   Rotate the break-glass password
  identree verify-breakglass             Verify a break-glass password

Host registry commands (run on the server):
  identree add-host <hostname>           Register a host
                   [--users user1,user2] Allow specific users (default: all)
                   [--group groupname]   Allow group members
  identree remove-host <hostname>        Unregister a host
  identree list-hosts                    List registered hosts
  identree rotate-host-secret <hostname> Rotate a host's shared secret

Setup commands (run on managed hosts as root):
  identree setup                         Configure PAM for identree authentication
            [--sssd]                     Also configure SSSD + nsswitch for LDAP identity
            [--auditd]                   Install auditd monitoring rules
            [--hostname <name>]          Override hostname (default: os.Hostname)
            [--force]                    Overwrite existing config files
            [--dry-run]                  Print changes without applying them
  identree renew-cert                    Renew mTLS client certificate from server
  identree verify-install                Verify install script signature
            --key <pubkey-path>          Path to Ed25519 public key PEM
            --script <script-path>       Path to downloaded install.sh
            --sig <sig-path>             Path to downloaded install.sh.sig
  identree sign-script                  Sign a script with Ed25519 private key
            --key <privkey-path>         Path to Ed25519 private key PEM
            --script <script-path>       Path to script to sign

Global flags:
  --version, -v                          Show version
  --help, -h                             Show this help

Config file locations:
  Server: /etc/identree/identree.conf
  Client: /etc/identree/client.conf
`)
}

// ── Server ────────────────────────────────────────────────────────────────────

func runServer() {
	cfg, err := config.LoadServerConfig()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	// Normalize ExternalURL: strip any trailing slashes so cfg.ExternalURL is
	// consistent wherever it is used (slog output, cookie Secure detection, etc.).
	cfg.ExternalURL = strings.TrimRight(cfg.ExternalURL, "/")

	// Clamp ClientPollInterval to a minimum of 1 second to prevent sub-second
	// polling hammering both the server and managed hosts.
	if cfg.ClientPollInterval > 0 && cfg.ClientPollInterval < time.Second {
		slog.Warn("IDENTREE_CLIENT_POLL_INTERVAL is sub-second; clamping to 1s", "value", cfg.ClientPollInterval)
		cfg.ClientPollInterval = time.Second
	}

	// Bridge mode: APIKey is empty — serve only ou=sudoers from local rules store.
	var rulesStore *sudorules.Store
	if cfg.APIKey == "" {
		rulesStore, err = sudorules.NewStore(cfg.SudoRulesFile)
		if err != nil {
			slog.Error("sudo rules store init error", "err", err)
			os.Exit(1)
		}
		slog.Info("bridge mode active — serving sudoers from local rules store",
			"path", cfg.SudoRulesFile)
	}

	srv, err := NewServer(cfg, rulesStore)
	if err != nil {
		slog.Error("server init error", "err", err)
		os.Exit(1)
	}

	// Restore revoked nonces and admin-session revocations from the persisted store.
	// This prevents signed-out session cookies from becoming valid again after a restart.
	for nonce, revokedAt := range srv.store.LoadRevokedNonces() {
		srv.revokedNoncesMu.Lock()
		srv.revokedNonces[nonce] = revokedAt
		srv.revokedNoncesMu.Unlock()
	}
	for username, revokedAt := range srv.store.LoadRevokedAdminSessions() {
		srv.revokedAdminSessions.Store(username, revokedAt)
	}

	// Clean up orphaned temp files from previous runs (atomic-write leftovers).
	// Derive the config directory from SessionStateFile (all state files share the same dir).
	if configDir := filepath.Dir(cfg.SessionStateFile); configDir != "" && configDir != "." {
		patterns := []string{
			".identree-*", ".sessions-tmp-*", ".hosts-tmp-*",
			".sudorules-tmp-*", ".notify-config-*", ".admin-notify-*",
		}
		var cleaned int
		for _, pat := range patterns {
			matches, _ := filepath.Glob(filepath.Join(configDir, pat))
			for _, m := range matches {
				if err := os.Remove(m); err == nil {
					cleaned++
				}
			}
		}
		if cleaned > 0 {
			slog.Info("cleaned orphaned temp files", "count", cleaned, "dir", configDir)
		}
	}

	slog.Info("identree server starting",
		"version", version,
		"listen", cfg.ListenAddr,
		"external_url", cfg.ExternalURL,
		"oidc_issuer", cfg.IssuerURL,
		"redirect_uri", strings.TrimRight(cfg.ExternalURL, "/")+"/callback",
		"challenge_ttl", cfg.ChallengeTTL,
	)
	if cfg.MTLSEnabled {
		slog.Info("mTLS client authentication enabled")
	}
	if cfg.GracePeriod > 0 {
		slog.Info("grace period enabled", "duration", cfg.GracePeriod)
	}
	if cfg.LDAPEnabled {
		slog.Info("LDAP server enabled",
			"listen", cfg.LDAPListenAddr,
			"base_dn", cfg.LDAPBaseDN,
			"refresh_interval", cfg.LDAPRefreshInterval,
		)
	} else {
		slog.Info("LDAP server is DISABLED — managed hosts cannot use LDAP/sudo; set IDENTREE_LDAP_ENABLED=true to enable")
	}
	if cfg.APIKey == "" {
		slog.Info("bridge mode rules loaded", "count", len(rulesStore.Rules()))
	}
	if len(cfg.AdminGroups) == 0 && !cfg.DevLoginEnabled {
		slog.Warn("IDENTREE_ADMIN_GROUPS is empty — admin UI will be inaccessible without IDENTREE_DEV_LOGIN")
	}
	if cfg.DevLoginEnabled && strings.HasPrefix(cfg.ExternalURL, "https://") {
		slog.Warn("IDENTREE_DEV_LOGIN is enabled but ExternalURL uses HTTPS — DevLogin bypasses OIDC and should NEVER be used in production")
	}

	// Validate IssuerPublicURL is a well-formed http/https URL if set.
	if cfg.IssuerPublicURL != "" {
		if u, err := url.Parse(cfg.IssuerPublicURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			slog.Error("IDENTREE_OIDC_ISSUER_PUBLIC_URL is not a valid http/https URL", "value", cfg.IssuerPublicURL)
			os.Exit(1)
		}
	}
	if cfg.SessionStateFile != "" {
		slog.Info("session persistence enabled", "path", cfg.SessionStateFile)
	} else {
		slog.Warn("IDENTREE_SESSION_STATE_FILE is not set — revokeTokensBefore and grace sessions will be lost on restart")
	}
	if cfg.HostRegistryFile != "" {
		count := len(srv.hostRegistry.RegisteredHosts())
		if count > 0 {
			slog.Info("host registry loaded", "path", cfg.HostRegistryFile, "hosts", count)
		} else {
			slog.Info("host registry empty — using global shared secret", "path", cfg.HostRegistryFile)
		}
	}
	// Notification config is loaded inside NewServer.

	// Start LDAP server if enabled.
	var ldapCancel context.CancelFunc
	var ldapRefreshDone chan struct{} // closed when the LDAP refresh goroutine exits
	if cfg.LDAPEnabled {
		um, err := uidmap.NewUIDMap(cfg.LDAPUIDMapFile, cfg.LDAPUIDBase, cfg.LDAPGIDBase)
		if err != nil {
			slog.Error("uid map load error", "err", err)
			os.Exit(1)
		}
		// When mTLS is enabled and we have a TLS server cert, configure LDAPS
		// with mutual TLS client certificate authentication.
		var ldapTLSCfg *ldapserver.LDAPTLSConfig
		if cfg.MTLSEnabled && srv.mtlsCACert != nil && cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			serverCert, tlsErr := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
			if tlsErr != nil {
				slog.Error("ldap: failed to load TLS server cert for LDAPS", "err", tlsErr)
				os.Exit(1)
			}
			ldapTLSCfg = &ldapserver.LDAPTLSConfig{
				ServerCert: serverCert,
				CACert:     srv.mtlsCACert,
				HostChecker: func(hostname string) bool {
					return srv.hostRegistry.HasHost(hostname)
				},
			}
			slog.Info("ldap: LDAPS/mTLS configured", "tls_listen", cfg.LDAPTLSListenAddr)
		}

		ldapSrv, err := ldapserver.NewLDAPServer(cfg, um, rulesStore, ldapTLSCfg)
		if err != nil {
			slog.Error("ldap server init error", "err", err)
			os.Exit(1)
		}

		// In full mode, seed the directory before opening the listener.
		if cfg.APIKey != "" {
			dir, ferr := srv.pocketIDClient.FetchDirectory()
			if ferr != nil {
				// Partial or failed fetch: do not load incomplete data into LDAP.
				// The periodic refresh goroutine will retry on the next interval.
				slog.Warn("ldap: initial directory fetch failed, skipping initial load (will retry)", "err", ferr)
			} else {
				ldapSrv.Refresh(dir, "poll", srv.removedUsersSnapshot())
				srv.ldapLastSyncMu.Lock()
				srv.ldapLastSync = time.Now()
				srv.ldapLastSyncMu.Unlock()
			}
		}

		var ldapCtx context.Context
		ldapCtx, ldapCancel = context.WithCancel(context.Background())

		// In bridge mode (no APIKey), mark the LDAP server as started so /healthz
		// reports healthy (bridge mode has no directory refresh cycle).
		if cfg.APIKey == "" {
			srv.ldapLastSyncMu.Lock()
			srv.ldapLastSync = time.Now()
			srv.ldapLastSyncMu.Unlock()
		}

		srv.ldapBound.Store(true)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					buf := make([]byte, 64<<10)
					n := runtime.Stack(buf, false)
					slog.Error("goroutine panicked", "panic", r, "stack", string(buf[:n]))
				}
			}()
			if lerr := ldapSrv.Start(ldapCtx); lerr != nil {
				slog.Error("ldap server stopped", "err", lerr)
				srv.ldapBound.Store(false)
			}
		}()

		// Full mode: periodic refresh + webhook-triggered refresh.
		if cfg.APIKey != "" {
			ldapRefreshDone = make(chan struct{})
			go func() {
				defer close(ldapRefreshDone)
				defer func() {
					if r := recover(); r != nil {
						buf := make([]byte, 64<<10)
						n := runtime.Stack(buf, false)
						slog.Error("goroutine panicked", "panic", r, "stack", string(buf[:n]))
					}
				}()
				ticker := time.NewTicker(cfg.LDAPRefreshInterval)
				defer ticker.Stop()

				var ldapConsecutiveFailures int
				// backoffTimer is used to delay the next poll attempt after failures.
				// It starts stopped (fired immediately so the first select hits ticker.C).
				backoffTimer := time.NewTimer(0)
				<-backoffTimer.C // drain the initial fire
				defer backoffTimer.Stop()
				backoffActive := false

				for {
					select {
					case <-ldapCtx.Done():
						return
					case <-backoffTimer.C:
						backoffActive = false
						// Retry after backoff: attempt a poll refresh.
						dir, ferr := srv.pocketIDClient.FetchDirectory()
						if ferr != nil {
							ldapConsecutiveFailures++
							backoff := time.Duration(1<<min(ldapConsecutiveFailures-1, 3)) * time.Minute
							if backoff > 5*time.Minute {
								backoff = 5 * time.Minute
							}
							ldapSyncFailures.Inc()
							slog.Warn("ldap: refresh failed, will retry with backoff", "err", ferr, "backoff", backoff, "consecutive_failures", ldapConsecutiveFailures)
							srv.ldapLastErrorMu.Lock()
							srv.ldapLastError = ferr
							srv.ldapLastErrorAt = time.Now()
							srv.ldapLastErrorMu.Unlock()
							backoffTimer.Reset(backoff)
							backoffActive = true
							continue
						}
						ldapConsecutiveFailures = 0
						ldapSrv.Refresh(dir, "poll", srv.removedUsersSnapshot())
						srv.ldapLastSyncMu.Lock()
						srv.ldapLastSync = time.Now()
						srv.ldapLastSyncMu.Unlock()
						srv.ldapLastErrorMu.Lock()
						srv.ldapLastError = nil
						srv.ldapLastErrorMu.Unlock()
						srv.cfgMu.Lock()
						srv.updateAdminRevocations(adminUsernamesFromDirectory(dir, srv.cfg.AdminGroups))
						srv.cfgMu.Unlock()
					case <-ticker.C:
						if backoffActive {
							// A backoff retry is pending — skip this tick to avoid
							// concurrent fetches while waiting for backoff to resolve.
							continue
						}
						dir, ferr := srv.pocketIDClient.FetchDirectory()
						if ferr != nil {
							ldapConsecutiveFailures++
							backoff := time.Duration(1<<min(ldapConsecutiveFailures-1, 3)) * time.Minute
							if backoff > 5*time.Minute {
								backoff = 5 * time.Minute
							}
							ldapSyncFailures.Inc()
							slog.Warn("ldap: refresh failed, will retry with backoff", "err", ferr, "backoff", backoff, "consecutive_failures", ldapConsecutiveFailures)
							srv.ldapLastErrorMu.Lock()
							srv.ldapLastError = ferr
							srv.ldapLastErrorAt = time.Now()
							srv.ldapLastErrorMu.Unlock()
							backoffTimer.Reset(backoff)
							backoffActive = true
							continue
						}
						ldapConsecutiveFailures = 0
						ldapSrv.Refresh(dir, "poll", srv.removedUsersSnapshot())
						srv.ldapLastSyncMu.Lock()
						srv.ldapLastSync = time.Now()
						srv.ldapLastSyncMu.Unlock()
						srv.ldapLastErrorMu.Lock()
						srv.ldapLastError = nil
						srv.ldapLastErrorMu.Unlock()
						srv.cfgMu.Lock()
						srv.updateAdminRevocations(adminUsernamesFromDirectory(dir, srv.cfg.AdminGroups))
						srv.cfgMu.Unlock()
					case <-srv.ldapRefreshCh:
						dir, ferr := srv.pocketIDClient.FetchDirectory()
						if ferr != nil {
							// Partial or failed fetch: keep stale directory in use rather
							// than refreshing with incomplete data. Retry on next trigger.
							ldapSyncFailures.Inc()
							srv.ldapLastSyncMu.RLock()
							staleFor := time.Since(srv.ldapLastSync).Round(time.Second)
							srv.ldapLastSyncMu.RUnlock()
							slog.Warn("ldap: webhook-triggered refresh failed, retaining previous directory", "err", ferr, "stale_for", staleFor)
							srv.ldapLastErrorMu.Lock()
							srv.ldapLastError = ferr
							srv.ldapLastErrorAt = time.Now()
							srv.ldapLastErrorMu.Unlock()
							continue
						}
						ldapConsecutiveFailures = 0
						backoffActive = false
						ldapSrv.Refresh(dir, "webhook", srv.removedUsersSnapshot())
						srv.ldapLastSyncMu.Lock()
						srv.ldapLastSync = time.Now()
						srv.ldapLastSyncMu.Unlock()
						srv.ldapLastErrorMu.Lock()
						srv.ldapLastError = nil
						srv.ldapLastErrorMu.Unlock()
						srv.cfgMu.Lock()
						srv.updateAdminRevocations(adminUsernamesFromDirectory(dir, srv.cfg.AdminGroups))
						srv.cfgMu.Unlock()
					}
				}
			}()
		}
	}

	// periodicFlushCtx is cancelled at graceful shutdown to stop the flush goroutine.
	periodicFlushCtx, periodicFlushCancel := context.WithCancel(context.Background())
	defer periodicFlushCancel()
	periodicFlushDone := make(chan struct{})

	// Periodically flush session state to disk to minimize data loss on crash.
	// Skip when using Redis — all state is already persisted.
	if cfg.StateBackend != "redis" {
		go func() {
			defer close(periodicFlushDone)
			defer func() {
				if r := recover(); r != nil {
					slog.Error("periodic flush panic recovered", "panic", r)
				}
			}()
			ticker := time.NewTicker(10 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					srv.store.SaveState()
					slog.Debug("periodic state flush completed")
				case <-periodicFlushCtx.Done():
					return
				}
			}
		}()
	} else {
		close(periodicFlushDone) // no goroutine to wait for
	}

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second, // SSE handler clears this per-connection
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8192,
	}

	// When TLS cert/key are configured, enable HTTPS with optional client cert
	// verification. RequestClientCert asks clients for a certificate but does
	// not require one — endpoints that need mTLS verify the cert themselves via
	// r.TLS.PeerCertificates. This allows the provision endpoint (shared-secret
	// auth) and web UI to work without a client cert on the same listener.
	useTLS := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
	if useTLS {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientAuth: tls.RequestClientCert,
		}
		// When mTLS is enabled, add the CA cert pool so Go can verify client
		// certs against our CA. We still use RequestClientCert (not
		// RequireAndVerifyClientCert) because not all endpoints need mTLS.
		if cfg.MTLSEnabled && srv.mtlsCACert != nil {
			pool := x509.NewCertPool()
			pool.AddCert(srv.mtlsCACert)
			tlsCfg.ClientCAs = pool
			tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
		httpServer.TLSConfig = tlsCfg
		slog.Info("TLS enabled", "cert", cfg.TLSCertFile, "key", cfg.TLSKeyFile)
	}

	shutdownDone := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				buf := make([]byte, 64<<10)
				n := runtime.Stack(buf, false)
				slog.Error("goroutine panicked", "panic", r, "stack", string(buf[:n]))
			}
		}()
		defer close(shutdownDone)
		sig := <-sigCh
		slog.Info("shutting down", "signal", sig)
		// Second signal forces immediate exit; cancelled when shutdown completes normally.
		shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-sigCh:
				slog.Info("forced exit")
				os.Exit(1)
			case <-shutdownCtx.Done():
				return
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			slog.Error("HTTP shutdown error", "err", err)
		}
		if ldapCancel != nil {
			ldapCancel()
		}
		// Wait for the LDAP refresh goroutine to exit before saving state so
		// that the final directory state is fully committed.
		if ldapRefreshDone != nil {
			select {
			case <-ldapRefreshDone:
			case <-time.After(30 * time.Second):
				slog.Error("ldap refresh goroutine did not stop within 30s — forced shutdown may cause data race; check for stuck network calls")
			}
		}
		srv.WaitForNotifications(45 * time.Second)
		periodicFlushCancel()
		select {
		case <-periodicFlushDone:
		case <-time.After(5 * time.Second):
			slog.Warn("periodic flush goroutine did not stop within 5s")
		}
		srv.store.SaveState()
		srv.Stop()
		shutdownCancel()
	}()

	var listenErr error
	if useTLS {
		listenErr = httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
	} else {
		listenErr = httpServer.ListenAndServe()
	}
	if listenErr != nil && listenErr != http.ErrServerClosed {
		slog.Error("server error", "err", listenErr)
		os.Exit(1)
	}
	<-shutdownDone
	slog.Info("server stopped")
}

// ── Break-glass ───────────────────────────────────────────────────────────────

func runRotateBreakglass() {
	force := false
	for _, arg := range os.Args[2:] {
		switch arg {
		case "--force", "-f":
			force = true
		default:
			fmt.Fprintf(os.Stderr, "unknown flag: %s\nusage: identree rotate-breakglass [--force]\n", arg)
			os.Exit(1)
		}
	}

	stripSensitiveEnv()

	cfg, err := config.LoadClientConfig(true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	plaintext, err := breakglass.RotateBreakglass(cfg, force, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if plaintext != "" {
		fmt.Fprintf(os.Stderr, "\n*** IMPORTANT: Break-glass password was NOT escrowed. Save it now! ***\n")
		fmt.Fprintln(os.Stdout, plaintext)
		fmt.Fprintf(os.Stderr, "*** Store this password securely. It will not be shown again. ***\n\n")
	}
}

func runVerifyBreakglass() {
	stripSensitiveEnv()

	cfg, err := config.LoadClientConfig(true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	hash, err := breakglass.ReadBreakglassHash(cfg.BreakglassFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	tty, err := breakglass.OpenTTY()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot open terminal: %v\n", err)
		os.Exit(1)
	}
	defer tty.Close()

	fmt.Fprintf(tty, "Break-glass password: ")
	password, err := breakglass.ReadPasswordFn(int(tty.Fd()))
	fmt.Fprintf(tty, "\n")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading password: %v\n", err)
		os.Exit(1)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), password); err != nil {
		fmt.Fprintln(os.Stderr, "Break-glass password does NOT match.")
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "Break-glass password verified successfully.")
}

// ── PAM helper ────────────────────────────────────────────────────────────────

func runPAMHelper() {
	pam.RequestParentDeathSignal()
	stripSensitiveEnv()

	username := os.Getenv("PAM_USER")
	if username == "" {
		fmt.Fprintln(os.Stderr, "PAM_USER not set (must be called via pam_exec)")
		os.Exit(1)
	}
	if !safeUsername.MatchString(username) {
		fmt.Fprintln(os.Stderr, "identree: invalid username format")
		os.Exit(1)
	}

	// Only handle auth; silently succeed for other PAM operations.
	if pamType := os.Getenv("PAM_TYPE"); pamType != "" && pamType != "auth" {
		os.Exit(0)
	}

	cfg, err := config.LoadClientConfig(false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "identree config error: %v\n", err)
		os.Exit(1)
	}

	// Resolve the hostname once here so it is consistent across the token
	// cache and the PAM client (both use it for cache paths and challenge
	// requests). Non-fatal: hostname is best-effort context.
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Fprintf(os.Stderr, "identree: os.Hostname() failed: %v\n", err)
	}

	var cache *pam.TokenCache
	if cfg.TokenCacheEnabled {
		var err error
		cache, err = pam.NewTokenCache(cfg.TokenCacheDir, cfg.TokenCacheIssuer, cfg.TokenCacheClientID, hostname)
		if err != nil {
			fmt.Fprintf(os.Stderr, "identree: %v\n", err)
			os.Exit(1)
		}
	}

	client, err := pam.NewPAMClient(cfg, cache, hostname)
	if err != nil {
		// Surface the error via the PAM conversation interface (MessageWriter →
		// pam_exec stdout → user's terminal) in addition to stderr, so that
		// misconfiguration (e.g. http:// ServerURL) is visible to the user.
		fmt.Fprintf(pam.MessageWriter, "  identree: %v\n", err)
		fmt.Fprintf(os.Stderr, "identree: %v\n", err)
		os.Exit(1)
	}
	if err := client.Authenticate(username); err != nil {
		fmt.Fprintf(os.Stderr, "identree: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// ── Host registry ─────────────────────────────────────────────────────────────

func runAddHost() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: identree add-host <hostname> [--users user1,user2] [--group groupname]")
		os.Exit(1)
	}
	hostname := os.Args[2]
	if !validHostname.MatchString(hostname) {
		fmt.Fprintln(os.Stderr, "invalid hostname format")
		os.Exit(1)
	}

	users := []string{"*"}
	group := ""
	for i := 3; i < len(os.Args); i++ {
		if os.Args[i] == "--users" && i+1 < len(os.Args) {
			users = strings.Split(os.Args[i+1], ",")
			i++
		} else if os.Args[i] == "--group" && i+1 < len(os.Args) {
			group = os.Args[i+1]
			i++
		} else if strings.HasPrefix(os.Args[i], "-") {
			fmt.Fprintf(os.Stderr, "unknown flag: %s\nusage: identree add-host <hostname> [--users user1,user2] [--group groupname]\n", os.Args[i])
			os.Exit(1)
		}
	}

	registry := NewHostRegistry(hostRegistryPath())
	secret, err := registry.AddHost(hostname, users, group)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Host %q registered.\n", hostname)
	fmt.Fprintf(os.Stderr, "Authorized users: %s\n", strings.Join(users, ", "))
	if group != "" {
		fmt.Fprintf(os.Stderr, "Group: %s\n", group)
	}
	fmt.Fprintf(os.Stderr, "\nAdd to /etc/identree/client.conf on %s:\n", hostname)
	fmt.Fprintf(os.Stderr, "  IDENTREE_SHARED_SECRET=%s\n\n", secret)
	fmt.Fprintln(os.Stdout, secret)
}

func runRemoveHost() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: identree remove-host <hostname>")
		os.Exit(1)
	}
	hostname := os.Args[2]
	if !validHostname.MatchString(hostname) {
		fmt.Fprintln(os.Stderr, "invalid hostname format")
		os.Exit(1)
	}
	registry := NewHostRegistry(hostRegistryPath())
	if err := registry.RemoveHost(hostname); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Host %q removed.\n", hostname)
}

func runListHosts() {
	registry := NewHostRegistry(hostRegistryPath())
	hosts := registry.RegisteredHosts()
	if len(hosts) == 0 {
		fmt.Fprintln(os.Stderr, "No hosts registered. All hosts use the global shared secret.")
		return
	}
	for _, h := range hosts {
		users, _, registeredAt, _ := registry.GetHost(h)
		fmt.Fprintf(os.Stdout, "%s  users=%s  registered=%s\n", h, strings.Join(users, ","), registeredAt.Format("2006-01-02"))
	}
}

func runRotateHostSecret() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: identree rotate-host-secret <hostname>")
		os.Exit(1)
	}
	hostname := os.Args[2]
	if !validHostname.MatchString(hostname) {
		fmt.Fprintln(os.Stderr, "invalid hostname format")
		os.Exit(1)
	}
	registry := NewHostRegistry(hostRegistryPath())
	secret, err := registry.RotateSecret(hostname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Secret rotated for %q.\n", hostname)
	fmt.Fprintf(os.Stderr, "Update /etc/identree/client.conf on %s:\n", hostname)
	fmt.Fprintf(os.Stderr, "  IDENTREE_SHARED_SECRET=%s\n\n", secret)
	fmt.Fprintln(os.Stdout, secret)
}

// ── Setup ─────────────────────────────────────────────────────────────────────

func runSetup() {
	cfg := setup.Config{}

	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--sssd":
			cfg.SSSD = true
		case "--auditd":
			cfg.Auditd = true
		case "--force":
			cfg.Force = true
		case "--dry-run":
			cfg.DryRun = true
		case "--hostname":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "usage: identree setup [--sssd] [--auditd] [--hostname <name>] [--force] [--dry-run]")
				os.Exit(1)
			}
			cfg.Hostname = args[i+1]
			i++
		default:
			fmt.Fprintf(os.Stderr, "unknown flag: %s\nusage: identree setup [--sssd] [--auditd] [--hostname <name>] [--force] [--dry-run]\n", args[i])
			os.Exit(1)
		}
	}

	// Load client config for server URL and shared secret (needed for --sssd).
	clientCfg, err := config.LoadClientConfig(true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "identree: load client config: %v\n", err)
		os.Exit(1)
	}
	cfg.ServerURL = clientCfg.ServerURL
	cfg.SharedSecret = clientCfg.SharedSecret

	if err := setup.Run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "identree setup: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("identree setup complete.")
}

// ── Renew cert ────────────────────────────────────────────────────────────

func runRenewCert() {
	stripSensitiveEnv()

	clientCfg, err := config.LoadClientConfig(false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "identree: load client config: %v\n", err)
		os.Exit(1)
	}

	if err := setup.RenewCert(
		clientCfg.ServerURL,
		clientCfg.SharedSecret,
		clientCfg.ClientCert,
		clientCfg.ClientKey,
		clientCfg.CACert,
	); err != nil {
		fmt.Fprintf(os.Stderr, "identree renew-cert: %v\n", err)
		os.Exit(1)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// stripSensitiveEnv removes env vars that could be used to inject config
// or redirect network traffic — called before loading client config.
func stripSensitiveEnv() {
	for _, env := range os.Environ() {
		for _, prefix := range []string{"IDENTREE_"} {
			if strings.HasPrefix(env, prefix) {
				key, _, _ := strings.Cut(env, "=")
				os.Unsetenv(key)
			}
		}
	}
	for _, key := range []string{
		"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
		"NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy",
		"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
		"LD_BIND_NOW", "LD_DEBUG", "LD_PROFILE",
	} {
		os.Unsetenv(key)
	}
}

func hostRegistryPath() string {
	if p := os.Getenv("IDENTREE_HOST_REGISTRY_FILE"); p != "" {
		return p
	}
	return "/data/hosts.json"
}

// runVerifyInstall verifies an install script's Ed25519 signature.
//
//	identree verify-install --key <pubkey> --script <script> --sig <sig>
func runVerifyInstall() {
	var keyPath, scriptPath, sigPath string
	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--key":
			if i+1 < len(os.Args) {
				i++
				keyPath = os.Args[i]
			}
		case "--script":
			if i+1 < len(os.Args) {
				i++
				scriptPath = os.Args[i]
			}
		case "--sig":
			if i+1 < len(os.Args) {
				i++
				sigPath = os.Args[i]
			}
		}
	}

	if keyPath == "" || scriptPath == "" || sigPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: identree verify-install --key <pubkey-path> --script <script-path> --sig <sig-path>")
		os.Exit(1)
	}

	pub, err := signing.LoadPublicKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading public key: %v\n", err)
		os.Exit(1)
	}

	script, err := os.ReadFile(scriptPath) // #nosec G703 -- operator-provided CLI argument
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading script: %v\n", err)
		os.Exit(1)
	}

	sigData, err := os.ReadFile(sigPath) // #nosec G703 -- operator-provided CLI argument
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading signature: %v\n", err)
		os.Exit(1)
	}
	sig := strings.TrimSpace(string(sigData))

	if signing.VerifyScript(pub, script, sig) {
		fmt.Println("OK: install script signature verified.")
		os.Exit(0)
	} else {
		fmt.Fprintln(os.Stderr, "FAILED: install script signature verification failed.")
		fmt.Fprintln(os.Stderr, "The script may have been tampered with. Do NOT execute it.")
		os.Exit(1)
	}
}

// runSignScript signs a script file with an Ed25519 private key.
//
//	identree sign-script --key <privkey> --script <script>
func runSignScript() {
	var keyPath, scriptPath string
	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--key":
			if i+1 < len(os.Args) {
				i++
				keyPath = os.Args[i]
			}
		case "--script":
			if i+1 < len(os.Args) {
				i++
				scriptPath = os.Args[i]
			}
		}
	}

	if keyPath == "" || scriptPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: identree sign-script --key <privkey-path> --script <script-path>")
		os.Exit(1)
	}

	priv, err := signing.LoadPrivateKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading private key: %v\n", err)
		os.Exit(1)
	}

	script, err := os.ReadFile(scriptPath) // #nosec G703 -- operator-provided CLI argument
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading script: %v\n", err)
		os.Exit(1)
	}

	sig := signing.SignScript(priv, script)

	// Write signature file alongside the script.
	sigPath := scriptPath + ".sig"
	if err := os.WriteFile(sigPath, []byte(sig+"\n"), 0644); err != nil { // #nosec G703 -- operator-provided CLI argument
		fmt.Fprintf(os.Stderr, "Error writing signature file: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(sig)
	fmt.Fprintf(os.Stderr, "Signature written to %s\n", sigPath)
}
