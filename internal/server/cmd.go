package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
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
	"github.com/rinseaid/identree/internal/sudorules"
	"github.com/rinseaid/identree/internal/uidmap"
)

// version and commit are set at build time:
//
//	-ldflags "-X main.version=v0.1.0 -X main.commit=abc12345"
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

Global flags:
  --version, -v                          Show version
  --help, -h                             Show this help

Config file locations:
  Server: /etc/identree/identree.conf
  Client: /etc/identree/client.conf (falls back to /etc/pam-pocketid.conf)
`)
}

// ── Server ────────────────────────────────────────────────────────────────────

func runServer() {
	cfg, err := config.LoadServerConfig()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
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

	slog.Info("identree server starting",
		"version", version,
		"listen", cfg.ListenAddr,
		"external_url", cfg.ExternalURL,
		"oidc_issuer", cfg.IssuerURL,
		"redirect_uri", strings.TrimRight(cfg.ExternalURL, "/")+"/callback",
		"challenge_ttl", cfg.ChallengeTTL,
	)
	if cfg.GracePeriod > 0 {
		slog.Info("grace period enabled", "duration", cfg.GracePeriod)
	}
	if cfg.LDAPEnabled {
		slog.Info("LDAP server enabled",
			"listen", cfg.LDAPListenAddr,
			"base_dn", cfg.LDAPBaseDN,
			"refresh_interval", cfg.LDAPRefreshInterval,
		)
	}
	if cfg.APIKey == "" {
		slog.Info("bridge mode rules loaded", "count", len(rulesStore.Rules()))
	}
	if len(cfg.AdminGroups) == 0 && !cfg.DevLoginEnabled {
		slog.Warn("IDENTREE_ADMIN_GROUPS is empty — admin UI will be inaccessible without IDENTREE_DEV_LOGIN")
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
	if cfg.NotifyCommand != "" {
		slog.Info("push notifications enabled")
	}

	// Start LDAP server if enabled.
	var ldapCancel context.CancelFunc
	if cfg.LDAPEnabled {
		um, err := uidmap.NewUIDMap(cfg.LDAPUIDMapFile, cfg.LDAPUIDBase, cfg.LDAPGIDBase)
		if err != nil {
			slog.Error("uid map load error", "err", err)
			os.Exit(1)
		}
		ldapSrv, err := ldapserver.NewLDAPServer(cfg, um, rulesStore)
		if err != nil {
			slog.Error("ldap server init error", "err", err)
			os.Exit(1)
		}

		// In full mode, seed the directory before opening the listener.
		if cfg.APIKey != "" {
			dir, ferr := srv.pocketIDClient.FetchDirectory()
			if ferr != nil {
				slog.Warn("ldap: initial directory fetch failed (will retry)", "err", ferr)
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
			}
		}()

		// Full mode: periodic refresh + webhook-triggered refresh.
		if cfg.APIKey != "" {
			go func() {
				defer func() {
					if r := recover(); r != nil {
						buf := make([]byte, 64<<10)
						n := runtime.Stack(buf, false)
						slog.Error("goroutine panicked", "panic", r, "stack", string(buf[:n]))
					}
				}()
				ticker := time.NewTicker(cfg.LDAPRefreshInterval)
				defer ticker.Stop()
				for {
					select {
					case <-ldapCtx.Done():
						return
					case <-ticker.C:
						dir, ferr := srv.pocketIDClient.FetchDirectory()
						if ferr != nil {
							slog.Warn("ldap: directory refresh failed", "err", ferr)
							srv.ldapLastErrorMu.Lock()
							srv.ldapLastError = ferr
							srv.ldapLastErrorAt = time.Now()
							srv.ldapLastErrorMu.Unlock()
							continue
						}
						ldapSrv.Refresh(dir, "poll", srv.removedUsersSnapshot())
						srv.ldapLastSyncMu.Lock()
						srv.ldapLastSync = time.Now()
						srv.ldapLastSyncMu.Unlock()
						srv.ldapLastErrorMu.Lock()
						srv.ldapLastError = nil
						srv.ldapLastErrorMu.Unlock()
					case <-srv.ldapRefreshCh:
						dir, ferr := srv.pocketIDClient.FetchDirectory()
						if ferr != nil {
							slog.Warn("ldap: webhook-triggered refresh failed", "err", ferr)
							srv.ldapLastErrorMu.Lock()
							srv.ldapLastError = ferr
							srv.ldapLastErrorAt = time.Now()
							srv.ldapLastErrorMu.Unlock()
							continue
						}
						ldapSrv.Refresh(dir, "webhook", srv.removedUsersSnapshot())
						srv.ldapLastSyncMu.Lock()
						srv.ldapLastSync = time.Now()
						srv.ldapLastSyncMu.Unlock()
						srv.ldapLastErrorMu.Lock()
						srv.ldapLastError = nil
						srv.ldapLastErrorMu.Unlock()
					}
				}
			}()
		}
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
		srv.WaitForNotifications(5 * time.Second)
		srv.store.SaveState()
		srv.Stop()
		shutdownCancel()
	}()

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server error", "err", err)
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

	var cache *pam.TokenCache
	if cfg.TokenCacheEnabled {
		var err error
		cache, err = pam.NewTokenCache(cfg.TokenCacheDir, cfg.TokenCacheIssuer, cfg.TokenCacheClientID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "identree: %v\n", err)
			os.Exit(1)
		}
	}

	client, err := pam.NewPAMClient(cfg, cache)
	if err != nil {
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

// ── Helpers ───────────────────────────────────────────────────────────────────

// stripSensitiveEnv removes env vars that could be used to inject config
// or redirect network traffic — called before loading client config.
func stripSensitiveEnv() {
	for _, env := range os.Environ() {
		for _, prefix := range []string{"IDENTREE_", "PAM_POCKETID_"} {
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
