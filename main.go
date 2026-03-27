package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// messageWriter is where PAM messages are written. pam_exec sends stdout to
// the user's terminal. Overridable for testing.
var messageWriter io.Writer = os.Stdout

// version and commit are set at build time:
//
//	-ldflags "-X main.version=v0.1.0 -X main.commit=abc12345"
var version = "dev"
var commit = ""

// safeUsername validates PAM_USER to prevent injection.
var safeUsername = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

func main() {
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
	cfg, err := LoadServerConfig()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	srv, err := NewServer(cfg)
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
	if cfg.SessionStateFile != "" {
		slog.Info("session persistence enabled", "path", cfg.SessionStateFile)
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

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      0, // disabled for SSE; per-handler timeouts used instead
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8192,
	}

	shutdownDone := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		defer close(shutdownDone)
		sig := <-sigCh
		slog.Info("shutting down", "signal", sig)
		// Second signal forces immediate exit
		go func() {
			<-sigCh
			slog.Info("forced exit")
			os.Exit(1)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			slog.Error("HTTP shutdown error", "err", err)
		}
		srv.WaitForNotifications(5 * time.Second)
		srv.store.SaveState()
		srv.Stop()
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

	cfg, err := LoadClientConfig(true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	plaintext, err := rotateBreakglass(cfg, force, false)
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

	cfg, err := LoadClientConfig(true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	hash, err := readBreakglassHash(cfg.BreakglassFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	tty, err := openTTY()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot open terminal: %v\n", err)
		os.Exit(1)
	}
	defer tty.Close()

	fmt.Fprintf(tty, "Break-glass password: ")
	password, err := readPasswordFn(int(tty.Fd()))
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
	requestParentDeathSignal()
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

	cfg, err := LoadClientConfig(false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "identree config error: %v\n", err)
		os.Exit(1)
	}

	var cache *TokenCache
	if cfg.TokenCacheEnabled {
		cache = NewTokenCache(cfg.TokenCacheDir, cfg.TokenCacheIssuer, cfg.TokenCacheClientID)
	}

	client := NewPAMClient(cfg, cache)
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
