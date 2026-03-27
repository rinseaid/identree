package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultConfigPath is the server-side config file location.
const DefaultConfigPath = "/etc/identree/identree.conf"

// DefaultClientConfigPath is the client-side config file location.
const DefaultClientConfigPath = "/etc/identree/client.conf"

// EscrowBackend names the native escrow integration to use.
type EscrowBackend string

const (
	EscrowBackend1PasswordConnect EscrowBackend = "1password-connect"
	EscrowBackendVault            EscrowBackend = "vault"
	EscrowBackendBitwarden        EscrowBackend = "bitwarden"
	EscrowBackendInfisical        EscrowBackend = "infisical"
)

// WebhookConfig is a single outbound notification destination.
type WebhookConfig struct {
	URL      string            `json:"url"`
	Format   string            `json:"format"` // raw, apprise, discord, slack, ntfy, custom
	Headers  map[string]string `json:"headers,omitempty"`
	Template string            `json:"template,omitempty"` // only for "custom" format
}

// ServerConfig holds all configuration for identree in server mode.
type ServerConfig struct {
	// ── OIDC ──────────────────────────────────────────────────────────────────
	IssuerURL    string // OIDC issuer (PocketID base URL)
	ClientID     string // OIDC client ID
	ClientSecret string // OIDC client secret

	// ── PocketID API ──────────────────────────────────────────────────────────
	// APIKey is required — it's used to fetch all users and groups from PocketID
	// for the LDAP server and to support admin UI features regardless of login state.
	APIKey    string // PocketID admin API key
	APIURL    string // PocketID API base URL (defaults to IssuerURL)

	// ── HTTP server ───────────────────────────────────────────────────────────
	ListenAddr   string        // default ":8090"
	ExternalURL  string        // public-facing URL (for OIDC redirects)
	SharedSecret string        // secret shared with PAM clients

	// ── Session / auth flow ───────────────────────────────────────────────────
	ChallengeTTL time.Duration // how long a pending challenge lives (default 120s)
	GracePeriod  time.Duration // skip re-auth if approved within this window (default 0 = disabled)
	OneTapMaxAge time.Duration // max age of last OIDC auth for silent one-tap (default 24h)

	// ── LDAP server ───────────────────────────────────────────────────────────
	LDAPEnabled        bool          // whether to start the embedded LDAP server
	LDAPListenAddr     string        // default ":389"
	LDAPBaseDN         string        // e.g. "dc=example,dc=com"
	LDAPBindDN         string        // service-account DN for read-only bind (optional)
	LDAPBindPassword   string        // service-account password (optional)
	LDAPRefreshInterval time.Duration // how often to poll PocketID API (default 300s)
	LDAPUIDMapFile     string        // path to UID/GID persistence file

	// ── Admin access ──────────────────────────────────────────────────────────
	AdminGroups        []string // OIDC groups granting admin dashboard access
	AdminApprovalHosts []string // hostnames requiring admin approval (glob patterns)
	APIKeys            []string // API bearer tokens for programmatic access

	// ── Notifications ─────────────────────────────────────────────────────────
	NotifyCommand        string
	NotifyEnvPassthrough []string
	NotifyUsersFile      string
	NotifyUsers          map[string]string
	Webhooks             []WebhookConfig

	// ── Break-glass escrow ────────────────────────────────────────────────────
	EscrowCommand        string
	EscrowEnvPassthrough []string
	EscrowBackend        EscrowBackend
	EscrowURL            string
	EscrowAuthID         string
	EscrowAuthSecret     string
	EscrowPath           string
	EscrowWebURL         string
	EscrowVaultMap       map[string]string
	BreakglassRotateBefore time.Time // clients should rotate if their hash is older than this

	// ── Host registry ─────────────────────────────────────────────────────────
	HostRegistryFile string

	// ── History ───────────────────────────────────────────────────────────────
	DefaultHistoryPageSize int

	// ── Session state ─────────────────────────────────────────────────────────
	SessionStateFile string

	// ── Client config overrides (pushed to clients at registration) ───────────
	ClientBreakglassPasswordType string
	ClientBreakglassRotationDays int
	ClientTokenCacheEnabled      *bool

	// ── Webhook receiver (PocketID → identree) ────────────────────────────────
	WebhookSecret string // validates incoming PocketID webhook signatures
}

// ClientConfig holds all configuration for identree in PAM client mode.
type ClientConfig struct {
	ServerURL    string
	SharedSecret string
	PollInterval time.Duration // default 2s
	Timeout      time.Duration // default 120s

	// Break-glass
	BreakglassEnabled      bool
	BreakglassFile         string // default /etc/identree-breakglass
	BreakglassRotationDays int    // default 90
	BreakglassPasswordType string // random, passphrase, alphanumeric

	// Token cache
	TokenCacheEnabled  bool
	TokenCacheDir      string
	TokenCacheIssuer   string
	TokenCacheClientID string
}

// LoadServerConfig reads ServerConfig from the config file and environment.
// Environment variables take precedence over config file values.
func LoadServerConfig() (*ServerConfig, error) {
	env, err := loadConfigFile(DefaultConfigPath)
	if err != nil {
		return nil, err
	}
	get := func(key string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return env[key]
	}
	getBool := func(key string, def bool) bool {
		v := get(key)
		if v == "" {
			return def
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			return def
		}
		return b
	}
	getDuration := func(key string, def time.Duration) time.Duration {
		v := get(key)
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return def
		}
		return d
	}
	getInt := func(key string, def int) int {
		v := get(key)
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return def
		}
		return n
	}
	getSlice := func(key string) []string {
		v := get(key)
		if v == "" {
			return nil
		}
		var out []string
		for _, s := range strings.Split(v, ",") {
			if t := strings.TrimSpace(s); t != "" {
				out = append(out, t)
			}
		}
		return out
	}

	cfg := &ServerConfig{
		IssuerURL:    get("IDENTREE_OIDC_ISSUER_URL"),
		ClientID:     get("IDENTREE_OIDC_CLIENT_ID"),
		ClientSecret: get("IDENTREE_OIDC_CLIENT_SECRET"),
		APIKey:       get("IDENTREE_POCKETID_API_KEY"),
		APIURL:       get("IDENTREE_POCKETID_API_URL"),

		ListenAddr:   stringDefault(get("IDENTREE_LISTEN_ADDR"), ":8090"),
		ExternalURL:  get("IDENTREE_EXTERNAL_URL"),
		SharedSecret: get("IDENTREE_SHARED_SECRET"),

		ChallengeTTL: getDuration("IDENTREE_CHALLENGE_TTL", 120*time.Second),
		GracePeriod:  getDuration("IDENTREE_GRACE_PERIOD", 0),
		OneTapMaxAge: getDuration("IDENTREE_ONE_TAP_MAX_AGE", 24*time.Hour),

		LDAPEnabled:         getBool("IDENTREE_LDAP_ENABLED", true),
		LDAPListenAddr:      stringDefault(get("IDENTREE_LDAP_LISTEN_ADDR"), ":389"),
		LDAPBaseDN:          get("IDENTREE_LDAP_BASE_DN"),
		LDAPBindDN:          get("IDENTREE_LDAP_BIND_DN"),
		LDAPBindPassword:    get("IDENTREE_LDAP_BIND_PASSWORD"),
		LDAPRefreshInterval: getDuration("IDENTREE_LDAP_REFRESH_INTERVAL", 300*time.Second),
		LDAPUIDMapFile:      stringDefault(get("IDENTREE_LDAP_UID_MAP_FILE"), "/var/lib/identree/uidmap.json"),

		AdminGroups:        getSlice("IDENTREE_ADMIN_GROUPS"),
		AdminApprovalHosts: getSlice("IDENTREE_ADMIN_APPROVAL_HOSTS"),
		APIKeys:            getSlice("IDENTREE_API_KEYS"),

		NotifyCommand:        get("IDENTREE_NOTIFY_COMMAND"),
		NotifyEnvPassthrough: getSlice("IDENTREE_NOTIFY_ENV_PASSTHROUGH"),
		NotifyUsersFile:      get("IDENTREE_NOTIFY_USERS_FILE"),

		EscrowCommand:        get("IDENTREE_ESCROW_COMMAND"),
		EscrowEnvPassthrough: getSlice("IDENTREE_ESCROW_COMMAND_ENV"),
		EscrowBackend:        EscrowBackend(get("IDENTREE_ESCROW_BACKEND")),
		EscrowURL:            get("IDENTREE_ESCROW_URL"),
		EscrowAuthID:         get("IDENTREE_ESCROW_AUTH_ID"),
		EscrowAuthSecret:     get("IDENTREE_ESCROW_AUTH_SECRET"),
		EscrowPath:           get("IDENTREE_ESCROW_PATH"),
		EscrowWebURL:         get("IDENTREE_ESCROW_WEB_URL"),

		HostRegistryFile:       get("IDENTREE_HOST_REGISTRY_FILE"),
		DefaultHistoryPageSize: getInt("IDENTREE_HISTORY_PAGE_SIZE", 10),
		SessionStateFile:       get("IDENTREE_SESSION_STATE_FILE"),

		ClientBreakglassPasswordType: get("IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE"),
		ClientBreakglassRotationDays: getInt("IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS", 0),

		WebhookSecret: get("IDENTREE_WEBHOOK_SECRET"),
	}

	// APIURL defaults to IssuerURL
	if cfg.APIURL == "" {
		cfg.APIURL = cfg.IssuerURL
	}

	// Parse escrow vault map
	if raw := get("IDENTREE_ESCROW_VAULT_MAP"); raw != "" {
		var m map[string]string
		if err := json.Unmarshal([]byte(raw), &m); err == nil {
			cfg.EscrowVaultMap = m
		}
	}

	// Parse webhooks
	cfg.Webhooks = parseWebhooks(get("IDENTREE_WEBHOOKS"), get("IDENTREE_WEBHOOKS_FILE"))

	// Parse notify users
	cfg.NotifyUsers = parseNotifyUsers(get("IDENTREE_NOTIFY_USERS"), cfg.NotifyUsersFile)

	// Client token cache override
	if v := get("IDENTREE_CLIENT_TOKEN_CACHE_ENABLED"); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			cfg.ClientTokenCacheEnabled = &b
		}
	}

	// BreakglassRotateBefore
	if v := get("IDENTREE_BREAKGLASS_ROTATE_BEFORE"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			cfg.BreakglassRotateBefore = t
		}
	}

	// Validate required fields
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("IDENTREE_OIDC_ISSUER_URL is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("IDENTREE_OIDC_CLIENT_ID is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("IDENTREE_OIDC_CLIENT_SECRET is required")
	}
	if cfg.SharedSecret == "" {
		return nil, fmt.Errorf("IDENTREE_SHARED_SECRET is required")
	}
	if cfg.ExternalURL == "" {
		return nil, fmt.Errorf("IDENTREE_EXTERNAL_URL is required")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("IDENTREE_POCKETID_API_KEY is required (needed for LDAP and admin features)")
	}
	if cfg.LDAPEnabled && cfg.LDAPBaseDN == "" {
		return nil, fmt.Errorf("IDENTREE_LDAP_BASE_DN is required when LDAP is enabled")
	}

	return cfg, nil
}

// LoadClientConfig reads ClientConfig from the config file and environment.
// allowNoServer allows the config to load without IDENTREE_SERVER_URL (for
// local-only operations like rotate-breakglass).
func LoadClientConfig(allowNoServer bool) (*ClientConfig, error) {
	env, err := loadConfigFile(DefaultClientConfigPath)
	if os.IsNotExist(err) {
		// Also try the legacy pam-pocketid path
		env, err = loadConfigFile("/etc/pam-pocketid.conf")
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if env == nil {
		env = map[string]string{}
	}
	get := func(keys ...string) string {
		for _, key := range keys {
			if v := os.Getenv(key); v != "" {
				return v
			}
			if v := env[key]; v != "" {
				return v
			}
		}
		return ""
	}
	getBool := func(def bool, keys ...string) bool {
		v := get(keys...)
		if v == "" {
			return def
		}
		b, _ := strconv.ParseBool(v)
		return b
	}
	getDuration := func(def time.Duration, keys ...string) time.Duration {
		v := get(keys...)
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return def
		}
		return d
	}
	getInt := func(def int, keys ...string) int {
		v := get(keys...)
		if v == "" {
			return def
		}
		n, _ := strconv.Atoi(v)
		return n
	}

	cfg := &ClientConfig{
		// Accept both new and legacy env var names
		ServerURL:    get("IDENTREE_SERVER_URL", "PAM_POCKETID_SERVER_URL"),
		SharedSecret: get("IDENTREE_SHARED_SECRET", "PAM_POCKETID_SHARED_SECRET"),
		PollInterval: getDuration(2*time.Second, "IDENTREE_POLL_INTERVAL", "PAM_POCKETID_POLL_INTERVAL"),
		Timeout:      getDuration(120*time.Second, "IDENTREE_TIMEOUT", "PAM_POCKETID_TIMEOUT"),

		BreakglassEnabled:      getBool(true, "IDENTREE_BREAKGLASS_ENABLED", "PAM_POCKETID_BREAKGLASS_ENABLED"),
		BreakglassFile:         stringDefault(get("IDENTREE_BREAKGLASS_FILE", "PAM_POCKETID_BREAKGLASS_FILE"), "/etc/identree-breakglass"),
		BreakglassRotationDays: getInt(90, "IDENTREE_BREAKGLASS_ROTATION_DAYS", "PAM_POCKETID_BREAKGLASS_ROTATION_DAYS"),
		BreakglassPasswordType: stringDefault(get("IDENTREE_BREAKGLASS_PASSWORD_TYPE", "PAM_POCKETID_BREAKGLASS_PASSWORD_TYPE"), "random"),

		TokenCacheEnabled:  getBool(true, "IDENTREE_TOKEN_CACHE_ENABLED", "PAM_POCKETID_TOKEN_CACHE_ENABLED"),
		TokenCacheDir:      stringDefault(get("IDENTREE_TOKEN_CACHE_DIR", "PAM_POCKETID_TOKEN_CACHE_DIR"), "/run/identree"),
		TokenCacheIssuer:   get("IDENTREE_TOKEN_CACHE_ISSUER", "PAM_POCKETID_TOKEN_CACHE_ISSUER"),
		TokenCacheClientID: get("IDENTREE_TOKEN_CACHE_CLIENT_ID", "PAM_POCKETID_TOKEN_CACHE_CLIENT_ID"),
	}

	if !allowNoServer && cfg.ServerURL == "" {
		return nil, fmt.Errorf("IDENTREE_SERVER_URL is required")
	}

	return cfg, nil
}

// loadConfigFile reads a KEY=VALUE config file into a map.
// Lines starting with # are ignored. The "export " prefix is stripped.
// Returns os.IsNotExist error if the file doesn't exist.
func loadConfigFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	m := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		// Strip optional surrounding quotes
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		} else if len(val) >= 2 && val[0] == '\'' && val[len(val)-1] == '\'' {
			val = val[1 : len(val)-1]
		}
		m[key] = val
	}
	return m, scanner.Err()
}

// parseCIDRs parses a comma-separated list of CIDR strings.
func parseCIDRs(s string) []*net.IPNet {
	var out []*net.IPNet
	for _, cidr := range strings.Split(s, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			out = append(out, network)
		}
	}
	return out
}

// parseWebhooks loads WebhookConfig from an inline JSON string or a JSON file.
func parseWebhooks(inline, filePath string) []WebhookConfig {
	var out []WebhookConfig
	if inline != "" {
		_ = json.Unmarshal([]byte(inline), &out)
	}
	if filePath != "" && len(out) == 0 {
		data, err := os.ReadFile(filePath)
		if err == nil {
			_ = json.Unmarshal(data, &out)
		}
	}
	return out
}

// parseNotifyUsers loads the per-user notification map from an inline JSON
// string or a JSON file.
func parseNotifyUsers(inline, filePath string) map[string]string {
	var out map[string]string
	if inline != "" {
		_ = json.Unmarshal([]byte(inline), &out)
	}
	if filePath != "" && out == nil {
		data, err := os.ReadFile(filePath)
		if err == nil {
			_ = json.Unmarshal(data, &out)
		}
	}
	return out
}

func stringDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
