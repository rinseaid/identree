package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultConfigPath is the server-side config file location.
const DefaultConfigPath = "/etc/identree/identree.conf"

// DefaultClientConfigPath is the client-side config file location.
const DefaultClientConfigPath = "/etc/identree/client.conf"

// SudoNoAuthenticate controls whether the !authenticate sudoOption is added to
// generated sudoRole LDAP entries.
type SudoNoAuthenticate string

const (
	// SudoNoAuthFalse (default): !authenticate is never added; sudo invokes PAM.
	SudoNoAuthFalse SudoNoAuthenticate = "false"
	// SudoNoAuthTrue: !authenticate is added to all sudo rules; PAM is never invoked.
	SudoNoAuthTrue SudoNoAuthenticate = "true"
	// SudoNoAuthClaims: per-group; IdP admins set sudoOptions=!authenticate on specific groups.
	SudoNoAuthClaims SudoNoAuthenticate = "claims"
)

// EscrowBackend names the native escrow integration to use.
type EscrowBackend string

const (
	EscrowBackend1PasswordConnect EscrowBackend = "1password-connect"
	EscrowBackendVault            EscrowBackend = "vault"
	EscrowBackendBitwarden        EscrowBackend = "bitwarden"
	EscrowBackendInfisical        EscrowBackend = "infisical"
	EscrowBackendLocal            EscrowBackend = "local"
)

// ServerConfig holds all configuration for identree in server mode.
type ServerConfig struct {
	// ── OIDC ──────────────────────────────────────────────────────────────────
	IssuerURL              string // OIDC issuer (PocketID base URL) — used for discovery/token exchange
	IssuerPublicURL        string // Optional public-facing PocketID URL (rewrites auth redirects for split internal/external routing)
	ClientID               string // OIDC client ID
	ClientSecret           string // OIDC client secret
	OIDCInsecureSkipVerify bool   // Skip TLS verification for OIDC discovery (test environments with self-signed certs only)

	// ── PocketID API ──────────────────────────────────────────────────────────
	// APIKey enables full mode (PocketID backend). When set, identree fetches
	// users and groups from PocketID and serves a complete LDAP directory.
	// When empty, identree runs in PAM bridge mode: any OIDC IdP works for
	// authentication, and the LDAP server serves only ou=sudoers from a local
	// JSON rules file managed via the admin UI.
	APIKey    string // PocketID admin API key (optional — empty = bridge mode)
	APIURL    string // PocketID API base URL (defaults to IssuerURL)

	// ── HTTP server ───────────────────────────────────────────────────────────
	ListenAddr   string        // default ":8090"
	ExternalURL  string        // public-facing URL (for OIDC redirects)
	InstallURL   string        // URL reachable from client hosts (for install script); defaults to ExternalURL
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

	// LDAPSudoNoAuthenticate controls the !authenticate sudoOption in generated sudoRole entries.
	//   "false"  (default) — !authenticate never added; sudo invokes PAM (passkey auth via pam-pocketid).
	//   "true"   — !authenticate added to all sudo rules; PAM is never invoked.
	//   "claims" — per-group: IDP admins set sudoOptions=!authenticate on specific groups.
	LDAPSudoNoAuthenticate SudoNoAuthenticate

	// SudoRulesFile is the path to the JSON sudo rules store (bridge mode only).
	// In bridge mode (APIKey == ""), the LDAP server serves ou=sudoers from this file.
	// Rules are managed via the admin UI at /admin/sudo-rules.
	SudoRulesFile string

	// LDAPUIDBase is the first UID to assign (default 200000).
	LDAPUIDBase int
	// LDAPGIDBase is the first GID to assign (default 200000).
	LDAPGIDBase int
	// LDAPDefaultShell is the default loginShell for LDAP user entries (default /bin/bash).
	LDAPDefaultShell string
	// LDAPDefaultHome is a fmt.Sprintf pattern for homeDirectory (default /home/%s).
	// The single %s is replaced with the username.
	LDAPDefaultHome string

	// ── Admin access ──────────────────────────────────────────────────────────
	AdminGroups        []string // OIDC groups granting admin dashboard access
	AdminApprovalHosts []string // hostnames requiring admin approval (glob patterns)
	APIKeys            []string // API bearer tokens for programmatic access

	// ── Notifications ─────────────────────────────────────────────────────────
	NotifyBackend string        // ntfy | slack | discord | apprise | webhook | custom | "" (disabled)
	NotifyURL     string        // webhook URL (all backends except custom)
	NotifyToken   string        // optional Bearer token (e.g. ntfy auth)
	NotifyCommand string        // path to executable (custom backend only)
	NotifyTimeout time.Duration // timeout for both HTTP and command (default 15s)

	// ── Break-glass escrow ────────────────────────────────────────────────────
	EscrowCommand          string
	EscrowEnvPassthrough   []string
	EscrowBackend          EscrowBackend
	EscrowURL              string
	EscrowAuthID           string
	EscrowAuthSecret       string
	EscrowAuthSecretFile   string
	EscrowPath             string
	EscrowWebURL           string
	EscrowVaultMap         map[string]string
	EscrowEncryptionKey    string // used by EscrowBackendLocal only
	BreakglassRotateBefore time.Time // clients should rotate if their hash is older than this

	// ── Host registry ─────────────────────────────────────────────────────────
	HostRegistryFile string

	// ── UI ────────────────────────────────────────────────────────────────────
	DefaultPageSize int

	// ── Session state ─────────────────────────────────────────────────────────
	SessionStateFile string

	// ── Client config overrides (pushed to clients at every auth) ────────────
	// Sent in the challenge response and override the client's local config.
	// Allows central control without editing client.conf on every host.
	ClientPollInterval           time.Duration
	ClientTimeout                time.Duration
	ClientBreakglassEnabled      *bool
	ClientBreakglassPasswordType string
	ClientBreakglassRotationDays int
	ClientTokenCacheEnabled      *bool

	// ── Webhook receiver (PocketID → identree) ────────────────────────────────
	WebhookSecret string // validates incoming PocketID webhook signatures

	// ── Development / testing ─────────────────────────────────────────────────
	// DevLoginEnabled enables /dev/login?user=X&role=Y for bypassing OIDC in
	// local test environments. NEVER enable in production.
	DevLoginEnabled bool
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
// Load priority (highest to lowest): environment variables > KEY=VALUE conf file > TOML config file > defaults.
func LoadServerConfig() (*ServerConfig, error) {
	// Load TOML config (lowest file-level priority).
	tomlEnv, err := LoadTOMLConfig(TOMLConfigPath())
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("loading TOML config: %w", err)
	}
	if tomlEnv == nil {
		tomlEnv = map[string]string{}
	}

	// Load KEY=VALUE conf (overrides TOML).
	confEnv, err := loadConfigFile(DefaultConfigPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		confEnv = map[string]string{}
	}
	for k, v := range confEnv {
		tomlEnv[k] = v
	}
	env := tomlEnv

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
			slog.Warn("config: invalid boolean value, using default", "key", key, "value", v, "default", def)
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
			slog.Warn("config: invalid duration value, using default", "key", key, "value", v, "default", def)
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
			slog.Warn("config: invalid integer value, using default", "key", key, "value", v, "default", def)
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
		IssuerURL:              get("IDENTREE_OIDC_ISSUER_URL"),
		IssuerPublicURL:        get("IDENTREE_OIDC_ISSUER_PUBLIC_URL"),
		ClientID:               get("IDENTREE_OIDC_CLIENT_ID"),
		ClientSecret:           get("IDENTREE_OIDC_CLIENT_SECRET"),
		OIDCInsecureSkipVerify: getBool("IDENTREE_OIDC_INSECURE_SKIP_VERIFY", false),
		APIKey:       get("IDENTREE_POCKETID_API_KEY"),
		APIURL:       get("IDENTREE_POCKETID_API_URL"),

		ListenAddr:   stringDefault(get("IDENTREE_LISTEN_ADDR"), ":8090"),
		ExternalURL:  get("IDENTREE_EXTERNAL_URL"),
		InstallURL:   get("IDENTREE_INSTALL_URL"),
		SharedSecret: get("IDENTREE_SHARED_SECRET"),

		ChallengeTTL: getDuration("IDENTREE_CHALLENGE_TTL", 120*time.Second),
		GracePeriod:  getDuration("IDENTREE_GRACE_PERIOD", 0),
		OneTapMaxAge: getDuration("IDENTREE_ONE_TAP_MAX_AGE", 24*time.Hour),

		LDAPEnabled:            getBool("IDENTREE_LDAP_ENABLED", true),
		LDAPListenAddr:         stringDefault(get("IDENTREE_LDAP_LISTEN_ADDR"), ":389"),
		LDAPBaseDN:             get("IDENTREE_LDAP_BASE_DN"),
		LDAPBindDN:             get("IDENTREE_LDAP_BIND_DN"),
		LDAPBindPassword:       get("IDENTREE_LDAP_BIND_PASSWORD"),
		LDAPRefreshInterval:    getDuration("IDENTREE_LDAP_REFRESH_INTERVAL", 300*time.Second),
		LDAPUIDMapFile:         stringDefault(get("IDENTREE_LDAP_UID_MAP_FILE"), "/config/uidmap.json"),
		LDAPSudoNoAuthenticate: SudoNoAuthenticate(stringDefault(get("IDENTREE_SUDO_NO_AUTHENTICATE"), "false")),
		SudoRulesFile:          stringDefault(get("IDENTREE_SUDO_RULES_FILE"), "/config/sudorules.json"),
		LDAPUIDBase:            getInt("IDENTREE_LDAP_UID_BASE", 200000),
		LDAPGIDBase:            getInt("IDENTREE_LDAP_GID_BASE", 200000),
		LDAPDefaultShell:       get("IDENTREE_LDAP_DEFAULT_SHELL"),
		LDAPDefaultHome:        get("IDENTREE_LDAP_DEFAULT_HOME"),

		AdminGroups:        getSlice("IDENTREE_ADMIN_GROUPS"),
		AdminApprovalHosts: getSlice("IDENTREE_ADMIN_APPROVAL_HOSTS"),
		APIKeys:            getSlice("IDENTREE_API_KEYS"),

		NotifyBackend: get("IDENTREE_NOTIFY_BACKEND"),
		NotifyURL:     get("IDENTREE_NOTIFY_URL"),
		NotifyToken:   get("IDENTREE_NOTIFY_TOKEN"),
		NotifyCommand: get("IDENTREE_NOTIFY_COMMAND"),
		NotifyTimeout: getDuration("IDENTREE_NOTIFY_TIMEOUT", 15*time.Second),

		EscrowCommand:        get("IDENTREE_ESCROW_COMMAND"),
		EscrowEnvPassthrough: getSlice("IDENTREE_ESCROW_COMMAND_ENV"),
		EscrowBackend:        EscrowBackend(get("IDENTREE_ESCROW_BACKEND")),
		EscrowURL:            get("IDENTREE_ESCROW_URL"),
		EscrowAuthID:         get("IDENTREE_ESCROW_AUTH_ID"),
		EscrowAuthSecret:     get("IDENTREE_ESCROW_AUTH_SECRET"),
		EscrowAuthSecretFile: get("IDENTREE_ESCROW_AUTH_SECRET_FILE"),
		EscrowPath:           get("IDENTREE_ESCROW_PATH"),
		EscrowWebURL:         get("IDENTREE_ESCROW_WEB_URL"),
		EscrowEncryptionKey:  get("IDENTREE_ESCROW_ENCRYPTION_KEY"),

		HostRegistryFile:       stringDefault(get("IDENTREE_HOST_REGISTRY_FILE"), "/config/hosts.json"),
		DefaultPageSize: getInt("IDENTREE_HISTORY_PAGE_SIZE", 15),
		SessionStateFile:       stringDefault(get("IDENTREE_SESSION_STATE_FILE"), "/config/sessions.json"),

		ClientPollInterval:           getDuration("IDENTREE_CLIENT_POLL_INTERVAL", 0),
		ClientTimeout:                getDuration("IDENTREE_CLIENT_TIMEOUT", 0),
		ClientBreakglassPasswordType: get("IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE"),
		ClientBreakglassRotationDays: getInt("IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS", 0),

		WebhookSecret:   get("IDENTREE_WEBHOOK_SECRET"),
		DevLoginEnabled: getBool("IDENTREE_DEV_LOGIN", false),
	}

	// Warn if SessionStateFile is unset — grace sessions, revocations, and audit log will not persist.
	if cfg.SessionStateFile == "" {
		slog.Warn("IDENTREE_SESSION_STATE_FILE is not set — grace sessions, revocations, and audit log will be lost on restart")
	}

	// APIURL defaults to IssuerURL
	if cfg.APIURL == "" {
		cfg.APIURL = cfg.IssuerURL
	}

	// InstallURL defaults to ExternalURL so install scripts point to the right place.
	if cfg.InstallURL == "" {
		cfg.InstallURL = cfg.ExternalURL
	}

	// Parse escrow vault map
	if raw := get("IDENTREE_ESCROW_VAULT_MAP"); raw != "" {
		var m map[string]string
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			return nil, fmt.Errorf("IDENTREE_ESCROW_VAULT_MAP: invalid JSON: %w", err)
		}
		cfg.EscrowVaultMap = m
	}

	// Client bool overrides
	if v := get("IDENTREE_CLIENT_TOKEN_CACHE_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.ClientTokenCacheEnabled = &b
		}
	}
	if v := get("IDENTREE_CLIENT_BREAKGLASS_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.ClientBreakglassEnabled = &b
		}
	}

	// BreakglassRotateBefore
	if v := get("IDENTREE_BREAKGLASS_ROTATE_BEFORE"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			cfg.BreakglassRotateBefore = t
		}
	}

	// Clamp ChallengeTTL to sane bounds (10s–600s).
	if cfg.ChallengeTTL < 10*time.Second {
		cfg.ChallengeTTL = 10 * time.Second
	}
	if cfg.ChallengeTTL > 600*time.Second {
		cfg.ChallengeTTL = 600 * time.Second
	}

	// Normalize LDAPUIDBase/GIDBase: 0 means "unset" (e.g. stored in a legacy TOML
	// config from when the default was 0); reset to the safe default of 200000.
	if cfg.LDAPUIDBase <= 0 {
		cfg.LDAPUIDBase = 200000
	}
	if cfg.LDAPGIDBase <= 0 {
		cfg.LDAPGIDBase = 200000
	}

	// Clamp GracePeriod: negative values are nonsensical — treat as 0 (disabled).
	if cfg.GracePeriod < 0 {
		cfg.GracePeriod = 0
	}
	// Clamp OneTapMaxAge: zero or negative disables the recency check — default to 24h.
	if cfg.OneTapMaxAge <= 0 {
		cfg.OneTapMaxAge = 24 * time.Hour
	}
	// Clamp NotifyTimeout: a zero value means no timeout at all in http.Client.
	if cfg.NotifyTimeout <= 0 {
		cfg.NotifyTimeout = 15 * time.Second
	}

	// Clamp LDAPRefreshInterval: time.NewTicker panics if d <= 0.
	if cfg.LDAPRefreshInterval < time.Second {
		cfg.LDAPRefreshInterval = time.Second
	}

	// Clamp DefaultPageSize to a sane range.
	if cfg.DefaultPageSize < 1 {
		cfg.DefaultPageSize = 15
	}
	if cfg.DefaultPageSize > 500 {
		cfg.DefaultPageSize = 500
	}

	// Clamp ClientPollInterval: a positive but sub-second value would cause a
	// tight polling loop on clients. Zero means "no override" and is left alone.
	if cfg.ClientPollInterval > 0 && cfg.ClientPollInterval < time.Second {
		cfg.ClientPollInterval = time.Second
	}

	// Clamp ClientBreakglassRotationDays: 0 means "no override"; negative is
	// nonsensical; cap at a reasonable upper bound.
	if cfg.ClientBreakglassRotationDays < 0 {
		cfg.ClientBreakglassRotationDays = 0
	}

	// Load escrow auth secret from file if EscrowAuthSecretFile is set and EscrowAuthSecret is empty.
	if cfg.EscrowAuthSecretFile != "" && cfg.EscrowAuthSecret == "" {
		for _, seg := range strings.Split(cfg.EscrowAuthSecretFile, "/") {
			if seg == ".." || seg == "." {
				return nil, fmt.Errorf("IDENTREE_ESCROW_AUTH_SECRET_FILE must not contain path traversal sequences")
			}
		}
		if data, err := os.ReadFile(cfg.EscrowAuthSecretFile); err == nil {
			cfg.EscrowAuthSecret = strings.TrimSpace(string(data))
		}
	}

	// Validate required fields
	if cfg.IssuerURL == "" && !cfg.DevLoginEnabled {
		return nil, fmt.Errorf("IDENTREE_OIDC_ISSUER_URL is required")
	}
	if cfg.ClientID == "" && !cfg.DevLoginEnabled {
		return nil, fmt.Errorf("IDENTREE_OIDC_CLIENT_ID is required")
	}
	if cfg.ClientSecret == "" && !cfg.DevLoginEnabled {
		return nil, fmt.Errorf("IDENTREE_OIDC_CLIENT_SECRET is required")
	}
	if cfg.SharedSecret == "" {
		return nil, fmt.Errorf("IDENTREE_SHARED_SECRET is required")
	}
	if len(cfg.SharedSecret) < 32 {
		return nil, fmt.Errorf("IDENTREE_SHARED_SECRET must be at least 32 characters")
	}
	if cfg.WebhookSecret != "" && len(cfg.WebhookSecret) < 32 {
		return nil, fmt.Errorf("IDENTREE_WEBHOOK_SECRET must be at least 32 characters when set")
	}
	if cfg.ExternalURL == "" {
		return nil, fmt.Errorf("IDENTREE_EXTERNAL_URL is required")
	}
	if !strings.HasPrefix(cfg.ExternalURL, "http://") && !strings.HasPrefix(cfg.ExternalURL, "https://") {
		return nil, fmt.Errorf("IDENTREE_EXTERNAL_URL must start with http:// or https://")
	}
	if strings.ContainsAny(cfg.ExternalURL, `"'<>`) {
		return nil, fmt.Errorf("IDENTREE_EXTERNAL_URL contains invalid characters (must not contain quotes or angle brackets)")
	}
	if cfg.LDAPEnabled && cfg.LDAPBaseDN == "" {
		return nil, fmt.Errorf("IDENTREE_LDAP_BASE_DN is required when LDAP is enabled")
	}
	if len(cfg.LDAPBaseDN) > 512 {
		return nil, fmt.Errorf("IDENTREE_LDAP_BASE_DN must not exceed 512 characters")
	}

	// Validate LDAPDefaultShell: must be an absolute path and must not contain
	// shell metacharacters that could be misinterpreted by a shell or LDAP client.
	if cfg.LDAPDefaultShell != "" {
		if !strings.HasPrefix(cfg.LDAPDefaultShell, "/") {
			return nil, fmt.Errorf("IDENTREE_LDAP_DEFAULT_SHELL must be an absolute path (start with /)")
		}
		if strings.ContainsAny(cfg.LDAPDefaultShell, " \t\n\r\x00;|&$`'\"\\<>(){}*?[]!^%~@#") {
			return nil, fmt.Errorf("IDENTREE_LDAP_DEFAULT_SHELL contains invalid characters")
		}
	}

	// NotifyBackend must be one of the recognised values or empty (disabled).
	switch cfg.NotifyBackend {
	case "", "ntfy", "slack", "discord", "apprise", "webhook", "custom":
		// valid
	default:
		return nil, fmt.Errorf("IDENTREE_NOTIFY_BACKEND must be one of: ntfy, slack, discord, apprise, webhook, custom (got %q)", cfg.NotifyBackend)
	}

	// EscrowCommand and EscrowBackend are mutually exclusive.
	if cfg.EscrowCommand != "" && cfg.EscrowBackend != "" {
		return nil, fmt.Errorf("IDENTREE_ESCROW_COMMAND and IDENTREE_ESCROW_BACKEND are mutually exclusive; set only one")
	}

	// EscrowEncryptionKey must be at least 32 characters when using the local backend.
	if cfg.EscrowBackend == EscrowBackendLocal && len(cfg.EscrowEncryptionKey) < 32 {
		return nil, fmt.Errorf("IDENTREE_ESCROW_ENCRYPTION_KEY must be at least 32 characters when using the local escrow backend")
	}

	if cfg.EscrowBackend == EscrowBackendVault && cfg.EscrowPath != "" {
		for _, seg := range strings.Split(cfg.EscrowPath, "/") {
			if seg == ".." || seg == "." {
				return nil, fmt.Errorf("IDENTREE_ESCROW_PATH must not contain path traversal sequences (.. or .)")
			}
		}
	}

	// URL scheme validation: fields used in outbound HTTP requests must start with http:// or https://.
	for _, pair := range [][2]string{
		{"IDENTREE_OIDC_ISSUER_URL", cfg.IssuerURL},
		{"IDENTREE_OIDC_ISSUER_PUBLIC_URL", cfg.IssuerPublicURL},
		{"IDENTREE_POCKETID_API_URL", cfg.APIURL},
		{"IDENTREE_NOTIFY_URL", cfg.NotifyURL},
		{"IDENTREE_ESCROW_URL", cfg.EscrowURL},
		{"IDENTREE_ESCROW_WEB_URL", cfg.EscrowWebURL},
	} {
		if pair[1] != "" && !strings.HasPrefix(pair[1], "http://") && !strings.HasPrefix(pair[1], "https://") {
			return nil, fmt.Errorf("%s must start with http:// or https://", pair[0])
		}
	}

	// HostRegistryFile path traversal guard.
	for _, seg := range strings.Split(cfg.HostRegistryFile, "/") {
		if seg == ".." || seg == "." {
			return nil, fmt.Errorf("IDENTREE_HOST_REGISTRY_FILE must not contain path traversal sequences")
		}
	}

	// LDAPUIDBase/GIDBase must be >= 1000 to prevent collisions with system accounts (root is UID 0).
	if cfg.LDAPEnabled && cfg.LDAPUIDBase < 1000 {
		return nil, fmt.Errorf("IDENTREE_LDAP_UID_BASE must be >= 1000 (got %d); values below 1000 may collide with system UIDs", cfg.LDAPUIDBase)
	}
	if cfg.LDAPEnabled && cfg.LDAPGIDBase < 1000 {
		return nil, fmt.Errorf("IDENTREE_LDAP_GID_BASE must be >= 1000 (got %d); values below 1000 may collide with system GIDs", cfg.LDAPGIDBase)
	}

	// Reject half-configured LDAP bind credentials.
	if cfg.LDAPBindPassword != "" && cfg.LDAPBindDN == "" {
		return nil, fmt.Errorf("IDENTREE_LDAP_BIND_PASSWORD is set but IDENTREE_LDAP_BIND_DN is empty; both must be configured together")
	}
	if cfg.LDAPBindDN != "" && cfg.LDAPBindPassword == "" {
		return nil, fmt.Errorf("IDENTREE_LDAP_BIND_DN is set but IDENTREE_LDAP_BIND_PASSWORD is empty; both must be configured together")
	}

	// Warn if UID and GID bases overlap: UPG GIDs equal UIDs, so overlapping
	// bases cause UPG entries to collide with PocketID group GIDs.
	if cfg.LDAPEnabled && cfg.LDAPUIDBase == cfg.LDAPGIDBase {
		slog.Warn("IDENTREE_LDAP_UID_BASE and IDENTREE_LDAP_GID_BASE are identical — UPG gidNumbers will collide with PocketID group gidNumbers; set IDENTREE_LDAP_GID_BASE above the UID range")
	}

	// Validate LDAPSudoNoAuthenticate
	switch cfg.LDAPSudoNoAuthenticate {
	case SudoNoAuthTrue, SudoNoAuthFalse, SudoNoAuthClaims:
		// valid
	default:
		cfg.LDAPSudoNoAuthenticate = SudoNoAuthFalse
	}

	// Validate LDAPDefaultHome format pattern: at most one %s, no other printf verbs.
	// %% is a literal percent sign and is always allowed.
	if cfg.LDAPDefaultHome != "" {
		// Strip all %% sequences before checking, so they don't count as verbs.
		stripped := strings.ReplaceAll(cfg.LDAPDefaultHome, "%%", "")
		percentS := strings.Count(stripped, "%s")
		if percentS > 1 {
			return nil, fmt.Errorf("IDENTREE_LDAP_DEFAULT_HOME: pattern contains more than one %%s")
		}
		// Any remaining %<letter> that is not %s is invalid.
		if regexp.MustCompile(`%[a-zA-Z]`).ReplaceAllLiteralString(stripped, "%s") != stripped {
			// There is at least one %<letter> that is not %s — find it for a useful error.
			bad := regexp.MustCompile(`%[a-zA-Z]`).FindAllString(stripped, -1)
			var nonS []string
			for _, v := range bad {
				if v != "%s" {
					nonS = append(nonS, v)
				}
			}
			if len(nonS) > 0 {
				return nil, fmt.Errorf("IDENTREE_LDAP_DEFAULT_HOME: unsupported format verb(s) %v (only %%s is allowed)", nonS)
			}
		}
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
	if cfg.ServerURL != "" && !strings.HasPrefix(cfg.ServerURL, "http://") && !strings.HasPrefix(cfg.ServerURL, "https://") {
		return nil, fmt.Errorf("IDENTREE_SERVER_URL must start with http:// or https://")
	}

	// Clamp PollInterval: 0 or negative would cause a tight loop.
	if cfg.PollInterval < time.Second {
		cfg.PollInterval = 2 * time.Second
	}

	// Clamp BreakglassRotationDays: negative values are nonsensical.
	if cfg.BreakglassRotationDays < 1 {
		cfg.BreakglassRotationDays = 90
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


func stringDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
