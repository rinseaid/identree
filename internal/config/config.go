package config

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
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

// DefaultJustificationChoices is the built-in list of justification options
// shown in the approval UI when IDENTREE_JUSTIFICATION_CHOICES is not set.
var DefaultJustificationChoices = []string{
	"Routine maintenance",
	"Incident response",
	"Deployment",
	"Debugging / troubleshooting",
	"Security investigation",
	"Configuration change",
}

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

	// ── Auth protocol ─────────────────────────────────────────────────────────
	AuthProtocol string // "oidc" (default) or "saml"

	// ── SAML ──────────────────────────────────────────────────────────────────
	SAMLIdPMetadataURL  string // URL to fetch IdP metadata XML
	SAMLIdPMetadata     string // raw XML metadata (alternative to URL)
	SAMLEntityID        string // SP entity ID (default: ExternalURL)
	SAMLCertFile        string // path to SP certificate PEM
	SAMLKeyFile         string // path to SP private key PEM
	SAMLGroupsAttr      string // assertion attribute for groups (default: "groups")
	SAMLUsernameAttr    string // assertion attribute for username (default: "" = NameID)
	SAMLDisplayNameAttr string // assertion attribute for display name (default: "displayName")

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
	SharedSecret string // secret shared with PAM clients
	HMACSecret   string // optional separate secret for HMAC signing (session, CSRF, onetap, approval_status); defaults to SharedSecret when empty
	MetricsToken string // bearer token for /metrics endpoint (optional; empty = unauthenticated)

	// ── Session / auth flow ───────────────────────────────────────────────────
	ChallengeTTL time.Duration // how long a pending challenge lives (default 120s)
	GracePeriod  time.Duration // skip re-auth if approved within this window (default 0 = disabled)
	OneTapMaxAge time.Duration // max age of last OIDC auth for silent one-tap (default 24h)

	// RequireJustification enforces that every elevation approval includes a
	// justification selected from JustificationChoices (or entered as custom text).
	// When true, the dashboard and one-tap confirmation page block approval until
	// a reason is chosen, and POST /api/challenge also rejects requests with no reason.
	RequireJustification bool
	// JustificationChoices is the ordered list of preset justification options
	// presented in the approval UI. Defaults to DefaultJustificationChoices when empty.
	// Configurable via IDENTREE_JUSTIFICATION_CHOICES (comma-separated) or the admin UI.
	JustificationChoices []string

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

	// LDAPAllowAnonymous controls whether unauthenticated (anonymous) LDAP
	// binds are permitted. Defaults to false.
	// Set IDENTREE_LDAP_ALLOW_ANONYMOUS=true to allow unauthenticated searches.
	LDAPAllowAnonymous bool

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
	AdminGroups          []string // OIDC groups granting admin dashboard access
	ApprovalPoliciesFile string   // path to approval policies JSON file
	APIKeys              []string // API bearer tokens for programmatic access

	// ── Notifications ─────────────────────────────────────────────────────────
	// NotificationConfigFile is the path to the JSON file defining notification
	// channels and routing rules. Channels are named destinations (Slack, ntfy,
	// Discord, etc.); routes determine which events go to which channels.
	NotificationConfigFile string
	// AdminNotifyFile is the path to the JSON file storing per-admin notification
	// preferences (personal subscriptions to event channels).
	AdminNotifyFile string
	// NotifyTimeout is the default timeout for webhook delivery and command
	// execution. Individual channels can override this.
	NotifyTimeout time.Duration

	// ── Audit streaming ──────────────────────────────────────────────────────
	AuditLog          string // "stdout" | "file:/path/to/audit.jsonl" | "" (disabled)
	AuditSyslogURL    string // "udp://host:514" or "tcp://host:601"
	AuditSplunkHECURL string // Splunk HEC endpoint URL
	AuditSplunkToken  string // Splunk HEC token
	AuditLokiURL      string // Loki base URL (e.g. "http://loki:3100")
	AuditLokiToken    string // optional Loki bearer token
	AuditBufferSize   int    // channel buffer size (default 4096)
	AuditLogMaxSize   int    // max bytes per log file before rotation (default 100MB, 0 = no rotation)
	AuditLogMaxFiles  int    // number of rotated files to keep (default 5)

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
	// EscrowHKDFSalt is a hex-encoded salt (16+ bytes recommended) used in the
	// HKDF key derivation for the local escrow backend. When set, it diversifies
	// the derived key across deployments so two servers with the same
	// EscrowEncryptionKey still produce distinct subkeys.
	// NOTE: changing this value after enrollment invalidates all stored escrow
	// ciphertexts — clients must re-enroll (re-rotate break-glass passwords).
	EscrowHKDFSalt         string
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

	// ── Security options ──────────────────────────────────────────────────────
	// EnforceOIDCIPBinding makes the OIDC callback reject (not just warn) when
	// the callback IP differs from the login initiation IP. Disabled by default
	// because legitimate users behind NAT/load balancers can have different IPs.
	EnforceOIDCIPBinding bool

	// ── TLS server ──────────────────────────────────────────────────────────
	// When TLSCertFile and TLSKeyFile are set, the HTTP server listens on HTTPS
	// instead of plain HTTP. Required for mTLS (client certificate verification
	// needs Go's TLS termination to populate r.TLS.PeerCertificates).
	TLSCertFile string // path to server certificate PEM
	TLSKeyFile  string // path to server private key PEM

	// ── mTLS client authentication ──────────────────────────────────────────
	// MTLSEnabled is true when the embedded CA is configured. identree generates
	// a self-signed CA and issues client certificates at provision time.
	// Enabled automatically when MTLSCACert/MTLSCAKey are set (or auto-generated).
	MTLSEnabled bool
	MTLSCACert  string        // path to CA certificate PEM (may be auto-generated)
	MTLSCAKey   string        // path to CA private key PEM
	MTLSCertTTL time.Duration // client cert validity (default 365 days)

	// ── LDAP auto-provisioning ────────────────────────────────────────────────
	// When LDAPProvisionEnabled is true, GET /api/client/provision returns LDAP
	// configuration and per-host derived bind credentials so that `identree setup`
	// can auto-configure SSSD without manual admin intervention.
	LDAPProvisionEnabled bool
	// LDAPExternalURL is the LDAP URL returned to clients (e.g. ldap://ldap.example.com:389).
	// When empty, the server derives a URL from ExternalURL on port 389.
	LDAPExternalURL string
	// LDAPTLSCACert is an optional PEM-encoded CA certificate for LDAP TLS.
	// When set, it is included in the provision response so clients can verify
	// the LDAP server certificate without installing a system CA.
	LDAPTLSCACert string

	// ── Development / testing ─────────────────────────────────────────────────
	// DevLoginEnabled enables /dev/login?user=X&role=Y for bypassing OIDC in
	// local test environments. NEVER enable in production.
	DevLoginEnabled bool

	// ── State backend ───────────────────────────────────────────��────────────
	StateBackend        string        // "local" (default) | "redis"
	RedisURL            string        // redis://host:6379/0
	RedisPassword       string
	RedisPasswordFile   string
	RedisDB             int           // default 0
	RedisKeyPrefix      string        // default "identree:"
	RedisTLS            bool
	RedisTLSCACert      string        // PEM CA cert path
	RedisSentinelMaster string
	RedisSentinelAddrs  []string
	RedisClusterAddrs   []string
	RedisPoolSize       int           // default 50
	RedisDialTimeout    time.Duration // default 5s
	RedisReadTimeout    time.Duration // default 3s
	RedisWriteTimeout   time.Duration // default 3s
}

// DeriveLDAPBindPassword returns the per-host LDAP bind password for hostname.
// Derivation: HMAC-SHA256(HMAC-SHA256(sharedSecret, "ldap-bind"), hostname).
// The outer HMAC over hostname means each host gets a unique credential that
// rotates automatically when the shared secret rotates — no extra storage needed.
func DeriveLDAPBindPassword(sharedSecret, hostname string) string {
	subkey := deriveSubkey(sharedSecret, "ldap-bind")
	h := hmac.New(sha256.New, subkey)
	h.Write([]byte(hostname))
	return hex.EncodeToString(h.Sum(nil))
}

// deriveSubkey creates a purpose-specific HMAC-SHA256 subkey.
// Mirrors server.deriveKey but lives in config so both the server
// (provision endpoint) and ldap (bind handler) packages can use it.
func deriveSubkey(sharedSecret, purpose string) []byte {
	h := hmac.New(sha256.New, []byte(sharedSecret))
	h.Write([]byte(purpose))
	return h.Sum(nil)
}

// ClientConfig holds all configuration for identree in PAM client mode.
type ClientConfig struct {
	ServerURL    string
	SharedSecret string
	PollInterval time.Duration // default 2s
	Timeout      time.Duration // default 120s

	// mTLS client certificate paths (set by `identree setup` in embedded mode,
	// or manually in external mode).
	ClientCert string // path to client certificate PEM
	ClientKey  string // path to client private key PEM
	CACert     string // path to CA certificate PEM (for verifying the server)

	// Break-glass
	BreakglassEnabled        bool
	BreakglassFile           string // default /etc/identree-breakglass
	BreakglassRotationDays   int    // default 90
	BreakglassPasswordType   string // random, passphrase, alphanumeric
	BreakglassBcryptCost     int    // bcrypt cost for hashing break-glass passwords (default 12, min 10, max 31)
	InsecureAllowHTTPEscrow  bool   // allow escrow over plain HTTP (test environments only — never use in production)

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
	getBytes := func(key string, def int) int {
		v := get(key)
		if v == "" {
			return def
		}
		// Try plain integer first (raw bytes).
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
		// Parse human-friendly suffixes: "100MB", "50mb", "1GB", etc.
		v = strings.TrimSpace(strings.ToUpper(v))
		multiplier := 1
		switch {
		case strings.HasSuffix(v, "GB"):
			multiplier = 1024 * 1024 * 1024
			v = strings.TrimSuffix(v, "GB")
		case strings.HasSuffix(v, "MB"):
			multiplier = 1024 * 1024
			v = strings.TrimSuffix(v, "MB")
		case strings.HasSuffix(v, "KB"):
			multiplier = 1024
			v = strings.TrimSuffix(v, "KB")
		default:
			slog.Warn("config: invalid byte size, using default", "key", key, "value", get(key), "default", def)
			return def
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			slog.Warn("config: invalid byte size, using default", "key", key, "value", get(key), "default", def)
			return def
		}
		return n * multiplier
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

		AuthProtocol:        stringDefault(get("IDENTREE_AUTH_PROTOCOL"), "oidc"),
		SAMLIdPMetadataURL:  get("IDENTREE_SAML_IDP_METADATA_URL"),
		SAMLIdPMetadata:     get("IDENTREE_SAML_IDP_METADATA"),
		SAMLEntityID:        get("IDENTREE_SAML_ENTITY_ID"),
		SAMLCertFile:        get("IDENTREE_SAML_CERT_FILE"),
		SAMLKeyFile:         get("IDENTREE_SAML_KEY_FILE"),
		SAMLGroupsAttr:      stringDefault(get("IDENTREE_SAML_GROUPS_ATTR"), "groups"),
		SAMLUsernameAttr:    get("IDENTREE_SAML_USERNAME_ATTR"),
		SAMLDisplayNameAttr: stringDefault(get("IDENTREE_SAML_DISPLAY_NAME_ATTR"), "displayName"),

		APIKey:       get("IDENTREE_POCKETID_API_KEY"),
		APIURL:       get("IDENTREE_POCKETID_API_URL"),

		ListenAddr:   stringDefault(get("IDENTREE_LISTEN_ADDR"), ":8090"),
		ExternalURL:  get("IDENTREE_EXTERNAL_URL"),
		InstallURL:   get("IDENTREE_INSTALL_URL"),
		SharedSecret: get("IDENTREE_SHARED_SECRET"),
		HMACSecret:   get("IDENTREE_HMAC_SECRET"),
		MetricsToken: get("IDENTREE_METRICS_TOKEN"),

		ChallengeTTL:         getDuration("IDENTREE_CHALLENGE_TTL", 120*time.Second),
		GracePeriod:          getDuration("IDENTREE_GRACE_PERIOD", 0),
		OneTapMaxAge:         getDuration("IDENTREE_ONE_TAP_MAX_AGE", 24*time.Hour),
		RequireJustification: getBool("IDENTREE_REQUIRE_JUSTIFICATION", false),
		JustificationChoices: getSlice("IDENTREE_JUSTIFICATION_CHOICES"),

		LDAPEnabled:            getBool("IDENTREE_LDAP_ENABLED", true),
		LDAPListenAddr:         stringDefault(get("IDENTREE_LDAP_LISTEN_ADDR"), ":389"),
		LDAPBaseDN:             get("IDENTREE_LDAP_BASE_DN"),
		LDAPBindDN:             get("IDENTREE_LDAP_BIND_DN"),
		LDAPBindPassword:       get("IDENTREE_LDAP_BIND_PASSWORD"),
		LDAPRefreshInterval:    getDuration("IDENTREE_LDAP_REFRESH_INTERVAL", 300*time.Second),
		LDAPUIDMapFile:         stringDefault(get("IDENTREE_LDAP_UID_MAP_FILE"), "/config/uidmap.json"),
		LDAPSudoNoAuthenticate: SudoNoAuthenticate(stringDefault(get("IDENTREE_LDAP_SUDO_NO_AUTHENTICATE"), "false")),
		LDAPAllowAnonymous:     getBool("IDENTREE_LDAP_ALLOW_ANONYMOUS", false),
		SudoRulesFile:          stringDefault(get("IDENTREE_SUDO_RULES_FILE"), "/config/sudorules.json"),
		LDAPUIDBase:            getInt("IDENTREE_LDAP_UID_BASE", 200000),
		LDAPGIDBase:            getInt("IDENTREE_LDAP_GID_BASE", 200000),
		LDAPDefaultShell:       get("IDENTREE_LDAP_DEFAULT_SHELL"),
		LDAPDefaultHome:        get("IDENTREE_LDAP_DEFAULT_HOME"),

		AdminGroups:          getSlice("IDENTREE_ADMIN_GROUPS"),
		ApprovalPoliciesFile: stringDefault(get("IDENTREE_APPROVAL_POLICIES_FILE"), "/config/approval-policies.json"),
		APIKeys:              getSlice("IDENTREE_API_KEYS"),

		NotificationConfigFile: stringDefault(get("IDENTREE_NOTIFICATION_CONFIG_FILE"), "/config/notification-channels.json"),
		AdminNotifyFile:        stringDefault(get("IDENTREE_ADMIN_NOTIFY_FILE"), "/config/admin-notifications.json"),
		NotifyTimeout:          getDuration("IDENTREE_NOTIFY_TIMEOUT", 15*time.Second),

		AuditLog:          get("IDENTREE_AUDIT_LOG"),
		AuditSyslogURL:    get("IDENTREE_AUDIT_SYSLOG_URL"),
		AuditSplunkHECURL: get("IDENTREE_AUDIT_SPLUNK_HEC_URL"),
		AuditSplunkToken:  get("IDENTREE_AUDIT_SPLUNK_TOKEN"),
		AuditLokiURL:      get("IDENTREE_AUDIT_LOKI_URL"),
		AuditLokiToken:    get("IDENTREE_AUDIT_LOKI_TOKEN"),
		AuditBufferSize:   getInt("IDENTREE_AUDIT_BUFFER_SIZE", 4096),
		AuditLogMaxSize:   getBytes("IDENTREE_AUDIT_LOG_MAX_SIZE", 100*1024*1024),
		AuditLogMaxFiles:  getInt("IDENTREE_AUDIT_LOG_MAX_FILES", 5),

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
		EscrowHKDFSalt:       get("IDENTREE_ESCROW_HKDF_SALT"),

		HostRegistryFile:       stringDefault(get("IDENTREE_HOST_REGISTRY_FILE"), "/config/hosts.json"),
		DefaultPageSize: getInt("IDENTREE_DEFAULT_PAGE_SIZE", 15),
		SessionStateFile:       stringDefault(get("IDENTREE_SESSION_STATE_FILE"), "/config/sessions.json"),

		ClientPollInterval:           getDuration("IDENTREE_CLIENT_POLL_INTERVAL", 0),
		ClientTimeout:                getDuration("IDENTREE_CLIENT_TIMEOUT", 0),
		ClientBreakglassPasswordType: get("IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE"),
		ClientBreakglassRotationDays: getInt("IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS", 0),

		TLSCertFile: get("IDENTREE_TLS_CERT_FILE"),
		TLSKeyFile:  get("IDENTREE_TLS_KEY_FILE"),

		MTLSCACert:  get("IDENTREE_MTLS_CA_CERT"),
		MTLSCAKey:   get("IDENTREE_MTLS_CA_KEY"),
		MTLSCertTTL: getDuration("IDENTREE_MTLS_CERT_TTL", 365*24*time.Hour),

		WebhookSecret:        get("IDENTREE_WEBHOOK_SECRET"),
		EnforceOIDCIPBinding: getBool("IDENTREE_OIDC_ENFORCE_IP_BINDING", false),
		DevLoginEnabled:      getBool("IDENTREE_DEV_LOGIN", false),

		LDAPProvisionEnabled: getBool("IDENTREE_LDAP_PROVISION_ENABLED", false),
		LDAPExternalURL:      get("IDENTREE_LDAP_EXTERNAL_URL"),
		LDAPTLSCACert:        get("IDENTREE_LDAP_TLS_CA_CERT"),

		StateBackend:        stringDefault(get("IDENTREE_STATE_BACKEND"), "local"),
		RedisURL:            get("IDENTREE_REDIS_URL"),
		RedisPassword:       get("IDENTREE_REDIS_PASSWORD"),
		RedisPasswordFile:   get("IDENTREE_REDIS_PASSWORD_FILE"),
		RedisDB:             getInt("IDENTREE_REDIS_DB", 0),
		RedisKeyPrefix:      stringDefault(get("IDENTREE_REDIS_KEY_PREFIX"), "identree:"),
		RedisTLS:            getBool("IDENTREE_REDIS_TLS", false),
		RedisTLSCACert:      get("IDENTREE_REDIS_TLS_CA_CERT"),
		RedisSentinelMaster: get("IDENTREE_REDIS_SENTINEL_MASTER"),
		RedisSentinelAddrs:  getSlice("IDENTREE_REDIS_SENTINEL_ADDRS"),
		RedisClusterAddrs:   getSlice("IDENTREE_REDIS_CLUSTER_ADDRS"),
		RedisPoolSize:       getInt("IDENTREE_REDIS_POOL_SIZE", 50),
		RedisDialTimeout:    getDuration("IDENTREE_REDIS_DIAL_TIMEOUT", 5*time.Second),
		RedisReadTimeout:    getDuration("IDENTREE_REDIS_READ_TIMEOUT", 3*time.Second),
		RedisWriteTimeout:   getDuration("IDENTREE_REDIS_WRITE_TIMEOUT", 3*time.Second),
	}

	// Backward compatibility: accept old env var names with deprecation warnings.
	if cfg.LDAPSudoNoAuthenticate == SudoNoAuthenticate("false") {
		if v := get("IDENTREE_SUDO_NO_AUTHENTICATE"); v != "" && get("IDENTREE_LDAP_SUDO_NO_AUTHENTICATE") == "" {
			slog.Warn("config: IDENTREE_SUDO_NO_AUTHENTICATE is deprecated, use IDENTREE_LDAP_SUDO_NO_AUTHENTICATE instead")
			cfg.LDAPSudoNoAuthenticate = SudoNoAuthenticate(v)
		}
	}
	if cfg.DefaultPageSize == 15 {
		if v := get("IDENTREE_HISTORY_PAGE_SIZE"); v != "" && get("IDENTREE_DEFAULT_PAGE_SIZE") == "" {
			slog.Warn("config: IDENTREE_HISTORY_PAGE_SIZE is deprecated, use IDENTREE_DEFAULT_PAGE_SIZE instead")
			cfg.DefaultPageSize = getInt("IDENTREE_HISTORY_PAGE_SIZE", 15)
		}
	}

	// Warn if SessionStateFile is unset — grace sessions, revocations, and audit log will not persist.
	if cfg.SessionStateFile == "" {
		slog.Warn("IDENTREE_SESSION_STATE_FILE is not set — grace sessions, revocations, and audit log will be lost on restart")
	}

	// Clamp LDAPRefreshInterval: 0 or negative would panic time.NewTicker.
	// Minimum 10 seconds to prevent hammering the PocketID API.
	if cfg.LDAPRefreshInterval <= 0 {
		slog.Warn("config: IDENTREE_LDAP_REFRESH_INTERVAL must be positive; using default 300s", "value", cfg.LDAPRefreshInterval)
		cfg.LDAPRefreshInterval = 300 * time.Second
	} else if cfg.LDAPRefreshInterval < 10*time.Second {
		slog.Warn("config: IDENTREE_LDAP_REFRESH_INTERVAL too low; clamping to 10s", "value", cfg.LDAPRefreshInterval)
		cfg.LDAPRefreshInterval = 10 * time.Second
	}

	// LDAP shell and home directory defaults.
	if cfg.LDAPEnabled {
		if cfg.LDAPDefaultShell == "" {
			cfg.LDAPDefaultShell = "/bin/bash"
			slog.Warn("IDENTREE_LDAP_DEFAULT_SHELL is not set — defaulting to /bin/bash")
		}
		if cfg.LDAPDefaultHome == "" {
			cfg.LDAPDefaultHome = "/home/%s"
			slog.Warn("IDENTREE_LDAP_DEFAULT_HOME is not set — defaulting to /home/%s")
		}
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

	// Client bool overrides — *bool fields (nil = no override, non-nil = override).
	if v := get("IDENTREE_CLIENT_TOKEN_CACHE_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.ClientTokenCacheEnabled = &b
		} else {
			slog.Warn("config: invalid boolean value, field left unset", "key", "IDENTREE_CLIENT_TOKEN_CACHE_ENABLED", "value", v)
		}
	}
	if v := get("IDENTREE_CLIENT_BREAKGLASS_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.ClientBreakglassEnabled = &b
		} else {
			slog.Warn("config: invalid boolean value, field left unset", "key", "IDENTREE_CLIENT_BREAKGLASS_ENABLED", "value", v)
		}
	}

	// BreakglassRotateBefore
	if v := get("IDENTREE_BREAKGLASS_ROTATE_BEFORE"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			cfg.BreakglassRotateBefore = t
		} else {
			slog.Error("config: invalid RFC3339 timestamp for IDENTREE_BREAKGLASS_ROTATE_BEFORE, field left unset", "value", v, "error", err)
		}
	}

	// Clamp ChallengeTTL to sane bounds (30s–24h), matching live-update range.
	if cfg.ChallengeTTL < 30*time.Second {
		cfg.ChallengeTTL = 30 * time.Second
	}
	if cfg.ChallengeTTL > 86400*time.Second {
		cfg.ChallengeTTL = 86400 * time.Second
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

	// Validate AuthProtocol.
	switch cfg.AuthProtocol {
	case "", "oidc":
		cfg.AuthProtocol = "oidc"
	case "saml":
		if cfg.SAMLIdPMetadataURL == "" && cfg.SAMLIdPMetadata == "" {
			return nil, fmt.Errorf("IDENTREE_SAML_IDP_METADATA_URL or IDENTREE_SAML_IDP_METADATA must be set when IDENTREE_AUTH_PROTOCOL=saml")
		}
		if cfg.SAMLEntityID == "" {
			cfg.SAMLEntityID = strings.TrimRight(cfg.ExternalURL, "/")
		}
	default:
		return nil, fmt.Errorf("IDENTREE_AUTH_PROTOCOL must be \"oidc\" or \"saml\" (got %q)", cfg.AuthProtocol)
	}

	// Enable mTLS when CA cert/key paths are configured (or default them).
	// Also accept the legacy IDENTREE_MTLS_MODE=embedded as a trigger.
	if cfg.MTLSCACert != "" || cfg.MTLSCAKey != "" || get("IDENTREE_MTLS_MODE") == "embedded" {
		cfg.MTLSEnabled = true
		if cfg.MTLSCACert == "" {
			cfg.MTLSCACert = "/config/mtls-ca.crt"
		}
		if cfg.MTLSCAKey == "" {
			cfg.MTLSCAKey = "/config/mtls-ca.key"
		}
		if cfg.MTLSCertTTL <= 0 {
			cfg.MTLSCertTTL = 365 * 24 * time.Hour
		}
	}

	// Warn when mTLS is enabled but the server has no TLS config. Without TLS,
	// r.TLS will be nil and client certificates will never be available.
	if cfg.MTLSEnabled && (cfg.TLSCertFile == "" || cfg.TLSKeyFile == "") {
		slog.Warn("mTLS is enabled but IDENTREE_TLS_CERT_FILE/IDENTREE_TLS_KEY_FILE are not set — client certificate verification requires TLS termination by identree (set TLS cert/key or use a reverse proxy that forwards client certs)")
	}

	// Validate StateBackend.
	switch cfg.StateBackend {
	case "", "local":
		cfg.StateBackend = "local"
	case "redis":
		if cfg.RedisURL == "" && len(cfg.RedisClusterAddrs) == 0 {
			return nil, fmt.Errorf("IDENTREE_REDIS_URL or IDENTREE_REDIS_CLUSTER_ADDRS must be set when IDENTREE_STATE_BACKEND=redis")
		}
	default:
		return nil, fmt.Errorf("IDENTREE_STATE_BACKEND must be \"local\" or \"redis\" (got %q)", cfg.StateBackend)
	}

	// Load Redis password from file if RedisPasswordFile is set and RedisPassword is empty.
	if cfg.RedisPasswordFile != "" && cfg.RedisPassword == "" {
		for _, seg := range strings.Split(cfg.RedisPasswordFile, "/") {
			if seg == ".." || seg == "." {
				return nil, fmt.Errorf("IDENTREE_REDIS_PASSWORD_FILE must not contain path traversal sequences")
			}
		}
		if data, err := os.ReadFile(cfg.RedisPasswordFile); err == nil {
			cfg.RedisPassword = strings.TrimSpace(string(data))
		}
	}

	// Validate required fields — OIDC fields only required when using OIDC protocol.
	if cfg.AuthProtocol != "saml" {
		if cfg.IssuerURL == "" && !cfg.DevLoginEnabled {
			return nil, fmt.Errorf("IDENTREE_OIDC_ISSUER_URL is required")
		}
		if cfg.ClientID == "" && !cfg.DevLoginEnabled {
			return nil, fmt.Errorf("IDENTREE_OIDC_CLIENT_ID is required")
		}
		if cfg.ClientSecret == "" && !cfg.DevLoginEnabled {
			return nil, fmt.Errorf("IDENTREE_OIDC_CLIENT_SECRET is required")
		}
	}
	// SharedSecret is required unless mTLS is enabled (mTLS replaces shared-secret auth).
	if !cfg.MTLSEnabled {
		if cfg.SharedSecret == "" {
			return nil, fmt.Errorf("IDENTREE_SHARED_SECRET is required (or configure IDENTREE_MTLS_CA_CERT/KEY to use mTLS instead)")
		}
		if len(cfg.SharedSecret) < 32 {
			return nil, fmt.Errorf("IDENTREE_SHARED_SECRET must be at least 32 characters")
		}
	}
	if cfg.WebhookSecret != "" && len(cfg.WebhookSecret) < 32 {
		return nil, fmt.Errorf("IDENTREE_WEBHOOK_SECRET must be at least 32 characters when set")
	}
	for i, key := range cfg.APIKeys {
		if len(key) < 32 {
			return nil, fmt.Errorf("IDENTREE_API_KEYS entry %d must be at least 32 characters", i+1)
		}
	}
	if cfg.ExternalURL == "" {
		return nil, fmt.Errorf("IDENTREE_EXTERNAL_URL is required")
	}
	if u, err := url.Parse(cfg.ExternalURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("IDENTREE_EXTERNAL_URL must be a valid http:// or https:// URL with a non-empty host (got %q)", cfg.ExternalURL)
	}
	if strings.ContainsAny(cfg.ExternalURL, `"'<>`) {
		return nil, fmt.Errorf("IDENTREE_EXTERNAL_URL contains invalid characters (must not contain quotes or angle brackets)")
	}
	if cfg.DevLoginEnabled && strings.HasPrefix(cfg.ExternalURL, "https://") {
		return nil, fmt.Errorf("IDENTREE_DEV_LOGIN must not be enabled when IDENTREE_EXTERNAL_URL is https:// — this bypass must never be used in production")
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

	// Warn if EscrowAuthSecret is set but too short.
	if cfg.EscrowAuthSecret != "" && len(cfg.EscrowAuthSecret) < 16 {
		slog.Warn("IDENTREE_ESCROW_AUTH_SECRET is set but shorter than 16 characters; consider using a longer secret for better security")
	}

	// EscrowCommand and EscrowBackend are mutually exclusive.
	if cfg.EscrowCommand != "" && cfg.EscrowBackend != "" {
		return nil, fmt.Errorf("IDENTREE_ESCROW_COMMAND and IDENTREE_ESCROW_BACKEND are mutually exclusive; set only one")
	}

	// EscrowEncryptionKey must be at least 32 characters when using the local backend.
	if cfg.EscrowBackend == EscrowBackendLocal && len(cfg.EscrowEncryptionKey) < 32 {
		return nil, fmt.Errorf("IDENTREE_ESCROW_ENCRYPTION_KEY must be at least 32 characters when using the local escrow backend")
	}

	// Validate EscrowHKDFSalt: must be valid hex and at least 32 hex chars (16 bytes) when set.
	if cfg.EscrowHKDFSalt != "" {
		decoded, err := hex.DecodeString(cfg.EscrowHKDFSalt)
		if err != nil {
			return nil, fmt.Errorf("IDENTREE_ESCROW_HKDF_SALT must be a valid hex-encoded string: %w", err)
		}
		if len(decoded) < 16 {
			return nil, fmt.Errorf("IDENTREE_ESCROW_HKDF_SALT must decode to at least 16 bytes (got %d)", len(decoded))
		}
	}

	if cfg.EscrowBackend == EscrowBackendVault && cfg.EscrowPath != "" {
		for _, seg := range strings.Split(cfg.EscrowPath, "/") {
			if seg == ".." || seg == "." {
				return nil, fmt.Errorf("IDENTREE_ESCROW_PATH must not contain path traversal sequences (.. or .)")
			}
		}
	}

	// URL scheme validation: fields used in outbound HTTP requests must be valid http:// or https:// URLs.
	for _, pair := range [][2]string{
		{"IDENTREE_OIDC_ISSUER_URL", cfg.IssuerURL},
		{"IDENTREE_OIDC_ISSUER_PUBLIC_URL", cfg.IssuerPublicURL},
		{"IDENTREE_POCKETID_API_URL", cfg.APIURL},
		// Notification URLs are validated per-channel at load time, not here.
		{"IDENTREE_ESCROW_URL", cfg.EscrowURL},
		{"IDENTREE_ESCROW_WEB_URL", cfg.EscrowWebURL},
	} {
		if pair[1] == "" {
			continue
		}
		u, err := url.Parse(pair[1])
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("%s must be a valid http:// or https:// URL with a non-empty host (got %q)", pair[0], pair[1])
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

	// Log anonymous LDAP status at startup so operators know the current posture.
	if cfg.LDAPEnabled && !cfg.LDAPAllowAnonymous {
		slog.Info("ldap: anonymous bind disabled; set IDENTREE_LDAP_ALLOW_ANONYMOUS=true to allow unauthenticated searches")
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

		ClientCert: get("IDENTREE_CLIENT_CERT"),
		ClientKey:  get("IDENTREE_CLIENT_KEY"),
		CACert:     get("IDENTREE_CA_CERT"),

		BreakglassEnabled:       getBool(true, "IDENTREE_BREAKGLASS_ENABLED", "PAM_POCKETID_BREAKGLASS_ENABLED"),
		BreakglassFile:          stringDefault(get("IDENTREE_BREAKGLASS_FILE", "PAM_POCKETID_BREAKGLASS_FILE"), "/etc/identree-breakglass"),
		BreakglassRotationDays:  getInt(90, "IDENTREE_BREAKGLASS_ROTATION_DAYS", "PAM_POCKETID_BREAKGLASS_ROTATION_DAYS"),
		BreakglassPasswordType:  stringDefault(get("IDENTREE_BREAKGLASS_PASSWORD_TYPE", "PAM_POCKETID_BREAKGLASS_PASSWORD_TYPE"), "random"),
		BreakglassBcryptCost:    getInt(12, "IDENTREE_BREAKGLASS_BCRYPT_COST"),
		InsecureAllowHTTPEscrow: getBool(false, "IDENTREE_INSECURE_ALLOW_HTTP_ESCROW"),

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

	// Clamp BreakglassBcryptCost to safe bounds (min 10, max 31).
	if cfg.BreakglassBcryptCost < 10 {
		cfg.BreakglassBcryptCost = 12
	}
	if cfg.BreakglassBcryptCost > 31 {
		cfg.BreakglassBcryptCost = 31
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
