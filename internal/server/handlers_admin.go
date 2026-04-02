package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/pocketid"
	"golang.org/x/crypto/ssh"
)

var sshKeyClaimPattern = regexp.MustCompile(`^sshPublicKey\d*$`)
var validAdminIDPattern = regexp.MustCompile(`^[a-fA-F0-9-]{1,128}$`)
var validLoginShellPattern = regexp.MustCompile(`^/[a-zA-Z0-9/_.-]+$`)

// liveUpdateKeys are env keys applied immediately by applyLiveConfigUpdates — no restart needed.
var liveUpdateKeys = map[string]bool{
	"IDENTREE_CHALLENGE_TTL":                   true,
	"IDENTREE_GRACE_PERIOD":                    true,
	"IDENTREE_ONE_TAP_MAX_AGE":                 true,
	"IDENTREE_ADMIN_GROUPS":                    true,
	"IDENTREE_ADMIN_APPROVAL_HOSTS":            true,
	"IDENTREE_NOTIFY_BACKEND":                  true,
	"IDENTREE_NOTIFY_URL":                      true,
	// IDENTREE_NOTIFY_COMMAND is intentionally excluded from live-update keys.
	// It executes arbitrary shell commands as the identree process user; allowing
	// admins to change it without a process restart (and without OS-level access)
	// would let any admin silently install persistence. Set via env var only,
	// like IDENTREE_ESCROW_COMMAND.
	"IDENTREE_NOTIFY_TIMEOUT":                  true,
	"IDENTREE_ESCROW_BACKEND":                  true,
	"IDENTREE_ESCROW_URL":                      true,
	"IDENTREE_ESCROW_AUTH_ID":                  true,
	"IDENTREE_ESCROW_PATH":                     true,
	"IDENTREE_ESCROW_WEB_URL":                  true,
	"IDENTREE_CLIENT_POLL_INTERVAL":            true,
	"IDENTREE_CLIENT_TIMEOUT":                  true,
	"IDENTREE_CLIENT_BREAKGLASS_ENABLED":       true,
	"IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE": true,
	"IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS": true,
	"IDENTREE_CLIENT_TOKEN_CACHE_ENABLED":      true,
	"IDENTREE_DEFAULT_PAGE_SIZE":               true,
	"IDENTREE_LDAP_SUDO_NO_AUTHENTICATE":       true,
	"IDENTREE_LDAP_DEFAULT_SHELL":              true,
	"IDENTREE_LDAP_DEFAULT_HOME":               true,
	"IDENTREE_LDAP_ALLOW_ANONYMOUS":            true,
}

var configSectionLabels = map[string]string{
	"oidc":           "OIDC Authentication",
	"pocketid":       "PocketID API",
	"server":         "Server",
	"auth":           "Authentication",
	"ldap":           "LDAP",
	"admin":          "Admin Access",
	"notifications":  "Notifications",
	"escrow":         "Break-Glass Escrow",
	"client_defaults": "Client Defaults",
	"misc":           "Miscellaneous",
}

// findRestartSections returns display names of sections that have changed values
// requiring a server restart (i.e. not in liveUpdateKeys).
func findRestartSections(submitted, current map[string]string) []string {
	changed := map[string]bool{}
	for k, v := range submitted {
		if !config.IsEnvSourced(k) && !liveUpdateKeys[k] && v != current[k] {
			changed[k] = true
		}
	}
	if len(changed) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var sections []string
	for _, sec := range config.TOMLSections {
		for _, fld := range sec.Fields {
			if changed[fld.EnvKey] && !seen[sec.Name] {
				seen[sec.Name] = true
				label := configSectionLabels[sec.Name]
				if label == "" {
					label = sec.Name
				}
				sections = append(sections, label)
			}
		}
	}
	return sections
}

// editableUserClaims are simple string claims identree can write directly on a user.
// SSH keys are handled separately (multi-value, numbered).
var editableUserClaims = []string{"loginShell", "homeDirectory"}

func isEditableUserClaim(key string) bool {
	for _, k := range editableUserClaims {
		if k == key {
			return true
		}
	}
	return false
}

// editableGroupClaims are the only claim keys identree can write to groups.
var editableGroupClaims = []string{"sudoCommands", "sudoHosts", "sudoRunAsUser", "sudoRunAsGroup", "sudoOptions", "accessHosts"}

func isEditableGroupClaim(key string) bool {
	for _, k := range editableGroupClaims {
		if k == key {
			return true
		}
	}
	return false
}

// deriveEscrowLink returns a web UI link for the stored escrow item based on the
// configured native backend. Returns "" when no link can be derived.
//
// For 1password-connect, webURL must be set to the 1Password web app URL
// including the account UUID fragment, e.g.:
//
//	https://my.1password.com/app#/ACCOUNTUUID
//
// The account UUID is extracted from the fragment and combined with the
// resolved vault UUID (stored in vaultID) and item UUID to form a direct link.
func deriveEscrowLink(backend, escrowURL, escrowPath, itemID, vaultID, webURL, hostname string) string {
	base := strings.TrimRight(escrowURL, "/")
	// Reject non-http(s) schemes to prevent javascript: or data: URIs in link hrefs.
	if escrowURL != "" && !strings.HasPrefix(escrowURL, "http://") && !strings.HasPrefix(escrowURL, "https://") {
		return ""
	}
	if webURL != "" && !strings.HasPrefix(webURL, "http://") && !strings.HasPrefix(webURL, "https://") {
		return ""
	}
	switch backend {
	case "1password-connect":
		// Requires ESCROW_WEB_URL = https://my.1password.com/app#/ACCOUNTUUID
		// Link format: {webURL}/Vault/{accountUUID}:{vaultUUID}:{itemUUID}
		if webURL == "" || itemID == "" || vaultID == "" {
			return ""
		}
		parsed, err := url.Parse(webURL)
		if err != nil {
			return ""
		}
		accountUUID := strings.TrimLeft(parsed.Fragment, "/")
		if accountUUID == "" {
			return ""
		}
		return fmt.Sprintf("%s/Vault/%s:%s:%s", strings.TrimRight(webURL, "/"), accountUUID, vaultID, itemID)
	case "vault":
		// HashiCorp Vault UI: /ui/vault/secrets/{mount}/kv/{prefix}/{hostname}/details
		mount, prefix, hasPrefix := strings.Cut(escrowPath, "/")
		if hasPrefix {
			return fmt.Sprintf("%s/ui/vault/secrets/%s/kv/%s/%s/details", base, mount, prefix, hostname)
		}
		return fmt.Sprintf("%s/ui/vault/secrets/%s/kv/%s/details", base, mount, hostname)
	case "bitwarden":
		// Bitwarden SM: vault.bitwarden.com/#/sm/{orgId}/secrets/{itemId}
		// API URL may be "https://api.bitwarden.com" or "https://bw.example.com/api"
		orgID, _, _ := strings.Cut(escrowPath, "/")
		webBase := strings.TrimSuffix(base, "/api")
		webBase = strings.ReplaceAll(webBase, "://api.", "://vault.")
		if itemID != "" {
			return fmt.Sprintf("%s/#/sm/%s/secrets/%s", webBase, orgID, itemID)
		}
		return fmt.Sprintf("%s/#/sm/%s/secrets", webBase, orgID)
	case "infisical":
		// Infisical: {base}/{workspaceId}/secrets/{environment}
		workspaceID, env, _ := strings.Cut(escrowPath, "/")
		if workspaceID == "" {
			return ""
		}
		if env != "" {
			return fmt.Sprintf("%s/%s/secrets/%s", base, workspaceID, env)
		}
		return fmt.Sprintf("%s/%s/secrets", base, workspaceID)
	}
	// Custom escrow commands: no web UI link available
	return ""
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	var failing []string

	if s.cfg.LDAPEnabled {
		interval := s.cfg.LDAPRefreshInterval
		if interval <= 0 {
			interval = 5 * time.Minute
		}
		s.ldapLastSyncMu.RLock()
		last := s.ldapLastSync
		s.ldapLastSyncMu.RUnlock()
		if !last.IsZero() && time.Since(last) > 2*interval {
			failing = append(failing, `"ldap":"stale"`)
		}
	}

	if path := s.cfg.SessionStateFile; path != "" {
		// Cache the filesystem writability check for 10 seconds to avoid
		// continuous disk I/O when the endpoint is polled by a load balancer.
		s.healthzMu.Lock()
		stateOK := s.healthzStateOK
		if time.Since(s.healthzLast) > 10*time.Second {
			dir := filepath.Dir(path)
			tmp, err := os.CreateTemp(dir, ".healthz-*")
			if err != nil {
				stateOK = false
			} else {
				tmp.Close()
				os.Remove(tmp.Name())
				stateOK = true
			}
			s.healthzStateOK = stateOK
			s.healthzLast = time.Now()
		}
		s.healthzMu.Unlock()
		if !stateOK {
			failing = append(failing, `"state_file":"not_writable"`)
		}
	}

	if len(failing) > 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"degraded","checks":{` + strings.Join(failing, ",") + `}}`))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}


// handleAdmin renders the admin overview page at /admin.
// GET /admin
func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// handleAdminInfo shows system information.
// GET /admin/info
func (s *Server) handleAdminInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if setLanguageCookie(w, r) {
		return
	}
	lang := detectLanguage(r)
	t := T(lang)

	username := s.getSessionUser(r)
	if username == "" {
		s.setFlashCookie(w, "expired:")
		http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
		return
	}
	role := s.getSessionRole(r)
	if role != "admin" {
		http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, username, role)

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	adminTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err := time.LoadLocation(c.Value); err == nil {
			adminTZ = c.Value
		}
	}

	infoCSRFTs := strconv.FormatInt(time.Now().Unix(), 10)
	infoCSRFToken := computeCSRFToken(s.cfg.SharedSecret, username, infoCSRFTs)

	w.Header().Set("Content-Type", "text/html")
	if err := adminTmpl.Execute(w, map[string]interface{}{
		"Username":            username,
		"Initial":             strings.ToUpper(username[:1]),
		"Avatar":              getAvatar(r),
		"Timezone":            adminTZ,
		"Flashes":             []string(nil),
		"FlashErrors":         []string(nil),
		"ActivePage":          "admin",
		"AdminTab":            "info",
		"BridgeMode":          s.isBridgeMode(),
		"DefaultPageSize":     s.cfg.DefaultPageSize,
		"Theme":               getTheme(r),
		"CSPNonce":            cspNonce(r),
		"T":                   t,
		"Lang":                lang,
		"Languages":           supportedLanguages,
		"IsAdmin":             true,
		"CSRFToken":           infoCSRFToken,
		"CSRFTs":              infoCSRFTs,
		"Pending":             s.buildPendingViews(username, lang),
		"AllPendingQueue":     s.buildAllPendingViews(lang),
		"Version":             version,
		"CommitShort":         commitShort(commit),
		"Commit":              commit,
		"Uptime":              formatDuration(t, time.Since(serverStartTime)),
		"GoVersion":           runtime.Version(),
		"OSArch":              runtime.GOOS + "/" + runtime.GOARCH,
		"Goroutines":          runtime.NumGoroutine(),
		"MemUsage":            fmt.Sprintf("%.1f MB alloc / %.1f MB sys", float64(memStats.Alloc)/1024/1024, float64(memStats.Sys)/1024/1024),
		"ActiveSessionsCount": len(s.store.AllActiveSessions()),
		"LDAPSyncError":       s.ldapSyncError(),
	}); err != nil {
		slog.Error("template execution", "err", err)
	}
}

// handleAdminConfig shows and processes the server configuration page.
// GET /admin/config — render config form
// POST /admin/config — save config to TOML, apply live changes
func (s *Server) handleAdminConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if setLanguageCookie(w, r) {
		return
	}
	lang := detectLanguage(r)
	t := T(lang)

	username := s.getSessionUser(r)
	if username == "" {
		s.setFlashCookie(w, "expired:")
		http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
		return
	}
	role := s.getSessionRole(r)
	if role != "admin" {
		http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, username, role)

	if r.Method == http.MethodPost {
		// Custom form auth with 64 KB body limit (config form exceeds default 8 KB).
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		if err := r.ParseForm(); err != nil {
			revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_form")
			return
		}
		formUser := r.FormValue("username")
		csrfToken := r.FormValue("csrf_token")
		csrfTs := r.FormValue("csrf_ts")
		if formUser == "" || csrfToken == "" || csrfTs == "" {
			revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
			return
		}
		if !validUsername.MatchString(formUser) {
			revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_username_format")
			return
		}
		if s.getSessionUser(r) != formUser {
			revokeErrorPage(w, r, http.StatusForbidden, "session_expired", "session_expired_sign_in")
			return
		}
		tsInt, err := strconv.ParseInt(csrfTs, 10, 64)
		if err != nil {
			revokeErrorPage(w, r, http.StatusForbidden, "form_expired", "form_expired_message")
			return
		}
		if age := time.Since(time.Unix(tsInt, 0)); age < 0 || age > 5*time.Minute {
			revokeErrorPage(w, r, http.StatusForbidden, "form_expired", "form_expired_message")
			return
		}
		expected := computeCSRFToken(s.cfg.SharedSecret, formUser, csrfTs)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(csrfToken)) != 1 {
			revokeErrorPage(w, r, http.StatusForbidden, "invalid_request", "invalid_csrf")
			return
		}

		// Collect non-locked form values.
		values := make(map[string]string)
		for _, sec := range config.TOMLSections {
			for _, fld := range sec.Fields {
				if config.IsEnvSourced(fld.EnvKey) {
					continue
				}
				if fld.IsBool {
					v := r.FormValue(fld.EnvKey)
					if v == "true" || v == "on" {
						values[fld.EnvKey] = "true"
					} else {
						values[fld.EnvKey] = "false"
					}
				} else {
					values[fld.EnvKey] = strings.TrimSpace(r.FormValue(fld.EnvKey))
				}
			}
		}

		// Validate.
		if err := validateConfigValues(values, s.cfg); err != nil {
			s.setFlashCookie(w, "config_error:"+url.QueryEscape(err.Error()))
			http.Redirect(w, r, s.baseURL+"/admin/config", http.StatusSeeOther)
			return
		}

		// Write TOML.
		if err := config.SaveTOMLConfig(config.TOMLConfigPath(), values); err != nil {
			s.setFlashCookie(w, "config_error:"+url.QueryEscape(err.Error()))
			http.Redirect(w, r, s.baseURL+"/admin/config", http.StatusSeeOther)
			return
		}

		// Determine restart-required sections before applying live updates.
		currentValues := configToValues(s.cfg)
		restartSections := findRestartSections(values, currentValues)

		// Apply live-safe changes.
		s.applyLiveConfigUpdates(values, username)

		s.store.LogAction(username, challpkg.ActionConfigChanged, "", "", username)

		if len(restartSections) > 0 {
			s.setFlashCookie(w, "config_saved_restart:"+strings.Join(restartSections, "|"))
		} else {
			s.setFlashCookie(w, "config_saved:")
		}
		http.Redirect(w, r, s.baseURL+"/admin/config", http.StatusSeeOther)
		return
	}

	// GET: parse flash messages.
	var flashes []string
	var flashErrors []string
	var restartSections []string
	if fp := s.getAndClearFlash(w, r); fp != "" {
		for _, f := range strings.Split(fp, ",") {
			parts := strings.SplitN(f, ":", 2)
			if len(parts) == 2 {
				switch parts[0] {
				case "config_saved":
					flashes = append(flashes, t("config_saved"))
				case "config_saved_restart":
					if parts[1] != "" {
						restartSections = strings.Split(parts[1], "|")
					}
				case "config_error":
					msg, _ := url.QueryUnescape(parts[1])
					flashErrors = append(flashErrors, msg)
				}
			}
		}
	}

	now := time.Now()
	csrfTs := strconv.FormatInt(now.Unix(), 10)
	csrfToken := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)

	adminTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err := time.LoadLocation(c.Value); err == nil {
			adminTZ = c.Value
		}
	}

	apiKeyCount := len(s.cfg.APIKeys)
	apiKeyStr := t("not_configured")
	if apiKeyCount > 0 {
		apiKeyStr = fmt.Sprintf(t("n_keys"), apiKeyCount)
	}

	w.Header().Set("Content-Type", "text/html")
	if err := adminTmpl.Execute(w, map[string]interface{}{
		"Username":      username,
		"Initial":       strings.ToUpper(username[:1]),
		"Avatar":        getAvatar(r),
		"Timezone":      adminTZ,
		"Flashes":        flashes,
		"FlashErrors":    flashErrors,
		"RestartSections": restartSections,
		"ActivePage":    "admin",
		"AdminTab":      "config",
		"BridgeMode":    s.isBridgeMode(),
		"DefaultPageSize": s.cfg.DefaultPageSize,
		"Theme":         getTheme(r),
		"CSPNonce":      cspNonce(r),
		"T":             T(lang),
		"Lang":          lang,
		"Languages":     supportedLanguages,
		"IsAdmin":       true,
		"CSRFToken":     csrfToken,
		"CSRFTs":        csrfTs,
		"Pending":       s.buildPendingViews(username, lang),
		"AllPendingQueue": s.buildAllPendingViews(lang),
		"ConfigValues":  configToValues(s.cfg),
		"ConfigLocked":  configLockedKeys(),
		"ConfigSecrets": configSecretStatus(s.cfg),
		"APIKeyCount":   apiKeyStr,
	}); err != nil {
		slog.Error("template execution", "err", err)
	}
}

// configToValues converts a ServerConfig to a flat map of env-key → string value
// suitable for pre-populating the config form.
func configToValues(cfg *config.ServerConfig) map[string]string {
	tokenCache := ""
	if cfg.ClientTokenCacheEnabled != nil {
		if *cfg.ClientTokenCacheEnabled {
			tokenCache = "true"
		} else {
			tokenCache = "false"
		}
	}
	return map[string]string{
		"IDENTREE_OIDC_ISSUER_URL":                 cfg.IssuerURL,
		"IDENTREE_OIDC_ISSUER_PUBLIC_URL":          cfg.IssuerPublicURL,
		"IDENTREE_OIDC_CLIENT_ID":                  cfg.ClientID,
		"IDENTREE_POCKETID_API_URL":                cfg.APIURL,
		"IDENTREE_LISTEN_ADDR":                     cfg.ListenAddr,
		"IDENTREE_EXTERNAL_URL":                    cfg.ExternalURL,
		"IDENTREE_INSTALL_URL":                     cfg.InstallURL,
		"IDENTREE_CHALLENGE_TTL":                   formatDuration(nil, cfg.ChallengeTTL),
		"IDENTREE_GRACE_PERIOD":                    formatDuration(nil, cfg.GracePeriod),
		"IDENTREE_ONE_TAP_MAX_AGE":                 formatDuration(nil, cfg.OneTapMaxAge),
		"IDENTREE_LDAP_ENABLED":                    boolToString(cfg.LDAPEnabled),
		"IDENTREE_LDAP_LISTEN_ADDR":                cfg.LDAPListenAddr,
		"IDENTREE_LDAP_BASE_DN":                    cfg.LDAPBaseDN,
		"IDENTREE_LDAP_BIND_DN":                    cfg.LDAPBindDN,
		"IDENTREE_LDAP_REFRESH_INTERVAL":           formatDuration(nil, cfg.LDAPRefreshInterval),
		"IDENTREE_LDAP_UID_MAP_FILE":               cfg.LDAPUIDMapFile,
		"IDENTREE_LDAP_SUDO_NO_AUTHENTICATE":       string(cfg.LDAPSudoNoAuthenticate),
		"IDENTREE_SUDO_RULES_FILE":                 cfg.SudoRulesFile,
		"IDENTREE_LDAP_UID_BASE":                   strconv.Itoa(cfg.LDAPUIDBase),
		"IDENTREE_LDAP_GID_BASE":                   strconv.Itoa(cfg.LDAPGIDBase),
		"IDENTREE_LDAP_DEFAULT_SHELL":              cfg.LDAPDefaultShell,
		"IDENTREE_LDAP_DEFAULT_HOME":               cfg.LDAPDefaultHome,
		"IDENTREE_ADMIN_GROUPS":                    strings.Join(cfg.AdminGroups, ", "),
		"IDENTREE_ADMIN_APPROVAL_HOSTS":            strings.Join(cfg.AdminApprovalHosts, ", "),
		"IDENTREE_NOTIFY_BACKEND":                  cfg.NotifyBackend,
		"IDENTREE_NOTIFY_URL":                      cfg.NotifyURL,
		// IDENTREE_NOTIFY_COMMAND intentionally excluded: it contains a shell command
		// path that may reveal internal infrastructure and runs as the server process.
		// It is env-var only (not admin-UI writable) and must not be shown in the UI.
		"IDENTREE_NOTIFY_TIMEOUT":                  formatDuration(nil, cfg.NotifyTimeout),
		"IDENTREE_ESCROW_BACKEND":                  string(cfg.EscrowBackend),
		"IDENTREE_ESCROW_URL":                      cfg.EscrowURL,
		"IDENTREE_ESCROW_AUTH_ID":                  cfg.EscrowAuthID,
		"IDENTREE_ESCROW_PATH":                     cfg.EscrowPath,
		"IDENTREE_ESCROW_WEB_URL":                  cfg.EscrowWebURL,
		"IDENTREE_CLIENT_POLL_INTERVAL": func() string {
			if cfg.ClientPollInterval == 0 {
				return ""
			}
			return formatDuration(nil, cfg.ClientPollInterval)
		}(),
		"IDENTREE_CLIENT_TIMEOUT": func() string {
			if cfg.ClientTimeout == 0 {
				return ""
			}
			return formatDuration(nil, cfg.ClientTimeout)
		}(),
		"IDENTREE_CLIENT_BREAKGLASS_ENABLED":       boolPtrToString(cfg.ClientBreakglassEnabled),
		"IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE": cfg.ClientBreakglassPasswordType,
		"IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS": strconv.Itoa(cfg.ClientBreakglassRotationDays),
		"IDENTREE_CLIENT_TOKEN_CACHE_ENABLED":      tokenCache,
		"IDENTREE_HOST_REGISTRY_FILE":              cfg.HostRegistryFile,
		"IDENTREE_DEFAULT_PAGE_SIZE":               strconv.Itoa(cfg.DefaultPageSize),
		"IDENTREE_SESSION_STATE_FILE":              cfg.SessionStateFile,
	}
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func boolPtrToString(b *bool) string {
	if b == nil {
		return ""
	}
	return boolToString(*b)
}

// configLockedKeys returns the set of env var keys that are currently sourced from the environment.
func configLockedKeys() map[string]bool {
	locked := make(map[string]bool)
	for _, sec := range config.TOMLSections {
		for _, fld := range sec.Fields {
			if config.IsEnvSourced(fld.EnvKey) {
				locked[fld.EnvKey] = true
			}
		}
	}
	for _, key := range []string{
		"IDENTREE_OIDC_CLIENT_SECRET", "IDENTREE_POCKETID_API_KEY",
		"IDENTREE_SHARED_SECRET", "IDENTREE_LDAP_BIND_PASSWORD",
		"IDENTREE_ESCROW_AUTH_SECRET", "IDENTREE_ESCROW_ENCRYPTION_KEY", "IDENTREE_WEBHOOK_SECRET", "IDENTREE_API_KEYS",
		"IDENTREE_NOTIFY_TOKEN",
	} {
		if config.IsEnvSourced(key) {
			locked[key] = true
		}
	}
	return locked
}

// configSecretStatus returns true for each secret key if the secret is currently set.
func configSecretStatus(cfg *config.ServerConfig) map[string]bool {
	return map[string]bool{
		"IDENTREE_OIDC_CLIENT_SECRET":    cfg.ClientSecret != "",
		"IDENTREE_POCKETID_API_KEY":      cfg.APIKey != "",
		"IDENTREE_SHARED_SECRET":         cfg.SharedSecret != "",
		"IDENTREE_LDAP_BIND_PASSWORD":    cfg.LDAPBindPassword != "",
		"IDENTREE_ESCROW_AUTH_SECRET":    cfg.EscrowAuthSecret != "",
		"IDENTREE_ESCROW_ENCRYPTION_KEY": cfg.EscrowEncryptionKey != "",
		"IDENTREE_WEBHOOK_SECRET":        cfg.WebhookSecret != "",
		"IDENTREE_NOTIFY_TOKEN":          cfg.NotifyToken != "",
	}
}

// isPrivateIP returns true if the given IP is loopback, link-local, or private
// (RFC 1918 / RFC 4193 / RFC 3927 / IPv6 loopback).
func isPrivateIP(ip net.IP) bool {
	private := []net.IPNet{
		{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)},
		{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)},
		{IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)},
		{IP: net.ParseIP("169.254.0.0"), Mask: net.CIDRMask(16, 32)}, // link-local
		{IP: net.ParseIP("fc00::"), Mask: net.CIDRMask(7, 128)},      // ULA
		{IP: net.ParseIP("fe80::"), Mask: net.CIDRMask(10, 128)},     // link-local IPv6
	}
	if ip.IsLoopback() {
		return true
	}
	for _, block := range private {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// validateWebhookURL checks that a URL is safe to use as an outbound webhook target.
// It rejects non-http(s) schemes, URLs with embedded userinfo, and hostnames that
// resolve to loopback, link-local, or private IP ranges to prevent SSRF.
func validateWebhookURL(rawURL string) error {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return fmt.Errorf("must start with http:// or https://")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.User != nil {
		return fmt.Errorf("URL must not contain userinfo credentials")
	}
	hostname := parsed.Hostname()
	if hostname == "" {
		return fmt.Errorf("URL must contain a hostname")
	}
	// Resolve the hostname and reject any address in a private/loopback range.
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		// If DNS resolution fails entirely, reject to be safe.
		return fmt.Errorf("hostname %q could not be resolved: %w", hostname, err)
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if isPrivateIP(ip) {
			return fmt.Errorf("hostname %q resolves to a private/loopback address (%s), which is not allowed", hostname, addr)
		}
	}
	return nil
}

// validateConfigValues validates form-submitted config values.
func validateConfigValues(values map[string]string, cfg *config.ServerConfig) error {
	for _, key := range []string{
		"IDENTREE_CHALLENGE_TTL", "IDENTREE_GRACE_PERIOD",
		"IDENTREE_ONE_TAP_MAX_AGE", "IDENTREE_LDAP_REFRESH_INTERVAL",
		"IDENTREE_NOTIFY_TIMEOUT",
		"IDENTREE_CLIENT_POLL_INTERVAL", "IDENTREE_CLIENT_TIMEOUT",
	} {
		if v := values[key]; v != "" {
			if _, err := time.ParseDuration(v); err != nil {
				return fmt.Errorf("invalid duration for %s: %q", key, v)
			}
		}
	}
	for _, key := range []string{
		"IDENTREE_LDAP_UID_BASE", "IDENTREE_LDAP_GID_BASE",
		"IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS", "IDENTREE_DEFAULT_PAGE_SIZE",
	} {
		if v := values[key]; v != "" {
			if _, err := strconv.Atoi(v); err != nil {
				return fmt.Errorf("invalid integer for %s: %q", key, v)
			}
		}
	}
	if v := values["IDENTREE_NOTIFY_BACKEND"]; v != "" {
		switch v {
		case "ntfy", "slack", "discord", "apprise", "webhook", "custom":
		default:
			return fmt.Errorf("invalid notify backend: %q", v)
		}
	}
	if v := values["IDENTREE_LDAP_SUDO_NO_AUTHENTICATE"]; v != "" {
		switch v {
		case "true", "false", "claims":
		default:
			return fmt.Errorf("invalid value for IDENTREE_LDAP_SUDO_NO_AUTHENTICATE: %q (must be true, false, or claims)", v)
		}
	}
	if v := values["IDENTREE_ESCROW_BACKEND"]; v != "" {
		switch v {
		case "local", "1password-connect", "vault", "bitwarden", "infisical":
		default:
			return fmt.Errorf("invalid escrow backend: %q", v)
		}
		// The local backend requires an encryption key that can only be supplied via
		// environment variable. Reject here rather than allowing a config that will
		// crash on the next startup.
		if v == string(config.EscrowBackendLocal) && cfg.EscrowEncryptionKey == "" {
			return fmt.Errorf("IDENTREE_ESCROW_BACKEND = \"local\" requires IDENTREE_ESCROW_ENCRYPTION_KEY to be set as an environment variable")
		}
	}
	// URL validation: reject non-http(s) values and SSRF-risky targets.
	for _, key := range []string{
		"IDENTREE_NOTIFY_URL", "IDENTREE_ESCROW_URL", "IDENTREE_ESCROW_WEB_URL",
	} {
		if v := values[key]; v != "" {
			if err := validateWebhookURL(v); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
	}
	if v := values["IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE"]; v != "" {
		switch v {
		case "random", "passphrase", "alphanumeric":
		default:
			return fmt.Errorf("invalid breakglass password type: %q", v)
		}
	}
	// Prevent saving a config that would break on next restart: required fields
	// must not be blanked via the UI. Only check fields that are not env-locked
	// (env-locked fields are absent from values and keep their runtime value).
	if !config.IsEnvSourced("IDENTREE_EXTERNAL_URL") {
		if v := values["IDENTREE_EXTERNAL_URL"]; v == "" {
			return fmt.Errorf("IDENTREE_EXTERNAL_URL is required and must not be blank")
		}
	}
	if v := values["IDENTREE_LDAP_DEFAULT_HOME"]; v != "" {
		stripped := strings.ReplaceAll(v, "%%", "")
		if strings.Count(stripped, "%s") > 1 {
			return fmt.Errorf("IDENTREE_LDAP_DEFAULT_HOME: pattern contains more than one %%s")
		}
		bad := regexp.MustCompile(`%[a-zA-Z]`).FindAllString(stripped, -1)
		for _, b := range bad {
			if b != "%s" {
				return fmt.Errorf("IDENTREE_LDAP_DEFAULT_HOME: unsupported format verb %q (only %%s is allowed)", b)
			}
		}
	}
	return nil
}

// applyLiveConfigUpdates applies the subset of config changes that are safe without a restart.
// Holds s.cfgMu write lock for the entire mutation so concurrent handlers that snapshot
// slice fields (AdminGroups, AdminApprovalHosts) under the read lock see consistent values.
// actor is the authenticated admin username making the change, used for audit logging.
func (s *Server) applyLiveConfigUpdates(values map[string]string, actor string) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	parseDur := func(key string, def time.Duration) time.Duration {
		if v := values[key]; v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				return d
			}
		}
		return def
	}
	parseInt := func(key string, def int) int {
		if v := values[key]; v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		}
		return def
	}
	parseSlice := func(key string) []string {
		v := values[key]
		if v == "" {
			return nil
		}
		var out []string
		for _, item := range strings.Split(v, ",") {
			if t := strings.TrimSpace(item); t != "" {
				out = append(out, t)
			}
		}
		return out
	}

	if !config.IsEnvSourced("IDENTREE_CHALLENGE_TTL") {
		s.cfg.ChallengeTTL = parseDur("IDENTREE_CHALLENGE_TTL", s.cfg.ChallengeTTL)
	}
	if !config.IsEnvSourced("IDENTREE_GRACE_PERIOD") {
		d := parseDur("IDENTREE_GRACE_PERIOD", s.cfg.GracePeriod)
		if d < 0 {
			d = 0
		}
		s.cfg.GracePeriod = d
	}
	if !config.IsEnvSourced("IDENTREE_ONE_TAP_MAX_AGE") {
		s.cfg.OneTapMaxAge = parseDur("IDENTREE_ONE_TAP_MAX_AGE", s.cfg.OneTapMaxAge)
	}
	if !config.IsEnvSourced("IDENTREE_ADMIN_GROUPS") {
		newGroups := parseSlice("IDENTREE_ADMIN_GROUPS")
		// Reject changes that would remove all admin groups (lockout prevention).
		if len(newGroups) == 0 && len(s.cfg.AdminGroups) > 0 {
			slog.Warn("ADMIN_GROUPS_CHANGE_REJECTED: new value is empty, keeping existing groups to prevent lockout",
				"actor", actor, "current_groups", s.cfg.AdminGroups)
		} else {
			if fmt.Sprintf("%v", newGroups) != fmt.Sprintf("%v", s.cfg.AdminGroups) {
				slog.Info("ADMIN_GROUPS_CHANGED", "actor", actor,
					"old_groups", s.cfg.AdminGroups, "new_groups", newGroups)
			}
			s.cfg.AdminGroups = newGroups
		}
	}
	if !config.IsEnvSourced("IDENTREE_ADMIN_APPROVAL_HOSTS") {
		s.cfg.AdminApprovalHosts = parseSlice("IDENTREE_ADMIN_APPROVAL_HOSTS")
	}
	if !config.IsEnvSourced("IDENTREE_NOTIFY_BACKEND") {
		s.cfg.NotifyBackend = values["IDENTREE_NOTIFY_BACKEND"]
	}
	if !config.IsEnvSourced("IDENTREE_NOTIFY_URL") {
		s.cfg.NotifyURL = values["IDENTREE_NOTIFY_URL"]
	}
	// IDENTREE_NOTIFY_COMMAND is intentionally not live-updated: it executes
	// arbitrary shell commands as the identree process user. Allowing admins
	// to change it without an OS-level restart would let any admin silently
	// install persistence. Set via environment variable only.
	if !config.IsEnvSourced("IDENTREE_NOTIFY_TIMEOUT") {
		if d, err := time.ParseDuration(values["IDENTREE_NOTIFY_TIMEOUT"]); err == nil && d > 0 {
			s.cfg.NotifyTimeout = d
		}
	}
	if !config.IsEnvSourced("IDENTREE_ESCROW_BACKEND") {
		s.cfg.EscrowBackend = config.EscrowBackend(values["IDENTREE_ESCROW_BACKEND"])
	}
	if !config.IsEnvSourced("IDENTREE_ESCROW_URL") {
		s.cfg.EscrowURL = values["IDENTREE_ESCROW_URL"]
	}
	if !config.IsEnvSourced("IDENTREE_ESCROW_AUTH_ID") {
		s.cfg.EscrowAuthID = values["IDENTREE_ESCROW_AUTH_ID"]
	}
	if !config.IsEnvSourced("IDENTREE_ESCROW_PATH") {
		s.cfg.EscrowPath = values["IDENTREE_ESCROW_PATH"]
	}
	if !config.IsEnvSourced("IDENTREE_ESCROW_WEB_URL") {
		s.cfg.EscrowWebURL = values["IDENTREE_ESCROW_WEB_URL"]
	}
	if !config.IsEnvSourced("IDENTREE_CLIENT_POLL_INTERVAL") {
		if d, err := time.ParseDuration(values["IDENTREE_CLIENT_POLL_INTERVAL"]); err == nil && d > 0 {
			s.cfg.ClientPollInterval = d
		} else if values["IDENTREE_CLIENT_POLL_INTERVAL"] == "" {
			s.cfg.ClientPollInterval = 0
		}
	}
	if !config.IsEnvSourced("IDENTREE_CLIENT_TIMEOUT") {
		if d, err := time.ParseDuration(values["IDENTREE_CLIENT_TIMEOUT"]); err == nil && d > 0 {
			s.cfg.ClientTimeout = d
		} else if values["IDENTREE_CLIENT_TIMEOUT"] == "" {
			s.cfg.ClientTimeout = 0
		}
	}
	if !config.IsEnvSourced("IDENTREE_CLIENT_BREAKGLASS_ENABLED") {
		if v := values["IDENTREE_CLIENT_BREAKGLASS_ENABLED"]; v != "" {
			if b, err := strconv.ParseBool(v); err == nil {
				s.cfg.ClientBreakglassEnabled = &b
			}
		} else {
			s.cfg.ClientBreakglassEnabled = nil
		}
	}
	if !config.IsEnvSourced("IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE") {
		s.cfg.ClientBreakglassPasswordType = values["IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE"]
	}
	if !config.IsEnvSourced("IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS") {
		s.cfg.ClientBreakglassRotationDays = parseInt("IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS", s.cfg.ClientBreakglassRotationDays)
	}
	if !config.IsEnvSourced("IDENTREE_CLIENT_TOKEN_CACHE_ENABLED") {
		if v := values["IDENTREE_CLIENT_TOKEN_CACHE_ENABLED"]; v != "" {
			if b, err := strconv.ParseBool(v); err == nil {
				s.cfg.ClientTokenCacheEnabled = &b
			}
		} else {
			s.cfg.ClientTokenCacheEnabled = nil
		}
	}
	if !config.IsEnvSourced("IDENTREE_DEFAULT_PAGE_SIZE") {
		s.cfg.DefaultPageSize = parseInt("IDENTREE_DEFAULT_PAGE_SIZE", s.cfg.DefaultPageSize)
	}
	if !config.IsEnvSourced("IDENTREE_LDAP_SUDO_NO_AUTHENTICATE") {
		switch v := config.SudoNoAuthenticate(values["IDENTREE_LDAP_SUDO_NO_AUTHENTICATE"]); v {
		case config.SudoNoAuthTrue, config.SudoNoAuthFalse, config.SudoNoAuthClaims:
			s.cfg.LDAPSudoNoAuthenticate = v
		}
	}
	if !config.IsEnvSourced("IDENTREE_LDAP_DEFAULT_SHELL") {
		s.cfg.LDAPDefaultShell = values["IDENTREE_LDAP_DEFAULT_SHELL"]
	}
	if !config.IsEnvSourced("IDENTREE_LDAP_DEFAULT_HOME") {
		s.cfg.LDAPDefaultHome = values["IDENTREE_LDAP_DEFAULT_HOME"]
	}
	if !config.IsEnvSourced("IDENTREE_LDAP_ALLOW_ANONYMOUS") {
		if v := values["IDENTREE_LDAP_ALLOW_ANONYMOUS"]; v != "" {
			if b, err := strconv.ParseBool(v); err == nil {
				s.cfg.LDAPAllowAnonymous = b
			}
		}
	}
}

// handleAdminUsers renders the admin users list at /admin/users.
// GET /admin/users
func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Handle language change via query param
	if setLanguageCookie(w, r) {
		return
	}
	lang := detectLanguage(r)
	t := T(lang)

	username := s.getSessionUser(r)
	if username == "" {
		s.setFlashCookie(w, "expired:")
		http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
		return
	}
	role := s.getSessionRole(r)
	if role != "admin" {
		http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, username, role)

	// Parse flash messages
	var flashes []string
	if flashParam := s.getAndClearFlash(w, r); flashParam != "" {
		for _, f := range strings.Split(flashParam, ",") {
			parts := strings.SplitN(f, ":", 2)
			if len(parts) == 2 {
				switch parts[0] {
				case "removed_user":
					flashes = append(flashes, t("removed_user_on")+" "+parts[1])
				}
			}
		}
	}

	users := s.store.AllUsers()

	// Fetch group permissions from Pocket ID (cached)
	var userPerms map[string][]pocketid.GroupInfo
	if s.pocketIDClient != nil {
		perms, err := s.pocketIDClient.GetUserPermissions()
		if err != nil {
			slog.Warn("fetching Pocket ID permissions", "err", err)
		} else {
			userPerms = perms
		}
	}

	// Build snapshot of recently-removed users to exclude from PocketID merge.
	s.removedUsersMu.Lock()
	for u, t := range s.removedUsers {
		if time.Since(t) > 10*time.Minute {
			delete(s.removedUsers, u)
		}
	}
	recentlyRemoved := make(map[string]bool, len(s.removedUsers))
	for u := range s.removedUsers {
		recentlyRemoved[u] = true
	}
	s.removedUsersMu.Unlock()

	// Merge Pocket ID users that haven't yet used identree
	if userPerms != nil {
		userSet := make(map[string]bool, len(users))
		for _, u := range users {
			userSet[u] = true
		}
		for uname := range userPerms {
			if !userSet[uname] && !recentlyRemoved[uname] {
				users = append(users, uname)
				userSet[uname] = true
			}
		}
		sort.Strings(users)
	}

	type userSessionView struct {
		Hostname        string
		Remaining       string
		SessionUsername string
	}
	type userView struct {
		Username       string
		UserID         string // PocketID user ID, used for SSH key editing
		ActiveSessions int
		LastActive     string
		LastActiveAgo  string
		LastActiveTime time.Time
		Groups         []pocketid.GroupInfo
		Sessions       []userSessionView
		SSHKeys        []string         // editable sshPublicKey* values
		LoginShell     string           // editable loginShell claim
		HomeDirectory  string           // editable homeDirectory claim
		OtherClaims    []pocketid.Claim // read-only: non-SSH, non-POSIX user claims
	}

	// Build username→PocketID-user map for ID lookup and claims pre-population.
	type pidUserInfo struct {
		ID     string
		Claims []pocketid.Claim
	}
	var pidUsers map[string]pidUserInfo
	if s.pocketIDClient != nil {
		// Use AllAdminUsers (not the cached variant) so the admin UI always
		// shows the live state from PocketID, not a potentially stale snapshot.
		adminUsers, err := s.pocketIDClient.AllAdminUsers()
		if err != nil {
			slog.Warn("fetching admin users for claims", "err", err)
		} else {
			pidUsers = make(map[string]pidUserInfo, len(adminUsers))
			for _, au := range adminUsers {
				pidUsers[au.Username] = pidUserInfo{ID: au.ID, Claims: au.CustomClaims}
			}
		}
	}

	adminTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err := time.LoadLocation(c.Value); err == nil {
			adminTZ = c.Value
		}
	}
	adminLoc, _ := time.LoadLocation(adminTZ)

	now := time.Now()
	csrfTs := strconv.FormatInt(now.Unix(), 10)
	csrfToken := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)

	// Bulk-fetch all active sessions and action history to avoid N+1 store queries.
	allSessionsByUser := make(map[string][]challpkg.GraceSession)
	for _, sess := range s.store.AllActiveSessions() {
		allSessionsByUser[sess.Username] = append(allSessionsByUser[sess.Username], sess)
	}
	latestActionByUser := make(map[string]time.Time)
	for _, entry := range s.store.AllActionHistoryWithUsers() {
		if entry.Timestamp.After(latestActionByUser[entry.Username]) {
			latestActionByUser[entry.Username] = entry.Timestamp
		}
	}

	var userViews []userView
	for _, u := range users {
		sessions := allSessionsByUser[u]
		lastActive := ""
		lastActiveAgo := ""
		var lastActiveTime time.Time
		if latest, ok := latestActionByUser[u]; ok {
			lastActive = latest.In(adminLoc).Format("2006-01-02 15:04")
			lastActiveAgo = timeAgoI18n(latest, t)
			lastActiveTime = latest
		}
		var sessionViews []userSessionView
		for _, sess := range sessions {
			sessionViews = append(sessionViews, userSessionView{
				Hostname:        sess.Hostname,
				Remaining:       formatDuration(t, time.Until(sess.ExpiresAt)),
				SessionUsername: u,
			})
		}
		uv := userView{
			Username:       u,
			ActiveSessions: len(sessions),
			LastActive:     lastActive,
			LastActiveAgo:  lastActiveAgo,
			LastActiveTime: lastActiveTime,
			Sessions:       sessionViews,
		}
		if pi, ok := pidUsers[u]; ok {
			uv.UserID = pi.ID
			for _, cl := range pi.Claims {
				switch {
				case sshKeyClaimPattern.MatchString(cl.Key):
					uv.SSHKeys = append(uv.SSHKeys, cl.Value)
				case cl.Key == "loginShell":
					uv.LoginShell = cl.Value
				case cl.Key == "homeDirectory":
					uv.HomeDirectory = cl.Value
				default:
					uv.OtherClaims = append(uv.OtherClaims, cl)
				}
			}
		}
		// Filter to only sudo-relevant groups (those with sudoCommands claim)
		var sudoGroups []pocketid.GroupInfo
		for _, g := range userPerms[u] {
			if g.SudoCommands != "" {
				sudoGroups = append(sudoGroups, g)
			}
		}
		uv.Groups = sudoGroups
		// Skip users with no sudo groups AND no identree activity
		hasPamActivity := uv.ActiveSessions > 0 || uv.LastActive != ""
		if len(uv.Groups) == 0 && !hasPamActivity {
			continue
		}
		userViews = append(userViews, uv)
	}

	// Sort user views
	userSortBy := r.URL.Query().Get("sort")
	userSortDir := r.URL.Query().Get("dir")
	if userSortDir != "desc" {
		userSortDir = "asc"
	}
	if userSortBy == "" {
		userSortBy = "name"
	}
	sort.Slice(userViews, func(i, j int) bool {
		var less bool
		switch userSortBy {
		case "sessions":
			less = userViews[i].ActiveSessions < userViews[j].ActiveSessions
		case "lastactive":
			less = userViews[i].LastActiveTime.Before(userViews[j].LastActiveTime)
		default:
			less = userViews[i].Username < userViews[j].Username
		}
		if userSortDir == "desc" {
			return !less
		}
		return less
	})

	w.Header().Set("Content-Type", "text/html")
	if err := adminTmpl.Execute(w, map[string]interface{}{
		"Username":      username,
		"Initial":       strings.ToUpper(username[:1]),
		"Avatar":        getAvatar(r),
		"Timezone":      adminTZ,
		"Flashes":       flashes,
		"ActivePage":    "admin",
		"AdminTab":      "users",
		"BridgeMode":    s.isBridgeMode(),
		"DefaultPageSize": s.cfg.DefaultPageSize,
		"Theme":         getTheme(r),
		"CSPNonce":      cspNonce(r),
		"T":             T(lang),
		"Lang":          lang,
		"Languages":     supportedLanguages,
		"IsAdmin":       true,
		"Users":         userViews,
		"UserSort":      userSortBy,
		"UserDir":       userSortDir,
		"CSRFToken":     csrfToken,
		"CSRFTs":        csrfTs,
		"Pending":       s.buildPendingViews(username, lang),
		"AllPendingQueue": s.buildAllPendingViews(lang),
		"CanEditClaims": s.pocketIDClient != nil,
	}); err != nil {
		slog.Error("template execution", "err", err)
	}
}

// handleAdminGroups renders the admin groups page at /admin/groups.
// GET /admin/groups
func (s *Server) handleAdminGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if setLanguageCookie(w, r) {
		return
	}
	lang := detectLanguage(r)
	t := T(lang)

	username := s.getSessionUser(r)
	if username == "" {
		s.setFlashCookie(w, "expired:")
		http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
		return
	}
	role := s.getSessionRole(r)
	if role != "admin" {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "not_authorized_message")
		return
	}
	s.setSessionCookie(w, username, role)
	if s.isBridgeMode() {
		http.Redirect(w, r, s.baseURL+"/admin/sudo-rules", http.StatusSeeOther)
		return
	}

	type groupView struct {
		GroupID        string
		Name           string
		SudoCommands   string
		SudoHosts      string
		SudoRunAs      string
		SudoRunAsGroup string
		SudoOptions    string
		AccessHosts    string
		OtherClaims    []pocketid.Claim // read-only: claims not managed by identree
		Members        []string
		AllCmds        bool
		AllHosts       bool
		CmdList        []string
		HostList       []string
	}

	allGroups, err := s.pocketIDClient.GetGroups()
	if err != nil {
		slog.Error("fetching groups", "err", err)
	}

	var groups []groupView
	for _, g := range allGroups {
		claims := make(map[string]string)
		for _, cl := range g.CustomClaims {
			claims[cl.Key] = cl.Value
		}
		cmds := claims["sudoCommands"]
		hosts := claims["sudoHosts"]
		accessHosts := claims["accessHosts"]
		// Only include groups with identree-managed claims
		if cmds == "" && hosts == "" && accessHosts == "" {
			continue
		}
		gv := groupView{
			GroupID:        g.ID,
			Name:           g.Name,
			SudoCommands:   cmds,
			SudoHosts:      hosts,
			SudoRunAs:      claims["sudoRunAsUser"],
			SudoRunAsGroup: claims["sudoRunAsGroup"],
			SudoOptions:    claims["sudoOptions"],
			AccessHosts:    accessHosts,
		}
		for _, cl := range g.CustomClaims {
			if !isEditableGroupClaim(cl.Key) {
				gv.OtherClaims = append(gv.OtherClaims, cl)
			}
		}
		gv.AllCmds = cmds == "ALL"
		gv.AllHosts = hosts == "" || hosts == "ALL"
		if !gv.AllCmds {
			for _, c := range strings.Split(cmds, ",") {
				if c := strings.TrimSpace(c); c != "" {
					gv.CmdList = append(gv.CmdList, c)
				}
			}
		}
		if !gv.AllHosts {
			for _, h := range strings.Split(hosts, ",") {
				if h := strings.TrimSpace(h); h != "" {
					gv.HostList = append(gv.HostList, h)
				}
			}
		}
		for _, u := range g.Users {
			gv.Members = append(gv.Members, u.Username)
		}
		sort.Strings(gv.Members)
		groups = append(groups, gv)
	}

	sortBy := r.URL.Query().Get("sort")
	sortDir := r.URL.Query().Get("dir")
	if sortDir != "desc" {
		sortDir = "asc"
	}
	switch sortBy {
	case "members":
		sort.Slice(groups, func(i, j int) bool {
			if sortDir == "desc" {
				return len(groups[i].Members) > len(groups[j].Members)
			}
			return len(groups[i].Members) < len(groups[j].Members)
		})
	case "commands":
		sort.Slice(groups, func(i, j int) bool {
			if sortDir == "desc" {
				return groups[i].SudoCommands > groups[j].SudoCommands
			}
			return groups[i].SudoCommands < groups[j].SudoCommands
		})
	case "hosts":
		sort.Slice(groups, func(i, j int) bool {
			if sortDir == "desc" {
				return groups[i].SudoHosts > groups[j].SudoHosts
			}
			return groups[i].SudoHosts < groups[j].SudoHosts
		})
	case "runas":
		sort.Slice(groups, func(i, j int) bool {
			if sortDir == "desc" {
				return groups[i].SudoRunAs > groups[j].SudoRunAs
			}
			return groups[i].SudoRunAs < groups[j].SudoRunAs
		})
	default:
		sortBy = "name"
		sort.Slice(groups, func(i, j int) bool {
			if sortDir == "desc" {
				return groups[i].Name > groups[j].Name
			}
			return groups[i].Name < groups[j].Name
		})
	}

	now := time.Now()
	csrfTs := strconv.FormatInt(now.Unix(), 10)
	csrfToken := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)

	adminTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err := time.LoadLocation(c.Value); err == nil {
			adminTZ = c.Value
		}
	}

	w.Header().Set("Content-Type", "text/html")
	if err := adminTmpl.Execute(w, map[string]interface{}{
		"Username":      username,
		"Initial":       strings.ToUpper(username[:1]),
		"Avatar":        getAvatar(r),
		"Timezone":      adminTZ,
		"AdminTab":      "groups",
		"BridgeMode":    s.isBridgeMode(),
		"DefaultPageSize": s.cfg.DefaultPageSize,
		"Groups":        groups,
		"GroupSort":     sortBy,
		"GroupDir":      sortDir,
		"Flashes":       []string{},
		"CSRFToken":     csrfToken,
		"CSRFTs":        csrfTs,
		"ActivePage":    "admin",
		"Theme":         getTheme(r),
		"CSPNonce":      cspNonce(r),
		"T":             t,
		"Lang":          lang,
		"Languages":     supportedLanguages,
		"IsAdmin":       true,
		"Pending":       s.buildPendingViews(username, lang),
		"AllPendingQueue": s.buildAllPendingViews(lang),
		"CanEditClaims": s.pocketIDClient != nil,
	}); err != nil {
		slog.Error("template execution", "err", err)
	}
}

// handleAdminHosts renders the admin hosts page at /admin/hosts.
// GET /admin/hosts
func (s *Server) handleAdminHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Handle language change via query param
	if setLanguageCookie(w, r) {
		return
	}
	lang := detectLanguage(r)
	t := T(lang)

	username := s.getSessionUser(r)
	if username == "" {
		s.setFlashCookie(w, "expired:")
		http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
		return
	}
	role := s.getSessionRole(r)
	if role != "admin" {
		http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, username, role)

	// Resolve timezone for flash time formatting
	flashTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err2 := time.LoadLocation(c.Value); err2 == nil {
			flashTZ = c.Value
		}
	}
	flashLoc, _ := time.LoadLocation(flashTZ)
	formatFlashTime := func(unixStr string) string {
		unix, err := strconv.ParseInt(unixStr, 10, 64)
		if err != nil {
			return ""
		}
		return time.Unix(unix, 0).In(flashLoc).Format("Jan 2, 3:04 PM")
	}

	// Parse flash messages from cookie
	var flashes []string
	if flashParam := s.getAndClearFlash(w, r); flashParam != "" {
		for _, f := range strings.Split(flashParam, ",") {
			parts := strings.SplitN(f, ":", 5)
			if len(parts) < 2 {
				continue
			}
			switch parts[0] {
			case "elevated":
				if len(parts) == 4 {
					flashes = append(flashes, t("elevated_session_on")+" "+parts[1]+" ("+parts[2]+") "+t("until")+" "+formatFlashTime(parts[3]))
				} else {
					flashes = append(flashes, t("elevated_session_on")+" "+parts[1])
				}
			case "extended":
				if len(parts) == 4 {
					flashes = append(flashes, t("extended_session_on")+" "+parts[1]+" ("+parts[2]+") "+t("until")+" "+formatFlashTime(parts[3]))
				} else {
					flashes = append(flashes, t("extended_session_on")+" "+parts[1])
				}
			case "extended_all":
				flashes = append(flashes, fmt.Sprintf(t("extended_n_sessions"), atoi(parts[1])))
			case "revoked":
				if len(parts) == 3 {
					flashes = append(flashes, t("revoked_session_on")+" "+parts[1]+" ("+parts[2]+")")
				} else {
					flashes = append(flashes, t("revoked_session_on")+" "+parts[1])
				}
			case "revoked_all":
				flashes = append(flashes, fmt.Sprintf(t("revoked_n_sessions"), atoi(parts[1])))
			case "rotated":
				flashes = append(flashes, t("rotated_breakglass_on")+" "+parts[1])
			case "rotated_all":
				flashes = append(flashes, fmt.Sprintf(t("rotated_n_hosts"), atoi(parts[1])))
			}
		}
	}

	var hosts []string
	if s.hostRegistry.IsEnabled() {
		// When the registry is enabled, it is the authoritative list of managed hosts.
		// Removing a host from the registry should immediately remove it from this page.
		hosts = s.hostRegistry.RegisteredHosts()
	} else {
		hosts = s.store.AllKnownHosts()
	}
	escrowed := s.store.EscrowedHosts()

	// Merge escrowed hosts into the known hosts list.
	// All escrowed hosts are visible to admins regardless of host-registry scoping.
	escrowedSet := make(map[string]bool)
	for h := range escrowed {
		escrowedSet[h] = true
		found := false
		for _, kh := range hosts {
			if kh == h {
				found = true
				break
			}
		}
		if !found {
			hosts = append(hosts, h)
		}
	}
	sort.Strings(hosts)

	// Default rotation days for escrow validity
	rotationDays := 90
	if s.cfg.ClientBreakglassRotationDays > 0 {
		rotationDays = s.cfg.ClientBreakglassRotationDays
	}

	// Merge registered hosts into the known hosts list
	if s.hostRegistry.IsEnabled() {
		for _, rh := range s.hostRegistry.HostsForUser(username) {
			found := false
			for _, kh := range hosts {
				if kh == rh {
					found = true
					break
				}
			}
			if !found {
				hosts = append(hosts, rh)
			}
		}
		sort.Strings(hosts)
	}

	type hostUserView struct {
		Username  string
		Active    bool
		Remaining string
		Hostname  string
	}

	type hostView struct {
		Hostname           string
		HostUsers          []hostUserView
		ActiveSessionCount int
		Escrowed           bool
		EscrowAge          string
		EscrowExpired      bool
		EscrowLink         string
		EscrowRevealable   bool // true when backend supports in-UI reveal
		Group              string
	}

	// usersForHost returns sorted usernames with sudo access to hostname from Pocket ID claims.
	// Falls back to allUsers if userPerms is empty.
	usersForHost := func(hostname string, userPerms map[string][]pocketid.GroupInfo, allUsers []string) []string {
		if len(userPerms) == 0 {
			return allUsers
		}
		seen := make(map[string]bool)
		var result []string
		for u, groups := range userPerms {
			for _, g := range groups {
				if g.SudoCommands == "" {
					continue
				}
				h := strings.TrimSpace(g.SudoHosts)
				// Empty SudoHosts means no host restriction — treat as ALL
				if h == "" || h == "ALL" {
					if !seen[u] {
						seen[u] = true
						result = append(result, u)
					}
					break
				}
				for _, part := range strings.Split(h, ",") {
					if strings.TrimSpace(part) == hostname {
						if !seen[u] {
							seen[u] = true
							result = append(result, u)
						}
						break
					}
				}
			}
		}
		sort.Strings(result)
		return result
	}

	// Fetch group permissions from Pocket ID for per-host user lists
	var userPerms map[string][]pocketid.GroupInfo
	if s.pocketIDClient != nil {
		perms, err := s.pocketIDClient.GetUserPermissions()
		if err != nil {
			slog.Warn("fetching Pocket ID permissions for hosts", "err", err)
		} else {
			userPerms = perms
		}
	}
	allKnownUsers := s.store.AllUsers()

	// Bulk-fetch all active sessions once and index by hostname to avoid N+1 store queries.
	allSessionsByHost := make(map[string][]challpkg.GraceSession)
	for _, sess := range s.store.AllActiveSessions() {
		allSessionsByHost[sess.Hostname] = append(allSessionsByHost[sess.Hostname], sess)
	}

	// Collect all group names for the filter dropdown
	groupFilter := r.URL.Query().Get("group")
	groupSet := make(map[string]struct{})

	var hostViews []hostView
	for _, h := range hosts {
		hv := hostView{Hostname: h}

		// Build active session map for this host from the pre-fetched bulk result.
		activeMap := make(map[string]string) // username -> remaining
		for _, sess := range allSessionsByHost[h] {
			activeMap[sess.Username] = formatDuration(t, time.Until(sess.ExpiresAt))
		}
		hv.ActiveSessionCount = len(activeMap)

		// Build per-user rows from Pocket ID claims (or fallback to all known users)
		seen := make(map[string]bool)
		for _, u := range usersForHost(h, userPerms, allKnownUsers) {
			seen[u] = true
			remaining, active := activeMap[u]
			hv.HostUsers = append(hv.HostUsers, hostUserView{
				Username:  u,
				Active:    active,
				Remaining: remaining,
				Hostname:  h,
			})
		}
		// Always include users with active sessions, even if no longer in Pocket ID claims
		for u, remaining := range activeMap {
			if !seen[u] {
				hv.HostUsers = append(hv.HostUsers, hostUserView{
					Username:  u,
					Active:    true,
					Remaining: remaining,
					Hostname:  h,
				})
			}
		}
		sort.Slice(hv.HostUsers, func(i, j int) bool { return hv.HostUsers[i].Username < hv.HostUsers[j].Username })

		if escrowRecord, ok := escrowed[h]; ok {
			hv.Escrowed = true
			hv.EscrowAge = formatDuration(t, time.Since(escrowRecord.Timestamp))
			hv.EscrowExpired = time.Since(escrowRecord.Timestamp) > time.Duration(rotationDays)*24*time.Hour
			hv.EscrowLink = deriveEscrowLink(string(s.cfg.EscrowBackend), s.cfg.EscrowURL, s.cfg.EscrowPath, escrowRecord.ItemID, escrowRecord.VaultID, s.cfg.EscrowWebURL, h)
			// Reveal is available for all native backends (local, 1password-connect, vault, bitwarden, infisical).
			// Command-based escrow has no standardised retrieval API.
			hv.EscrowRevealable = s.cfg.EscrowBackend != "" && s.cfg.EscrowCommand == ""
		}
		if _, group, _, ok := s.hostRegistry.GetHost(h); ok {
			hv.Group = group
		}
		if hv.Group != "" {
			groupSet[hv.Group] = struct{}{}
		}
		// Apply group filter if set
		if groupFilter != "" && hv.Group != groupFilter {
			continue
		}
		hostViews = append(hostViews, hv)
	}

	// Build sorted list of all known groups for the filter dropdown
	var allGroups []string
	for g := range groupSet {
		allGroups = append(allGroups, g)
	}
	sort.Strings(allGroups)

	// Sort host views
	hostSortBy := r.URL.Query().Get("sort")
	hostSortDir := r.URL.Query().Get("dir")
	if hostSortDir != "desc" {
		hostSortDir = "asc"
	}
	if hostSortBy == "" {
		hostSortBy = "hostname"
	}
	sort.Slice(hostViews, func(i, j int) bool {
		var less bool
		switch hostSortBy {
		case "sessions":
			less = len(hostViews[i].HostUsers) < len(hostViews[j].HostUsers)
		default:
			less = hostViews[i].Hostname < hostViews[j].Hostname
		}
		if hostSortDir == "desc" {
			return !less
		}
		return less
	})

	now := time.Now()
	csrfTs := strconv.FormatInt(now.Unix(), 10)
	csrfToken := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)

	// Build duration options, filtering to those <= GracePeriod
	type durationOption struct {
		Value    int
		Label    string
		Selected bool
	}
	allDurations := []durationOption{
		{3600, "1h", false},
		{14400, "4h", false},
		{28800, "8h", true},
		{86400, "1d", false},
	}
	var durations []durationOption
	graceSec := int(s.cfg.GracePeriod.Seconds())
	if graceSec <= 0 {
		graceSec = 86400
	}
	for _, d := range allDurations {
		if d.Value <= graceSec {
			d.Selected = false
			durations = append(durations, d)
		}
	}
	if len(durations) > 0 {
		durations[len(durations)-1].Selected = true
	}
	if len(durations) == 0 && s.cfg.GracePeriod > 0 {
		durations = append(durations, durationOption{
			Value:    int(s.cfg.GracePeriod.Seconds()),
			Label:    formatDuration(t, s.cfg.GracePeriod),
			Selected: true,
		})
	}

	hostsTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err := time.LoadLocation(c.Value); err == nil {
			hostsTZ = c.Value
		}
	}

	hasEscrowed := false
	for _, hv := range hostViews {
		if hv.Escrowed {
			hasEscrowed = true
			break
		}
	}

	w.Header().Set("Content-Type", "text/html")
	if err := adminTmpl.Execute(w, map[string]interface{}{
		"Username":         username,
		"Initial":          strings.ToUpper(username[:1]),
		"Avatar":           getAvatar(r),
		"Timezone":         hostsTZ,
		"Flashes":          flashes,
		"BridgeMode":       s.isBridgeMode(),
		"Hosts":            hostViews,
		"CSRFToken":        csrfToken,
		"CSRFTs":           csrfTs,
		"Durations":        durations,
		"ActivePage":       "admin",
		"AdminTab":         "hosts",
		"DefaultPageSize":  s.cfg.DefaultPageSize,
		"Theme":            getTheme(r),
		"CSPNonce":         cspNonce(r),
		"T":                T(lang),
		"Lang":             lang,
		"Languages":        supportedLanguages,
		"IsAdmin":          true,
		"Pending":          s.buildPendingViews(username, lang),
		"AllPendingQueue":  s.buildAllPendingViews(lang),
		"HasEscrowedHosts": hasEscrowed,
		"AllGroups":        allGroups,
		"GroupFilter":      groupFilter,
		"HostSort":         hostSortBy,
		"HostDir":          hostSortDir,
		"InstallURL":       s.baseURL + "/install.sh",
		"DeployEnabled":    true,
	}); err != nil {
		slog.Error("template execution", "err", err)
	}
}

func (s *Server) handleRemoveUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminUser := s.verifyFormAuth(w, r)
	if adminUser == "" {
		return
	}
	if s.getSessionRole(r) != "admin" {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "not_authorized_message")
		return
	}
	targetUser := r.FormValue("target_user")
	if targetUser == "" || !validUsername.MatchString(targetUser) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}
	// Don't allow removing yourself
	if targetUser == adminUser {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}

	// Remove from host registry user lists
	if s.hostRegistry.IsEnabled() {
		s.hostRegistry.RemoveUserFromAllHosts(targetUser)
	}

	s.store.LogAction(targetUser, challpkg.ActionRemovedUser, "", "", adminUser)
	s.store.RemoveUser(targetUser)
	s.removedUsersMu.Lock()
	s.removedUsers[targetUser] = time.Now()
	s.removedUsersMu.Unlock()
	slog.Info("USER_REMOVED", "admin", adminUser, "user", targetUser, "remote_addr", remoteAddr(r))

	s.setFlashCookie(w, "removed_user:"+targetUser)
	http.Redirect(w, r, s.baseURL+"/admin/users", http.StatusSeeOther)
}

// handleUpdateGroupClaims handles POST /api/admin/groups/claims.
// It updates the editable identree-managed claims for a Pocket ID group, preserving
// any other claims on that group that identree does not manage.
func (s *Server) handleUpdateGroupClaims(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminUser := s.verifyFormAuth(w, r)
	if adminUser == "" {
		return
	}
	if s.getSessionRole(r) != "admin" {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "not_authorized_message")
		return
	}
	if s.pocketIDClient == nil {
		http.Error(w, "pocketid not configured", http.StatusServiceUnavailable)
		return
	}

	groupID := r.FormValue("group_id")
	if !validAdminIDPattern.MatchString(groupID) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}

	// Read current group to preserve non-editable claims.
	current, err := s.pocketIDClient.GetAdminGroupByID(groupID)
	if err != nil {
		slog.Error("get group for claims update", "group_id", groupID, "err", err)
		http.Error(w, "failed to fetch group", http.StatusInternalServerError)
		return
	}

	// Start with claims identree does not manage (preserve them).
	var claims []pocketid.Claim
	for _, cl := range current.CustomClaims {
		if !isEditableGroupClaim(cl.Key) {
			claims = append(claims, cl)
		}
	}

	// sudoClaimKeys are the group claims that carry sudo policy; validated below.
	// accessHosts is also included here so it receives the same length and
	// character checks as the sudo fields.
	sudoClaimKeys := map[string]bool{
		"sudoCommands":   true,
		"sudoHosts":      true,
		"sudoRunAsUser":  true,
		"sudoRunAsGroup": true,
		"sudoOptions":    true,
		"accessHosts":    true,
	}

	// Add non-empty form values for managed keys.
	for _, k := range editableGroupClaims {
		v := strings.TrimSpace(r.FormValue(k))
		if v == "" {
			continue
		}
		if sudoClaimKeys[k] {
			if len(v) > 4096 {
				http.Error(w, k+" exceeds maximum length of 4096 characters", http.StatusBadRequest)
				return
			}
			if strings.ContainsAny(v, "\x00\n\r") {
				http.Error(w, k+" contains invalid characters (null byte, newline, or carriage return)", http.StatusBadRequest)
				return
			}
		}
		claims = append(claims, pocketid.Claim{Key: k, Value: v})
	}

	if err := s.pocketIDClient.PutGroupClaims(groupID, claims); err != nil {
		slog.Error("put group claims", "group_id", groupID, "err", err)
		http.Error(w, "failed to update claims", http.StatusInternalServerError)
		return
	}

	s.pocketIDClient.InvalidateCache()
	s.store.LogAction(adminUser, challpkg.ActionClaimsUpdated, current.Name, "", adminUser)
	slog.Info("CLAIMS_UPDATED", "admin", adminUser, "group_id", groupID, "remote_addr", remoteAddr(r))
	if r.Header.Get("Accept") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
		return
	}
	http.Redirect(w, r, s.baseURL+"/admin/groups", http.StatusSeeOther)
}

// handleUpdateUserClaims handles POST /api/admin/users/claims.
// It updates the sshPublicKey* claims for a Pocket ID user, preserving all other claims.
func (s *Server) handleUpdateUserClaims(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminUser := s.verifyFormAuth(w, r)
	if adminUser == "" {
		return
	}
	if s.getSessionRole(r) != "admin" {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "not_authorized_message")
		return
	}
	if s.pocketIDClient == nil {
		http.Error(w, "pocketid not configured", http.StatusServiceUnavailable)
		return
	}

	userID := r.FormValue("user_id")
	if !validAdminIDPattern.MatchString(userID) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}

	// Read current user to preserve non-SSH claims.
	current, err := s.pocketIDClient.GetAdminUserByID(userID)
	if err != nil {
		slog.Error("get user for claims update", "user_id", userID, "err", err)
		http.Error(w, "failed to fetch user", http.StatusInternalServerError)
		return
	}

	// Start with non-SSH claims (preserve them).
	// Start with claims identree does not manage (preserve them).
	var claims []pocketid.Claim
	for _, cl := range current.CustomClaims {
		if !sshKeyClaimPattern.MatchString(cl.Key) && !isEditableUserClaim(cl.Key) {
			claims = append(claims, cl)
		}
	}

	// Add simple POSIX claims from form (empty value = omit/delete the claim).
	for _, k := range editableUserClaims {
		v := strings.TrimSpace(r.FormValue(k))
		if v == "" {
			continue
		}
		switch k {
		case "loginShell":
			if len(v) > 256 {
				http.Error(w, "loginShell exceeds maximum length of 256 characters", http.StatusBadRequest)
				return
			}
			if !validLoginShellPattern.MatchString(v) {
				http.Error(w, "loginShell must start with / and contain only alphanumeric characters, /, _, ., or -", http.StatusBadRequest)
				return
			}
		case "homeDirectory":
			if len(v) > 256 {
				http.Error(w, "homeDirectory exceeds maximum length of 256 characters", http.StatusBadRequest)
				return
			}
			if !strings.HasPrefix(v, "/") {
				http.Error(w, "homeDirectory must be an absolute path starting with /", http.StatusBadRequest)
				return
			}
			for _, seg := range strings.Split(v, "/") {
				if seg == ".." {
					http.Error(w, "homeDirectory must not contain .. path segments", http.StatusBadRequest)
					return
				}
			}
		}
		claims = append(claims, pocketid.Claim{Key: k, Value: v})
	}

	// Add SSH keys from form (ssh_keys[] repeated field); number them sequentially.
	if err := r.ParseForm(); err == nil {
		keyIdx := 0
		for _, k := range r.Form["ssh_keys"] {
			if keyIdx >= 50 {
				http.Error(w, "too many SSH keys: maximum is 50", http.StatusBadRequest)
				return
			}
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			// Validate SSH public key format before storing.
			if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k)); err != nil {
				http.Error(w, fmt.Sprintf("invalid SSH public key at index %d: %v", keyIdx, err), http.StatusBadRequest)
				return
			}
			keyName := "sshPublicKey"
			if keyIdx > 0 {
				keyName = fmt.Sprintf("sshPublicKey%d", keyIdx)
			}
			claims = append(claims, pocketid.Claim{Key: keyName, Value: k})
			keyIdx++
		}
	}

	if err := s.pocketIDClient.PutUserClaims(userID, claims); err != nil {
		slog.Error("put user claims", "user_id", userID, "err", err)
		http.Error(w, "failed to update claims", http.StatusInternalServerError)
		return
	}

	s.pocketIDClient.InvalidateCache()
	s.store.LogAction(adminUser, challpkg.ActionClaimsUpdated, current.Username, "", adminUser)
	slog.Info("CLAIMS_UPDATED", "admin", adminUser, "user_id", userID, "remote_addr", remoteAddr(r))
	if r.Header.Get("Accept") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
		return
	}
	http.Redirect(w, r, s.baseURL+"/admin/users", http.StatusSeeOther)
}

// handleGetUserClaims handles GET /api/admin/users/claims?user_id=...
// Returns JSON with the user's current SSH keys and read-only claims for the UI to render.
func (s *Server) handleGetUserClaims(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.getSessionUser(r) == "" || s.getSessionRole(r) != "admin" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.pocketIDClient == nil {
		http.Error(w, "pocketid not configured", http.StatusServiceUnavailable)
		return
	}

	userID := r.URL.Query().Get("user_id")
	if !validAdminIDPattern.MatchString(userID) {
		http.Error(w, "invalid user_id", http.StatusBadRequest)
		return
	}

	user, err := s.pocketIDClient.GetAdminUserByID(userID)
	if err != nil {
		slog.Error("get user claims", "user_id", userID, "err", err)
		http.Error(w, "failed to fetch user", http.StatusInternalServerError)
		return
	}

	type claimsResponse struct {
		SSHKeys     []string         `json:"ssh_keys"`
		OtherClaims []pocketid.Claim `json:"other_claims"`
	}
	resp := claimsResponse{}
	for _, cl := range user.CustomClaims {
		if sshKeyClaimPattern.MatchString(cl.Key) {
			resp.SSHKeys = append(resp.SSHKeys, cl.Value)
		} else {
			resp.OtherClaims = append(resp.OtherClaims, cl)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleAdminRestart exits the process so the container/process supervisor can restart it,
// reloading configuration from disk.
// POST /api/admin/restart
func (s *Server) handleAdminRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}
	if s.getSessionRole(r) != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.store.LogAction(username, challpkg.ActionServerRestarted, "", "", username)
	slog.Info("server restart requested via admin UI", "user", username)
	w.WriteHeader(http.StatusNoContent)
	go func() {
		time.Sleep(300 * time.Millisecond)
		// Send SIGTERM to trigger the graceful shutdown path (drain HTTP, flush
		// session state, wait for notifications) rather than hard-exiting.
		if p, err := os.FindProcess(os.Getpid()); err == nil {
			_ = p.Signal(os.Interrupt)
		}
	}()
}
