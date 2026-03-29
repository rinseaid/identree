package server

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/pocketid"
)

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
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
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

	username := s.getSessionUser(r)
	if username == "" {
		setFlashCookie(w, "expired:")
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, username, s.getSessionRole(r))
	if s.getSessionRole(r) != "admin" {
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
		return
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	adminTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err := time.LoadLocation(c.Value); err == nil {
			adminTZ = c.Value
		}
	}

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
		"Theme":               getTheme(r),
		"CSPNonce":            cspNonce(r),
		"T":                   T(lang),
		"Lang":                lang,
		"Languages":           supportedLanguages,
		"IsAdmin":             true,
		"Version":             version,
		"CommitShort":         commitShort(commit),
		"Commit":              commit,
		"Uptime":              formatDuration(time.Since(serverStartTime)),
		"GoVersion":           runtime.Version(),
		"OSArch":              runtime.GOOS + "/" + runtime.GOARCH,
		"Goroutines":          runtime.NumGoroutine(),
		"MemUsage":            fmt.Sprintf("%.1f MB alloc / %.1f MB sys", float64(memStats.Alloc)/1024/1024, float64(memStats.Sys)/1024/1024),
		"ActiveSessionsCount": len(s.store.AllActiveSessions()),
	}); err != nil {
		log.Printf("ERROR: template execution: %v", err)
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
		setFlashCookie(w, "expired:")
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
		return
	}
	if s.getSessionRole(r) != "admin" {
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, username, s.getSessionRole(r))

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
		if err != nil || time.Since(time.Unix(tsInt, 0)).Abs() > 5*time.Minute {
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
		if err := validateConfigValues(values); err != nil {
			setFlashCookie(w, "config_error:"+err.Error())
			http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/admin/config", http.StatusSeeOther)
			return
		}

		// Write TOML.
		if err := config.SaveTOMLConfig(config.DefaultTOMLConfigPath, values); err != nil {
			setFlashCookie(w, "config_error:"+err.Error())
			http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/admin/config", http.StatusSeeOther)
			return
		}

		// Apply live-safe changes.
		s.applyLiveConfigUpdates(values)

		setFlashCookie(w, "config_saved:")
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/admin/config", http.StatusSeeOther)
		return
	}

	// GET: parse flash messages.
	var flashes []string
	var flashErrors []string
	if fp := getAndClearFlash(w, r); fp != "" {
		for _, f := range strings.Split(fp, ",") {
			parts := strings.SplitN(f, ":", 2)
			if len(parts) == 2 {
				switch parts[0] {
				case "config_saved":
					flashes = append(flashes, t("config_saved"))
				case "config_error":
					flashErrors = append(flashErrors, parts[1])
				}
			}
		}
	}

	now := time.Now()
	csrfTs := fmt.Sprintf("%d", now.Unix())
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
		"Flashes":       flashes,
		"FlashErrors":   flashErrors,
		"ActivePage":    "admin",
		"AdminTab":      "config",
		"BridgeMode":    s.isBridgeMode(),
		"Theme":         getTheme(r),
		"CSPNonce":      cspNonce(r),
		"T":             T(lang),
		"Lang":          lang,
		"Languages":     supportedLanguages,
		"IsAdmin":       true,
		"CSRFToken":     csrfToken,
		"CSRFTs":        csrfTs,
		"ConfigValues":  configToValues(s.cfg),
		"ConfigLocked":  configLockedKeys(),
		"ConfigSecrets": configSecretStatus(s.cfg),
		"APIKeyCount":   apiKeyStr,
	}); err != nil {
		log.Printf("ERROR: template execution: %v", err)
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
		"IDENTREE_CHALLENGE_TTL":                   formatDuration(cfg.ChallengeTTL),
		"IDENTREE_GRACE_PERIOD":                    formatDuration(cfg.GracePeriod),
		"IDENTREE_ONE_TAP_MAX_AGE":                 formatDuration(cfg.OneTapMaxAge),
		"IDENTREE_LDAP_ENABLED":                    boolToString(cfg.LDAPEnabled),
		"IDENTREE_LDAP_LISTEN_ADDR":                cfg.LDAPListenAddr,
		"IDENTREE_LDAP_BASE_DN":                    cfg.LDAPBaseDN,
		"IDENTREE_LDAP_BIND_DN":                    cfg.LDAPBindDN,
		"IDENTREE_LDAP_REFRESH_INTERVAL":           formatDuration(cfg.LDAPRefreshInterval),
		"IDENTREE_LDAP_UID_MAP_FILE":               cfg.LDAPUIDMapFile,
		"IDENTREE_SUDO_NO_AUTHENTICATE":            cfg.LDAPSudoNoAuthenticate,
		"IDENTREE_SUDO_RULES_FILE":                 cfg.SudoRulesFile,
		"IDENTREE_LDAP_UID_BASE":                   strconv.Itoa(cfg.LDAPUIDBase),
		"IDENTREE_LDAP_GID_BASE":                   strconv.Itoa(cfg.LDAPGIDBase),
		"IDENTREE_LDAP_DEFAULT_SHELL":              cfg.LDAPDefaultShell,
		"IDENTREE_LDAP_DEFAULT_HOME":               cfg.LDAPDefaultHome,
		"IDENTREE_ADMIN_GROUPS":                    strings.Join(cfg.AdminGroups, ", "),
		"IDENTREE_ADMIN_APPROVAL_HOSTS":            strings.Join(cfg.AdminApprovalHosts, ", "),
		"IDENTREE_NOTIFY_COMMAND":                  cfg.NotifyCommand,
		"IDENTREE_NOTIFY_USERS_FILE":               cfg.NotifyUsersFile,
		"IDENTREE_ESCROW_BACKEND":                  string(cfg.EscrowBackend),
		"IDENTREE_ESCROW_URL":                      cfg.EscrowURL,
		"IDENTREE_ESCROW_AUTH_ID":                  cfg.EscrowAuthID,
		"IDENTREE_ESCROW_PATH":                     cfg.EscrowPath,
		"IDENTREE_ESCROW_WEB_URL":                  cfg.EscrowWebURL,
		"IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE": cfg.ClientBreakglassPasswordType,
		"IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS": strconv.Itoa(cfg.ClientBreakglassRotationDays),
		"IDENTREE_CLIENT_TOKEN_CACHE_ENABLED":      tokenCache,
		"IDENTREE_HOST_REGISTRY_FILE":              cfg.HostRegistryFile,
		"IDENTREE_HISTORY_PAGE_SIZE":               strconv.Itoa(cfg.DefaultHistoryPageSize),
		"IDENTREE_SESSION_STATE_FILE":              cfg.SessionStateFile,
		"IDENTREE_DEV_LOGIN":                       boolToString(cfg.DevLoginEnabled),
	}
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
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
		"IDENTREE_OIDC_CLIENT_SECRET": cfg.ClientSecret != "",
		"IDENTREE_POCKETID_API_KEY":   cfg.APIKey != "",
		"IDENTREE_SHARED_SECRET":      cfg.SharedSecret != "",
		"IDENTREE_LDAP_BIND_PASSWORD": cfg.LDAPBindPassword != "",
		"IDENTREE_ESCROW_AUTH_SECRET":     cfg.EscrowAuthSecret != "",
		"IDENTREE_ESCROW_ENCRYPTION_KEY": cfg.EscrowEncryptionKey != "",
		"IDENTREE_WEBHOOK_SECRET":     cfg.WebhookSecret != "",
	}
}

// validateConfigValues validates form-submitted config values.
func validateConfigValues(values map[string]string) error {
	for _, key := range []string{
		"IDENTREE_CHALLENGE_TTL", "IDENTREE_GRACE_PERIOD",
		"IDENTREE_ONE_TAP_MAX_AGE", "IDENTREE_LDAP_REFRESH_INTERVAL",
	} {
		if v := values[key]; v != "" {
			if _, err := time.ParseDuration(v); err != nil {
				return fmt.Errorf("invalid duration for %s: %q", key, v)
			}
		}
	}
	for _, key := range []string{
		"IDENTREE_LDAP_UID_BASE", "IDENTREE_LDAP_GID_BASE",
		"IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS", "IDENTREE_HISTORY_PAGE_SIZE",
	} {
		if v := values[key]; v != "" {
			if _, err := strconv.Atoi(v); err != nil {
				return fmt.Errorf("invalid integer for %s: %q", key, v)
			}
		}
	}
	if v := values["IDENTREE_SUDO_NO_AUTHENTICATE"]; v != "" {
		switch v {
		case "true", "false", "claims":
		default:
			return fmt.Errorf("invalid value for IDENTREE_SUDO_NO_AUTHENTICATE: %q (must be true, false, or claims)", v)
		}
	}
	if v := values["IDENTREE_ESCROW_BACKEND"]; v != "" {
		switch v {
		case "1password-connect", "vault", "bitwarden", "infisical":
		default:
			return fmt.Errorf("invalid escrow backend: %q", v)
		}
	}
	if v := values["IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE"]; v != "" {
		switch v {
		case "random", "passphrase", "alphanumeric":
		default:
			return fmt.Errorf("invalid breakglass password type: %q", v)
		}
	}
	return nil
}

// applyLiveConfigUpdates applies the subset of config changes that are safe without a restart.
func (s *Server) applyLiveConfigUpdates(values map[string]string) {
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
		s.cfg.GracePeriod = parseDur("IDENTREE_GRACE_PERIOD", s.cfg.GracePeriod)
	}
	if !config.IsEnvSourced("IDENTREE_ONE_TAP_MAX_AGE") {
		s.cfg.OneTapMaxAge = parseDur("IDENTREE_ONE_TAP_MAX_AGE", s.cfg.OneTapMaxAge)
	}
	if !config.IsEnvSourced("IDENTREE_ADMIN_GROUPS") {
		s.cfg.AdminGroups = parseSlice("IDENTREE_ADMIN_GROUPS")
	}
	if !config.IsEnvSourced("IDENTREE_ADMIN_APPROVAL_HOSTS") {
		s.cfg.AdminApprovalHosts = parseSlice("IDENTREE_ADMIN_APPROVAL_HOSTS")
	}
	if !config.IsEnvSourced("IDENTREE_NOTIFY_COMMAND") {
		s.cfg.NotifyCommand = values["IDENTREE_NOTIFY_COMMAND"]
	}
	if !config.IsEnvSourced("IDENTREE_NOTIFY_USERS_FILE") {
		s.cfg.NotifyUsersFile = values["IDENTREE_NOTIFY_USERS_FILE"]
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
		}
	}
	if !config.IsEnvSourced("IDENTREE_HISTORY_PAGE_SIZE") {
		s.cfg.DefaultHistoryPageSize = parseInt("IDENTREE_HISTORY_PAGE_SIZE", s.cfg.DefaultHistoryPageSize)
	}
	if !config.IsEnvSourced("IDENTREE_SUDO_NO_AUTHENTICATE") {
		if v := values["IDENTREE_SUDO_NO_AUTHENTICATE"]; v == "true" || v == "false" || v == "claims" {
			s.cfg.LDAPSudoNoAuthenticate = v
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
		setFlashCookie(w, "expired:")
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, username, s.getSessionRole(r))

	if s.getSessionRole(r) != "admin" {
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
		return
	}

	// Parse flash messages
	var flashes []string
	if flashParam := getAndClearFlash(w, r); flashParam != "" {
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
			log.Printf("WARNING: fetching Pocket ID permissions: %v", err)
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
		ActiveSessions int
		LastActive     string
		LastActiveAgo  string
		LastActiveTime time.Time
		Groups         []pocketid.GroupInfo
		Sessions       []userSessionView
	}

	adminTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err := time.LoadLocation(c.Value); err == nil {
			adminTZ = c.Value
		}
	}
	adminLoc, _ := time.LoadLocation(adminTZ)

	now := time.Now()
	csrfTs := fmt.Sprintf("%d", now.Unix())
	csrfToken := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)

	var userViews []userView
	for _, u := range users {
		sessions := s.store.ActiveSessions(u)
		history := s.store.ActionHistory(u)
		lastActive := ""
		lastActiveAgo := ""
		var lastActiveTime time.Time
		if len(history) > 0 {
			// Find most recent entry
			var latest time.Time
			for _, e := range history {
				if e.Timestamp.After(latest) {
					latest = e.Timestamp
				}
			}
			lastActive = latest.In(adminLoc).Format("2006-01-02 15:04")
			lastActiveAgo = timeAgoI18n(latest, t)
			lastActiveTime = latest
		}
		var sessionViews []userSessionView
		for _, sess := range sessions {
			sessionViews = append(sessionViews, userSessionView{
				Hostname:        sess.Hostname,
				Remaining:       formatDuration(time.Until(sess.ExpiresAt)),
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
		"Username":   username,
		"Initial":    strings.ToUpper(username[:1]),
		"Avatar":     getAvatar(r),
		"Timezone":   adminTZ,
		"Flashes":    flashes,
		"ActivePage": "admin",
		"AdminTab":   "users",
		"BridgeMode": s.isBridgeMode(),
		"Theme":      getTheme(r),
		"CSPNonce":   cspNonce(r),
		"T":          T(lang),
		"Lang":       lang,
		"Languages":  supportedLanguages,
		"IsAdmin":    true,
		"Users":      userViews,
		"UserSort":   userSortBy,
		"UserDir":    userSortDir,
		"CSRFToken":  csrfToken,
		"CSRFTs":     csrfTs,
	}); err != nil {
		log.Printf("ERROR: template execution: %v", err)
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
		setFlashCookie(w, "expired:")
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, username, s.getSessionRole(r))
	if s.getSessionRole(r) != "admin" {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "not_authorized_message")
		return
	}
	if s.isBridgeMode() {
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/admin/sudo-rules", http.StatusSeeOther)
		return
	}

	type groupView struct {
		Name         string
		SudoCommands string
		SudoHosts    string
		SudoRunAs    string
		Members      []string
		AllCmds      bool
		AllHosts     bool
		CmdList      []string
		HostList     []string
	}

	allGroups, err := s.pocketIDClient.GetGroups()
	if err != nil {
		log.Printf("ERROR: fetching groups: %v", err)
	}

	var groups []groupView
	for _, g := range allGroups {
		claims := make(map[string]string)
		for _, cl := range g.CustomClaims {
			claims[cl.Key] = cl.Value
		}
		cmds := claims["sudoCommands"]
		hosts := claims["sudoHosts"]
		// Only include groups with sudo claims
		if cmds == "" && hosts == "" {
			continue
		}
		gv := groupView{
			Name:         g.Name,
			SudoCommands: cmds,
			SudoHosts:    hosts,
			SudoRunAs:    claims["sudoRunAsUser"],
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
	csrfTs := fmt.Sprintf("%d", now.Unix())
	csrfToken := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)

	adminTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err := time.LoadLocation(c.Value); err == nil {
			adminTZ = c.Value
		}
	}

	w.Header().Set("Content-Type", "text/html")
	if err := adminTmpl.Execute(w, map[string]interface{}{
		"Username":   username,
		"Initial":    strings.ToUpper(username[:1]),
		"Avatar":     getAvatar(r),
		"Timezone":   adminTZ,
		"AdminTab":   "groups",
		"BridgeMode": s.isBridgeMode(),
		"Groups":     groups,
		"GroupSort":  sortBy,
		"GroupDir":   sortDir,
		"Flashes":    []string{},
		"CSRFToken":  csrfToken,
		"CSRFTs":     csrfTs,
		"ActivePage": "admin",
		"Theme":      getTheme(r),
		"CSPNonce":   cspNonce(r),
		"T":          t,
		"Lang":       lang,
		"Languages":  supportedLanguages,
		"IsAdmin":    true,
	}); err != nil {
		log.Printf("ERROR: template execution: %v", err)
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
		setFlashCookie(w, "expired:")
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, username, s.getSessionRole(r))

	if s.getSessionRole(r) != "admin" {
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
		return
	}

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
	if flashParam := getAndClearFlash(w, r); flashParam != "" {
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
	if s.getSessionRole(r) == "admin" {
		if s.hostRegistry.IsEnabled() {
			// When the registry is enabled, it is the authoritative list of managed hosts.
			// Removing a host from the registry should immediately remove it from this page.
			hosts = s.hostRegistry.RegisteredHosts()
		} else {
			hosts = s.store.AllKnownHosts()
		}
	} else {
		hosts = s.store.KnownHosts(username)
	}
	escrowed := s.store.EscrowedHosts()

	// Merge escrowed hosts into the known hosts list
	escrowedSet := make(map[string]bool)
	isAdmin := s.getSessionRole(r) == "admin"
	for h := range escrowed {
		if !isAdmin && s.hostRegistry.IsEnabled() && !s.hostRegistry.IsUserAuthorized(h, username) {
			continue
		}
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
			log.Printf("WARNING: fetching Pocket ID permissions for hosts: %v", err)
		} else {
			userPerms = perms
		}
	}
	allKnownUsers := s.store.AllUsers()

	// Collect all group names for the filter dropdown
	groupFilter := r.URL.Query().Get("group")
	groupSet := make(map[string]struct{})

	var hostViews []hostView
	for _, h := range hosts {
		hv := hostView{Hostname: h}

		// Build active session map for this host
		activeMap := make(map[string]string) // username -> remaining
		for _, sess := range s.store.ActiveSessionsForHost(h) {
			activeMap[sess.Username] = formatDuration(time.Until(sess.ExpiresAt))
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
			hv.EscrowAge = formatDuration(time.Since(escrowRecord.Timestamp))
			hv.EscrowExpired = time.Since(escrowRecord.Timestamp) > time.Duration(rotationDays)*24*time.Hour
			hv.EscrowLink = deriveEscrowLink(string(s.cfg.EscrowBackend), s.cfg.EscrowURL, s.cfg.EscrowPath, escrowRecord.ItemID, escrowRecord.VaultID, s.cfg.EscrowWebURL, h)
			// Reveal is available for all native backends (local, 1password-connect, vault, bitwarden, infisical).
			// Command-based escrow has no standardised retrieval API.
			hv.EscrowRevealable = isAdmin && s.cfg.EscrowBackend != "" && s.cfg.EscrowCommand == ""
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
	csrfTs := fmt.Sprintf("%d", now.Unix())
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
			Label:    formatDuration(s.cfg.GracePeriod),
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
		"Theme":            getTheme(r),
		"CSPNonce":         cspNonce(r),
		"T":                T(lang),
		"Lang":             lang,
		"Languages":        supportedLanguages,
		"IsAdmin":          true,
		"HasEscrowedHosts": hasEscrowed,
		"AllGroups":        allGroups,
		"GroupFilter":      groupFilter,
		"HostSort":         hostSortBy,
		"HostDir":          hostSortDir,
		"InstallURL":       strings.TrimRight(s.cfg.ExternalURL, "/") + "/install.sh",
		"DeployEnabled":    true,
	}); err != nil {
		log.Printf("ERROR: template execution: %v", err)
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

	s.store.LogAction(targetUser, "user_removed", "", "", adminUser)
	s.store.RemoveUser(targetUser)
	s.removedUsersMu.Lock()
	s.removedUsers[targetUser] = time.Now()
	s.removedUsersMu.Unlock()
	log.Printf("USER_REMOVED: admin %q removed user %q from %s", adminUser, targetUser, remoteAddr(r))

	setFlashCookie(w, "removed_user:"+targetUser)
	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/admin/users", http.StatusSeeOther)
}
