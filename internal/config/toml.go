package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultTOMLConfigPath is the TOML configuration file written by the admin UI.
// Override with IDENTREE_TOML_CONFIG_FILE env var (useful in Docker where /etc is not writable).
const DefaultTOMLConfigPath = "/etc/identree/config.toml"

// TOMLConfigPath returns the active TOML config file path, respecting the
// IDENTREE_TOML_CONFIG_FILE environment variable override.
func TOMLConfigPath() string {
	if v := os.Getenv("IDENTREE_TOML_CONFIG_FILE"); v != "" {
		return v
	}
	return DefaultTOMLConfigPath
}

// TOMLField describes a single configurable value in the TOML file.
type TOMLField struct {
	Key    string // TOML key within the section
	EnvKey string // IDENTREE_* environment variable name
	IsList bool   // stored as TOML string array (comma-separated in env format)
	IsBool bool   // checkbox field: form absence means false
}

// TOMLSection describes a named TOML section and its fields.
type TOMLSection struct {
	Name   string
	Fields []TOMLField
}

// TOMLSections is the canonical ordered list of TOML sections and their fields.
// Sensitive credentials (secrets, API keys, passwords) are intentionally excluded;
// they must be supplied via environment variables only.
var TOMLSections = []TOMLSection{
	{Name: "oidc", Fields: []TOMLField{
		{Key: "issuer_url", EnvKey: "IDENTREE_OIDC_ISSUER_URL"},
		{Key: "issuer_public_url", EnvKey: "IDENTREE_OIDC_ISSUER_PUBLIC_URL"},
		{Key: "client_id", EnvKey: "IDENTREE_OIDC_CLIENT_ID"},
	}},
	{Name: "pocketid", Fields: []TOMLField{
		{Key: "api_url", EnvKey: "IDENTREE_POCKETID_API_URL"},
	}},
	{Name: "server", Fields: []TOMLField{
		{Key: "listen_addr", EnvKey: "IDENTREE_LISTEN_ADDR"},
		{Key: "external_url", EnvKey: "IDENTREE_EXTERNAL_URL"},
		{Key: "install_url", EnvKey: "IDENTREE_INSTALL_URL"},
	}},
	{Name: "auth", Fields: []TOMLField{
		{Key: "challenge_ttl", EnvKey: "IDENTREE_CHALLENGE_TTL"},
		{Key: "grace_period", EnvKey: "IDENTREE_GRACE_PERIOD"},
		{Key: "onetap_max_age", EnvKey: "IDENTREE_ONE_TAP_MAX_AGE"},
	}},
	{Name: "ldap", Fields: []TOMLField{
		{Key: "enabled", EnvKey: "IDENTREE_LDAP_ENABLED", IsBool: true},
		{Key: "listen_addr", EnvKey: "IDENTREE_LDAP_LISTEN_ADDR"},
		{Key: "base_dn", EnvKey: "IDENTREE_LDAP_BASE_DN"},
		{Key: "bind_dn", EnvKey: "IDENTREE_LDAP_BIND_DN"},
		{Key: "refresh_interval", EnvKey: "IDENTREE_LDAP_REFRESH_INTERVAL"},
		{Key: "uid_map_file", EnvKey: "IDENTREE_LDAP_UID_MAP_FILE"},
		{Key: "sudo_no_authenticate", EnvKey: "IDENTREE_SUDO_NO_AUTHENTICATE"},
		{Key: "sudo_rules_file", EnvKey: "IDENTREE_SUDO_RULES_FILE"},
		{Key: "uid_base", EnvKey: "IDENTREE_LDAP_UID_BASE"},
		{Key: "gid_base", EnvKey: "IDENTREE_LDAP_GID_BASE"},
		{Key: "default_shell", EnvKey: "IDENTREE_LDAP_DEFAULT_SHELL"},
		{Key: "default_home", EnvKey: "IDENTREE_LDAP_DEFAULT_HOME"},
	}},
	{Name: "admin", Fields: []TOMLField{
		{Key: "groups", EnvKey: "IDENTREE_ADMIN_GROUPS", IsList: true},
		{Key: "approval_hosts", EnvKey: "IDENTREE_ADMIN_APPROVAL_HOSTS", IsList: true},
	}},
	{Name: "notifications", Fields: []TOMLField{
		{Key: "backend", EnvKey: "IDENTREE_NOTIFY_BACKEND"},
		{Key: "url", EnvKey: "IDENTREE_NOTIFY_URL"},
		{Key: "command", EnvKey: "IDENTREE_NOTIFY_COMMAND"},
		{Key: "timeout", EnvKey: "IDENTREE_NOTIFY_TIMEOUT"},
	}},
	{Name: "escrow", Fields: []TOMLField{
		{Key: "backend", EnvKey: "IDENTREE_ESCROW_BACKEND"},
		{Key: "url", EnvKey: "IDENTREE_ESCROW_URL"},
		{Key: "auth_id", EnvKey: "IDENTREE_ESCROW_AUTH_ID"},
		{Key: "path", EnvKey: "IDENTREE_ESCROW_PATH"},
		{Key: "web_url", EnvKey: "IDENTREE_ESCROW_WEB_URL"},
	}},
	{Name: "client_defaults", Fields: []TOMLField{
		{Key: "breakglass_password_type", EnvKey: "IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE"},
		{Key: "breakglass_rotation_days", EnvKey: "IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS"},
		{Key: "token_cache_enabled", EnvKey: "IDENTREE_CLIENT_TOKEN_CACHE_ENABLED", IsBool: true},
	}},
	{Name: "misc", Fields: []TOMLField{
		{Key: "host_registry_file", EnvKey: "IDENTREE_HOST_REGISTRY_FILE"},
		{Key: "default_page_size", EnvKey: "IDENTREE_HISTORY_PAGE_SIZE"},
		{Key: "session_state_file", EnvKey: "IDENTREE_SESSION_STATE_FILE"},
		{Key: "dev_login", EnvKey: "IDENTREE_DEV_LOGIN", IsBool: true},
	}},
}

// IsEnvSourced returns true if the given env var key is set in the process environment.
func IsEnvSourced(key string) bool {
	return os.Getenv(key) != ""
}

// LoadTOMLConfig reads the TOML config file and returns a map keyed by env var names.
// Returns an error wrapping os.ErrNotExist if the file does not exist.
func LoadTOMLConfig(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Build lookup: "section.key" → TOMLField
	lookup := make(map[string]TOMLField)
	for _, sec := range TOMLSections {
		for _, fld := range sec.Fields {
			lookup[sec.Name+"."+fld.Key] = fld
		}
	}

	result := make(map[string]string)
	currentSection := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		valRaw := strings.TrimSpace(line[idx+1:])
		// Strip inline comment, but only outside quoted strings.
		// A ` #` inside a quoted value (e.g. a URL with a hash) must be preserved.
		if len(valRaw) > 0 && valRaw[0] == '"' {
			// Scan to the closing quote, skipping backslash-escaped characters.
			closeIdx := -1
			for i := 1; i < len(valRaw); i++ {
				if valRaw[i] == '\\' {
					i++ // skip the escaped character
					continue
				}
				if valRaw[i] == '"' {
					closeIdx = i
					break
				}
			}
			// If a closing quote was found, strip any trailing comment after it.
			if closeIdx >= 0 {
				after := valRaw[closeIdx+1:]
				if ci := strings.Index(after, " #"); ci >= 0 {
					valRaw = valRaw[:closeIdx+1]
				}
			}
		} else if ci := strings.Index(valRaw, " #"); ci >= 0 {
			valRaw = strings.TrimSpace(valRaw[:ci])
		}

		fld, ok := lookup[currentSection+"."+key]
		if !ok {
			continue
		}
		result[fld.EnvKey] = parseTOMLValue(valRaw, fld.IsList)
	}
	return result, scanner.Err()
}

// parseTOMLValue converts a raw TOML token to a string in env-var format.
// For list fields, the TOML array ["a", "b"] becomes the comma-separated string "a,b".
func parseTOMLValue(raw string, isList bool) string {
	if isList {
		raw = strings.TrimSpace(raw)
		if !strings.HasPrefix(raw, "[") || !strings.HasSuffix(raw, "]") {
			return raw
		}
		inner := strings.TrimSpace(raw[1 : len(raw)-1])
		if inner == "" {
			return ""
		}
		// Parse comma-separated items, respecting quoted strings so that
		// a value like ["admin, ops", "users"] splits into two items, not three.
		var items []string
		inQuote := false
		var cur strings.Builder
		for i := 0; i < len(inner); i++ {
			c := inner[i]
			if c == '\\' && inQuote && i+1 < len(inner) {
				cur.WriteByte(inner[i+1])
				i++
				continue
			}
			if c == '"' {
				inQuote = !inQuote
				continue
			}
			if c == '\'' && !inQuote {
				// single-quoted items — skip the quote char
				continue
			}
			if c == ',' && !inQuote {
				if item := strings.TrimSpace(cur.String()); item != "" {
					items = append(items, item)
				}
				cur.Reset()
				continue
			}
			cur.WriteByte(c)
		}
		if item := strings.TrimSpace(cur.String()); item != "" {
			items = append(items, item)
		}
		return strings.Join(items, ",")
	}
	// Quoted string
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		s := raw[1 : len(raw)-1]
		s = strings.ReplaceAll(s, `\\`, `\`)
		s = strings.ReplaceAll(s, `\"`, `"`)
		s = strings.ReplaceAll(s, `\n`, "\n")
		s = strings.ReplaceAll(s, `\t`, "\t")
		return s
	}
	return raw
}

// SaveTOMLConfig writes a TOML config file from the provided env-var-keyed values map.
// Only fields defined in TOMLSections are written. Fields absent from values are written as empty.
func SaveTOMLConfig(path string, values map[string]string) error {
	var sb strings.Builder
	sb.WriteString("# identree configuration\n")
	sb.WriteString("# Generated by the identree admin UI.\n")
	sb.WriteString("# Fields set via environment variables take precedence and are not stored here.\n\n")

	for _, sec := range TOMLSections {
		sb.WriteString("[" + sec.Name + "]\n")
		for _, fld := range sec.Fields {
			val := values[fld.EnvKey]
			if fld.IsList {
				sb.WriteString(fld.Key + " = [")
				if val != "" {
					parts := strings.Split(val, ",")
					for i, p := range parts {
						p = strings.TrimSpace(p)
						if i > 0 {
							sb.WriteString(", ")
						}
						sb.WriteString(`"` + tomlEscapeString(p) + `"`)
					}
				}
				sb.WriteString("]\n")
			} else {
				// Only write non-empty scalar values. Empty means "use default";
				// absent keys load back as "" which is identical to writing `key = ""`.
				// This prevents stale values (e.g. a previously-set escrow backend)
				// from persisting in the TOML after the field is cleared in the UI.
				if val != "" {
					sb.WriteString(fld.Key + " = " + formatTOMLScalar(val) + "\n")
				}
			}
		}
		sb.WriteString("\n")
	}

	// Ensure parent directory exists.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}
	// Write atomically: write to a temp file in the same directory, then
	// rename into place. This prevents a partial write from leaving a corrupt
	// config file if the process is killed mid-write.
	tmp, err := os.CreateTemp(dir, ".identree-config-*.toml")
	if err != nil {
		return fmt.Errorf("creating temp config file: %w", err)
	}
	tmpName := tmp.Name()
	if err := func() error {
		defer tmp.Close()
		if err := tmp.Chmod(0600); err != nil {
			return fmt.Errorf("setting temp file permissions: %w", err)
		}
		if _, err := tmp.WriteString(sb.String()); err != nil {
			return fmt.Errorf("writing temp config file: %w", err)
		}
		return tmp.Sync()
	}(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("renaming temp config file: %w", err)
	}
	return nil
}

// formatTOMLScalar formats a scalar value for TOML output.
// Booleans and non-negative integers are written unquoted; everything else is quoted.
func formatTOMLScalar(val string) string {
	if val == "true" || val == "false" {
		return val
	}
	if len(val) > 0 {
		allDigits := true
		for _, c := range val {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return val
		}
	}
	return `"` + tomlEscapeString(val) + `"`
}

// tomlEscapeString escapes a string for use in a TOML basic string.
func tomlEscapeString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return s
}
