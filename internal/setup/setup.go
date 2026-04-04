// Package setup implements the `identree setup` subcommand which auto-configures
// SSSD, PAM, and nsswitch.conf on a managed host using credentials fetched from
// the identree server's provision endpoint.
package setup

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config holds the flags accepted by `identree setup`.
type Config struct {
	// ServerURL is read from the client config (IDENTREE_SERVER_URL).
	ServerURL string
	// SharedSecret is read from the client config (IDENTREE_SHARED_SECRET).
	SharedSecret string
	// Hostname to use when requesting bind credentials. Defaults to os.Hostname.
	Hostname string
	// SSSD configures SSSD + nsswitch in addition to PAM.
	SSSD bool
	// Force overwrites existing config files even when they look up-to-date.
	Force bool
	// DryRun prints what would be done without making changes.
	DryRun bool
}

// provisionResponse mirrors the server-side struct in handlers_provision.go.
type provisionResponse struct {
	LDAPUrl      string `json:"ldap_url"`
	BaseDN       string `json:"base_dn"`
	BindDN       string `json:"bind_dn"`
	BindPassword string `json:"bind_password"`
	TLSCACert    string `json:"tls_ca_cert,omitempty"`
}

// Run executes the setup subcommand. It returns an error on failure.
func Run(cfg Config) error {
	if os.Getuid() != 0 {
		return fmt.Errorf("must be run as root")
	}

	hostname := cfg.Hostname
	if hostname == "" {
		var err error
		hostname, err = os.Hostname()
		if err != nil {
			return fmt.Errorf("hostname: %w", err)
		}
	}

	if cfg.SSSD && cfg.ServerURL == "" {
		return fmt.Errorf("--sssd requires IDENTREE_SERVER_URL in /etc/identree/client.conf")
	}

	// Configure PAM — always done regardless of --sssd.
	if err := configurePAM(cfg.DryRun, cfg.Force); err != nil {
		return fmt.Errorf("PAM: %w", err)
	}

	if cfg.SSSD {
		prov, err := fetchProvision(cfg.ServerURL, cfg.SharedSecret, hostname)
		if err != nil {
			return fmt.Errorf("provision: %w", err)
		}
		if err := writeSSSDConfig(prov, hostname, cfg.DryRun, cfg.Force); err != nil {
			return fmt.Errorf("sssd.conf: %w", err)
		}
		if err := configureNsswitch(cfg.DryRun, cfg.Force, "sss"); err != nil {
			return fmt.Errorf("nsswitch: %w", err)
		}
		// Write the LDAP TLS CA cert if provided.
		if prov.TLSCACert != "" {
			if err := writeTLSCACert(prov.TLSCACert, cfg.DryRun); err != nil {
				return fmt.Errorf("tls_ca_cert: %w", err)
			}
		}
	}

	return nil
}

// ── Provision endpoint ────────────────────────────────────────────────────────

func fetchProvision(serverURL, sharedSecret, hostname string) (*provisionResponse, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	url := strings.TrimRight(serverURL, "/") + "/api/client/provision"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Shared-Secret", sharedSecret)
	req.Header.Set("X-Hostname", hostname)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var prov provisionResponse
	if err := json.Unmarshal(body, &prov); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &prov, nil
}

// ── PAM configuration ─────────────────────────────────────────────────────────

// pamLine is the auth line inserted by identree.
const pamLine = "auth    required    pam_exec.so    stdout /usr/local/bin/identree"

// pamFiles are the PAM service files to configure.
var pamFiles = []string{"/etc/pam.d/sudo", "/etc/pam.d/sudo-i"}

func configurePAM(dryRun, force bool) error {
	for _, path := range pamFiles {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		modified, err := insertPAMLine(path, pamLine, dryRun, force)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if modified {
			fmt.Printf("PAM: updated %s\n", path)
		} else {
			fmt.Printf("PAM: %s already configured\n", path)
		}
	}
	return nil
}

// insertPAMLine inserts pamLine before the first auth or @include line in path,
// unless it is already present. Returns true if the file was modified.
func insertPAMLine(path, line string, dryRun, force bool) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	lines := splitLines(string(data))

	// Already present? Idempotent regardless of force: if the line is correct,
	// there is nothing to do. Proceeding past this check when force=true would
	// insert a second copy before the first auth/include line.
	for _, l := range lines {
		if strings.TrimSpace(l) == strings.TrimSpace(line) {
			return false, nil
		}
	}

	// Insert before first auth or @include line.
	var out []string
	inserted := false
	for _, l := range lines {
		if !inserted && (isAuthLine(l) || strings.HasPrefix(strings.TrimSpace(l), "@include")) {
			out = append(out, line)
			inserted = true
		}
		out = append(out, l)
	}
	if !inserted {
		out = append(out, line)
	}

	if dryRun {
		fmt.Printf("[dry-run] would write %s\n", path)
		return true, nil
	}

	// Write atomically via temp file.
	return true, atomicWrite(path, []byte(strings.Join(out, "\n")), 0644)
}

func isAuthLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "#") || trimmed == "" {
		return false
	}
	fields := strings.Fields(trimmed)
	return len(fields) > 0 && fields[0] == "auth"
}

// ── nsswitch.conf ─────────────────────────────────────────────────────────────

// configureNsswitch ensures provider is present in passwd and group lines.
func configureNsswitch(dryRun, force bool, provider string) error {
	const nssFile = "/etc/nsswitch.conf"
	data, err := os.ReadFile(nssFile)
	if os.IsNotExist(err) {
		fmt.Printf("nsswitch: %s not found, skipping\n", nssFile)
		return nil
	}
	if err != nil {
		return err
	}

	lines := splitLines(string(data))
	changed := false
	for i, l := range lines {
		for _, db := range []string{"passwd", "group"} {
			if !strings.HasPrefix(strings.TrimSpace(l), db+":") {
				continue
			}
			fields := strings.Fields(l)
			for _, f := range fields[1:] {
				if f == provider {
					goto alreadyPresent
				}
			}
			lines[i] = l + " " + provider
			changed = true
			fmt.Printf("nsswitch: added %s to %s line\n", provider, db)
			continue
		alreadyPresent:
			fmt.Printf("nsswitch: %s already in %s line\n", provider, db)
		}
	}

	if !changed {
		return nil
	}
	if dryRun {
		fmt.Printf("[dry-run] would write %s\n", nssFile)
		return nil
	}
	return atomicWrite(nssFile, []byte(strings.Join(lines, "\n")), 0644)
}

// ── SSSD configuration ────────────────────────────────────────────────────────

// sssdConfigDir returns the distribution-appropriate path for sssd.conf.
// Both Debian/Ubuntu and RHEL/Fedora use /etc/sssd/sssd.conf.
const sssdConfigDir = "/etc/sssd"
const sssdConfigPath = "/etc/sssd/sssd.conf"

// sssdConfigTmpl is the sssd.conf template. Callers substitute:
// [0] ldap_uri, [1] ldap_search_base, [2] ldap_default_bind_dn,
// [3] ldap_default_authtok, [4] ldap_tls_reqcert, [5] optional extra
// lines (e.g. "ldap_tls_cacert = /path\n") appended to the domain section.
const sssdConfigTmpl = `[sssd]
services = nss, pam
config_file_version = 2
domains = identree

[domain/identree]
id_provider = ldap
auth_provider = none
ldap_uri = %s
ldap_search_base = %s
ldap_default_bind_dn = %s
ldap_default_authtok = %s
ldap_default_authtok_type = password
ldap_id_use_start_tls = false
ldap_tls_reqcert = %s
%sldap_schema = rfc2307
enumerate = true
cache_credentials = true

[nss]
homedir_substring = /home

[pam]
`

// sssdCACertPath is the path where the LDAP TLS CA cert is stored within
// the SSSD config directory so that SSSD can find it without relying on
// the system trust store (which requires running update-ca-certificates).
const sssdCACertPath = "/etc/sssd/identree-ldap-ca.crt"

func writeSSSDConfig(prov *provisionResponse, hostname string, dryRun, force bool) error {
	if err := os.MkdirAll(sssdConfigDir, 0700); err != nil && !os.IsExist(err) {
		return err
	}

	// If a config already exists and --force is not set, skip.
	if _, err := os.Stat(sssdConfigPath); err == nil && !force {
		fmt.Printf("SSSD: %s already exists (use --force to overwrite)\n", sssdConfigPath)
		return nil
	}

	tlsReqcert := "never"
	cacertLine := ""
	if prov.TLSCACert != "" {
		tlsReqcert = "demand"
		// Point SSSD explicitly at the cert file so it doesn't depend on the
		// system trust store or update-ca-certificates having been run.
		cacertLine = "ldap_tls_cacert = " + sssdCACertPath + "\n"
	}

	content := fmt.Sprintf(sssdConfigTmpl,
		prov.LDAPUrl,
		prov.BaseDN,
		prov.BindDN,
		prov.BindPassword,
		tlsReqcert,
		cacertLine,
	)

	// Write the CA cert into the SSSD config directory alongside sssd.conf so
	// SSSD can find it without relying on system trust store state.
	if prov.TLSCACert != "" && !dryRun {
		if err := atomicWrite(sssdCACertPath, []byte(prov.TLSCACert), 0644); err != nil {
			return fmt.Errorf("write LDAP CA cert to %s: %w", sssdCACertPath, err)
		}
		fmt.Printf("SSSD: wrote LDAP CA cert to %s\n", sssdCACertPath)
	} else if prov.TLSCACert != "" && dryRun {
		fmt.Printf("[dry-run] would write LDAP CA cert to %s\n", sssdCACertPath)
	}

	if dryRun {
		fmt.Printf("[dry-run] would write %s\n", sssdConfigPath)
		return nil
	}

	if err := atomicWrite(sssdConfigPath, []byte(content), 0600); err != nil {
		return err
	}
	fmt.Printf("SSSD: wrote %s\n", sssdConfigPath)
	return nil
}

// writeTLSCACert writes the PEM CA certificate to the OS trust store location.
func writeTLSCACert(pemCert string, dryRun bool) error {
	// Debian/Ubuntu: /usr/local/share/ca-certificates/identree.crt
	// RHEL/Fedora:   /etc/pki/ca-trust/source/anchors/identree.crt
	// We write to both paths when both directories exist.
	targets := []struct{ dir, file string }{
		{"/usr/local/share/ca-certificates", "identree.crt"},
		{"/etc/pki/ca-trust/source/anchors", "identree.crt"},
	}
	wrote := false
	for _, t := range targets {
		if _, err := os.Stat(t.dir); os.IsNotExist(err) {
			continue
		}
		path := filepath.Join(t.dir, t.file)
		if dryRun {
			fmt.Printf("[dry-run] would write %s\n", path)
			wrote = true
			continue
		}
		if err := atomicWrite(path, []byte(pemCert), 0644); err != nil {
			return fmt.Errorf("write CA cert %s: %w", path, err)
		}
		fmt.Printf("TLS: wrote CA cert to %s (run update-ca-certificates or update-ca-trust)\n", path)
		wrote = true
	}
	if !wrote {
		fmt.Printf("TLS: CA cert directory not found — write manually:\n%s\n", pemCert)
	}
	return nil
}

// ── Utilities ─────────────────────────────────────────────────────────────────

// atomicWrite writes data to path via a temp file then renames.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".identree-setup-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename

	if _, err := io.Copy(tmp, bytes.NewReader(data)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// splitLines splits s into lines, preserving newline style.
func splitLines(s string) []string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}
