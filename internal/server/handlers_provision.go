package server

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/mtls"
)

// provisionResponse is the JSON payload returned by GET /api/client/provision.
type provisionResponse struct {
	LDAPUrl      string `json:"ldap_url"`
	BaseDN       string `json:"base_dn"`
	BindDN       string `json:"bind_dn"`
	BindPassword string `json:"bind_password"`
	TLSCACert    string `json:"tls_ca_cert,omitempty"`

	// mTLS fields — only populated when mTLS is enabled.
	ClientCert string `json:"client_cert,omitempty"` // PEM-encoded client certificate
	ClientKey  string `json:"client_key,omitempty"`  // PEM-encoded client private key
	CACert     string `json:"ca_cert,omitempty"`     // PEM-encoded CA certificate
}

// handleClientProvision returns LDAP configuration and per-host derived bind
// credentials so that `identree setup --sssd` can auto-configure SSSD without
// requiring manual admin intervention on each host.
//
// When mTLS is enabled, the endpoint also issues and returns a client
// certificate signed by the embedded CA.
//
// Authentication: X-Shared-Secret (global or per-host registry) + X-Hostname.
// The endpoint is only active when IDENTREE_LDAP_PROVISION_ENABLED=true.
//
// GET /api/client/provision
func (s *Server) handleClientProvision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.cfg.LDAPProvisionEnabled {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Require a shared secret — provision leaks bind credentials.
	if !s.verifyAPISecret(r) {
		slog.Warn("PROVISION_REJECTED unauthorized", "remote_addr", remoteAddr(r))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	hostname := strings.TrimSpace(r.Header.Get("X-Hostname"))
	if hostname == "" {
		http.Error(w, "X-Hostname header required", http.StatusBadRequest)
		return
	}
	if !validHostname.MatchString(hostname) {
		http.Error(w, "invalid hostname", http.StatusBadRequest)
		return
	}
	// Reject characters that are special in LDAP DNs (RFC 4514) or that would
	// break DN construction: comma, equals, plus (multi-valued RDN), angle
	// brackets, hash, semicolon, backslash, quote, and control characters.
	if strings.ContainsAny(hostname, ",=+<>#;\\\"") || strings.ContainsFunc(hostname, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		http.Error(w, "invalid hostname", http.StatusBadRequest)
		return
	}

	// When the host registry is active, only registered hostnames may provision credentials.
	if s.hostRegistry.IsEnabled() {
		if !s.hostRegistry.HasHost(hostname) {
			slog.Warn("PROVISION_REJECTED hostname not registered", "hostname", hostname, "remote_addr", remoteAddr(r))
			http.Error(w, "hostname not registered", http.StatusForbidden)
			return
		}
	}

	if s.cfg.SharedSecret == "" && !s.mtlsEnabled() {
		slog.Error("provision: IDENTREE_SHARED_SECRET is not set — cannot derive per-host bind password")
		http.Error(w, "server misconfigured", http.StatusInternalServerError)
		return
	}
	if s.cfg.LDAPBaseDN == "" {
		slog.Error("provision: IDENTREE_LDAP_BASE_DN is not set")
		http.Error(w, "server misconfigured", http.StatusInternalServerError)
		return
	}

	ldapURL := s.ldapProvisionURL()
	if ldapURL == "" {
		slog.Error("provision: cannot determine LDAP URL — set IDENTREE_LDAP_EXTERNAL_URL")
		http.Error(w, "server misconfigured", http.StatusInternalServerError)
		return
	}

	bindDN := fmt.Sprintf("uid=%s,ou=identree-hosts,%s", hostname, s.cfg.LDAPBaseDN)
	bindPassword := ""
	if s.cfg.SharedSecret != "" {
		bindPassword = config.DeriveLDAPBindPassword(s.cfg.SharedSecret, hostname)
	}

	resp := provisionResponse{
		LDAPUrl:      ldapURL,
		BaseDN:       s.cfg.LDAPBaseDN,
		BindDN:       bindDN,
		BindPassword: bindPassword,
		TLSCACert:    s.cfg.LDAPTLSCACert,
	}

	// When mTLS is enabled, issue a client certificate for this host.
	if s.cfg.MTLSEnabled && s.mtlsCA != nil {
		certPEM, keyPEM, err := mtls.IssueCert(*s.mtlsCA, hostname, s.cfg.MTLSCertTTL)
		if err != nil {
			slog.Error("provision: failed to issue mTLS client cert", "hostname", hostname, "err", err)
			http.Error(w, "failed to issue client certificate", http.StatusInternalServerError)
			return
		}
		resp.ClientCert = string(certPEM)
		resp.ClientKey = string(keyPEM)
		// Include the CA cert so the client can verify the server (or be
		// configured to trust it).
		caCertPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: s.mtlsCA.Certificate[0],
		})
		resp.CACert = string(caCertPEM)
		slog.Info("PROVISION mTLS cert issued", "hostname", hostname, "ttl", s.cfg.MTLSCertTTL, "remote_addr", remoteAddr(r))
	}

	slog.Info("PROVISION", "hostname", hostname, "remote_addr", remoteAddr(r))

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Debug("provision: failed to write response", "err", err)
	}
}

// ldapProvisionURL returns the LDAP URL to include in provision responses.
// Uses IDENTREE_LDAP_EXTERNAL_URL if set; otherwise derives ldap://<host>:389
// from the server's ExternalURL.
func (s *Server) ldapProvisionURL() string {
	if s.cfg.LDAPExternalURL != "" {
		return s.cfg.LDAPExternalURL
	}
	// Derive from ExternalURL: replace scheme, keep host, use LDAP port.
	if s.cfg.ExternalURL == "" {
		return ""
	}
	// Strip scheme
	u := s.cfg.ExternalURL
	for _, pfx := range []string{"https://", "http://"} {
		u = strings.TrimPrefix(u, pfx)
	}
	// Strip path
	if idx := strings.IndexByte(u, '/'); idx != -1 {
		u = u[:idx]
	}
	// Use hostname only (strip any existing port)
	host := u
	if h, _, err := net.SplitHostPort(u); err == nil {
		host = h
	}
	// Use LDAP listen port if configured and non-standard, otherwise 389.
	port := "389"
	if s.cfg.LDAPListenAddr != "" {
		if _, p, err := net.SplitHostPort(s.cfg.LDAPListenAddr); err == nil && p != "" && p != "389" {
			port = p
		}
	}
	return fmt.Sprintf("ldap://%s:%s", host, port)
}
