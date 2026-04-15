package ldap

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jimlambrt/gldap"

	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/pocketid"
	"github.com/rinseaid/identree/internal/sanitize"
	"github.com/rinseaid/identree/internal/sudorules"
	"github.com/rinseaid/identree/internal/uidmap"
)

// maxLDAPSearchResults caps the number of LDAP entries written per search request
// to prevent memory exhaustion from extremely large directories.
const maxLDAPSearchResults = 10000

// maxFilterLength caps the byte length of an LDAP filter string to prevent
// CPU/memory exhaustion from pathologically large filters crafted by a client.
const maxFilterLength = 65536

// validUsernameRe matches usernames accepted by the server (consistent with
// server.validUsername). Used to skip PocketID users whose names contain
// characters that would be unsafe in LDAP DN values or sudoUser attributes.
var validUsernameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// sshKeyClaimRe matches sshPublicKey, sshPublicKey1, sshPublicKey2, etc.
var sshKeyClaimRe = regexp.MustCompile(`^sshPublicKey\d*$`)

// sshKeyPrefixRe matches valid SSH public key type prefixes.
var sshKeyPrefixRe = regexp.MustCompile(`^(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) `)

// isValidLDAPAttrValue returns false if the value contains null bytes or newlines,
// which are invalid in LDAP attribute values and could corrupt directory entries.
func isValidLDAPAttrValue(v string) bool {
	return !strings.ContainsAny(v, "\x00\n\r\t")
}

// LDAPServer embeds an RFC 4519 LDAP server.
//
// Full mode (sudoRules == nil): serves a complete directory from PocketID.
//
//	ou=people,dc=example,dc=com      — posixAccount + shadowAccount per user
//	ou=groups,dc=example,dc=com      — posixGroup per group + one UPG per user
//	ou=sudoers,dc=example,dc=com     — sudoRole entries from PocketID group claims
//
// Bridge mode (sudoRules != nil): serves only ou=sudoers from the local rules store.
// The upstream LDAP (Authentik, Kanidm, lldap, etc.) handles people and groups.
//
//	ou=sudoers,dc=example,dc=com     — sudoRole entries from the sudorules store
type LDAPServer struct {
	cfg       *config.ServerConfig
	uidmap    *uidmap.UIDMap
	sudoRules *sudorules.Store // non-nil = bridge mode

	mu          sync.RWMutex
	dir         *pocketid.UserDirectory // refreshed periodically (full mode only)
	userHostMap map[string][]string     // precomputed per Refresh (full mode only)

	// authedConns tracks which connection IDs have completed a successful
	// authenticated bind. Used to enforce LDAPAllowAnonymous=false for searches.
	authedConns sync.Map // map[int]struct{}

	// mtlsKnownCNs tracks cert CNs seen during TLS handshakes (populated by
	// the VerifyPeerCertificate callback). Used to cross-check bind DN
	// hostnames: a host can only bind as a hostname for which a valid cert
	// CN exists. This is the strongest check possible given that gldap does
	// not expose per-connection TLS state to handlers.
	mtlsKnownCNs sync.Map // map[string]struct{} — lowercase CN -> struct{}

	// tlsConfig is the TLS configuration for LDAPS (mTLS mode). nil = plaintext.
	tlsConfig *tls.Config

	// mtlsCACert is the parsed mTLS CA certificate for verifying client certs
	// in the bind handler. nil when mTLS is not active.
	mtlsCACert *x509.Certificate

	// mtlsAllVerified is true when the LDAP server uses RequireAndVerifyClientCert
	// TLS config, meaning every connection that reaches a handler has already been
	// authenticated by the TLS stack against the mTLS CA. When true, the bind
	// handler accepts provisioned host DNs without checking the password.
	mtlsAllVerified bool

	// hostChecker, when non-nil, verifies that a hostname is still registered
	// in the host registry. Used to reject decommissioned hosts in the mTLS
	// bind path even when their certs are still cryptographically valid.
	hostChecker func(hostname string) bool

	srv *gldap.Server
}

// LDAPTLSConfig holds the TLS parameters for enabling LDAPS with mTLS client
// certificate authentication. Pass nil to NewLDAPServer for plaintext LDAP.
type LDAPTLSConfig struct {
	// ServerCert is the TLS server certificate presented to LDAP clients.
	ServerCert tls.Certificate
	// CACert is the mTLS CA certificate used to verify client certificates.
	CACert *x509.Certificate
	// HostChecker, when non-nil, is called with the hostname extracted from
	// the bind DN to verify that the host is still registered. This is the
	// revocation equivalent for the LDAP layer — decommissioned hosts whose
	// certs are still cryptographically valid will be rejected.
	// Returns true if the host is allowed.
	HostChecker func(hostname string) bool
}

// NewLDAPServer creates (but does not start) the LDAP server.
// Pass a non-nil store to run in bridge mode (sudoers-only LDAP).
// Pass a non-nil tlsCfg to enable LDAPS with mTLS client certificate auth.
func NewLDAPServer(cfg *config.ServerConfig, um *uidmap.UIDMap, store *sudorules.Store, tlsCfg *LDAPTLSConfig) (*LDAPServer, error) {
	s := &LDAPServer{
		cfg:       cfg,
		uidmap:    um,
		sudoRules: store,
	}

	if tlsCfg != nil {
		caPool := x509.NewCertPool()
		caPool.AddCert(tlsCfg.CACert)

		s.mtlsCACert = tlsCfg.CACert
		s.mtlsAllVerified = true
		s.hostChecker = tlsCfg.HostChecker
		s.tlsConfig = &tls.Config{ // #nosec G123 -- session resumption is safe here; VerifyPeerCertificate only captures CN for audit, chain verification is done by RequireAndVerifyClientCert
			Certificates:         []tls.Certificate{tlsCfg.ServerCert},
			ClientAuth:           tls.RequireAndVerifyClientCert,
			ClientCAs:            caPool,
			MinVersion:           tls.VersionTLS12,
			SessionTicketsDisabled: true,
			// VerifyPeerCertificate captures the cert CN during TLS handshake
			// so we can cross-check it against the bind DN hostname later.
			// This runs after Go's built-in chain verification (RequireAndVerifyClientCert).
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) > 0 {
					cert, err := x509.ParseCertificate(rawCerts[0])
					if err == nil && cert.Subject.CommonName != "" {
						cn := strings.ToLower(cert.Subject.CommonName)
						s.mtlsKnownCNs.Store(cn, struct{}{})
					}
				}
				return nil
			},
		}
		slog.Info("ldap: LDAPS with mTLS client certificate authentication enabled")
	}

	return s, nil
}

// Refresh replaces the cached directory snapshot atomically.
// It eagerly assigns UIDs/GIDs for all entries so the map stays current.
// trigger, if non-empty, is used to label the ldap_refresh_total metric (e.g. "poll", "webhook").
// Refresh updates the in-memory directory snapshot. excludeUsers is an optional
// set of usernames to filter out — used to ensure recently-deleted users do not
// reappear in the LDAP directory until the next full PocketID sync clears them.
func (s *LDAPServer) Refresh(dir *pocketid.UserDirectory, trigger string, excludeUsers map[string]bool) {
	// Filter excluded users from the directory snapshot before serving.
	if len(excludeUsers) > 0 {
		filtered := make([]pocketid.PocketIDAdminUser, 0, len(dir.Users))
		for _, u := range dir.Users {
			if !excludeUsers[u.Username] {
				filtered = append(filtered, u)
			}
		}
		dir = pocketid.NewUserDirectory(filtered, dir.Groups)
	}

	for _, u := range dir.Users {
		s.uidmap.UID(u.ID)
	}
	for _, g := range dir.Groups {
		s.uidmap.GID(g.ID)
	}
	if err := s.uidmap.Flush(); err != nil {
		slog.Error("ldap: uid map flush failed — UIDs may be reassigned on restart", "err", err)
	}

	// Precompute the user→host map once per refresh so that every search
	// request reads from the cached result rather than recomputing it.
	hostMap := buildUserHostMap(dir.Groups, dir)

	s.mu.Lock()
	s.dir = dir
	s.userHostMap = hostMap
	s.mu.Unlock()

	slog.Info("ldap: directory refreshed",
		"users", len(dir.Users),
		"groups", len(dir.Groups),
	)

	if trigger != "" {
		ldapRefreshTotal.WithLabelValues(trigger).Inc()
	}
}

// Start launches the LDAP listener. It blocks until ctx is cancelled.
func (s *LDAPServer) Start(ctx context.Context) error {
	srv, err := gldap.NewServer(
		gldap.WithReadTimeout(60*time.Second),
		gldap.WithWriteTimeout(60*time.Second),
		gldap.WithOnClose(func(connID int) {
			s.authedConns.Delete(connID)
		}),
	)
	if err != nil {
		return fmt.Errorf("ldap: new server: %w", err)
	}
	s.srv = srv

	mux, err := gldap.NewMux()
	if err != nil {
		return fmt.Errorf("ldap: new mux: %w", err)
	}
	mux.Bind(s.handleBind)
	mux.Search(s.handleSearch)
	srv.Router(mux)

	go func() {
		<-ctx.Done()
		srv.Stop()
	}()

	listenAddr := s.cfg.LDAPListenAddr

	// When TLS is configured, use LDAPS with mTLS.
	if s.tlsConfig != nil {
		// Use LDAPTLSListenAddr if set, otherwise the standard LDAPS port.
		if s.cfg.LDAPTLSListenAddr != "" {
			listenAddr = s.cfg.LDAPTLSListenAddr
		}

		slog.Info("ldap: listening (LDAPS/mTLS)", "addr", listenAddr)
		return srv.Run(listenAddr, gldap.WithTLSConfig(s.tlsConfig))
	}

	slog.Info("ldap: listening", "addr", listenAddr)
	return srv.Run(listenAddr)
}

// ── Bind handler ─────────────────────────────────────────────────────────────

func (s *LDAPServer) handleBind(w *gldap.ResponseWriter, req *gldap.Request) {
	resp := req.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials))
	defer func() { w.Write(resp) }()

	msg, err := req.GetSimpleBindMessage()
	if err != nil {
		resp.SetResultCode(gldap.ResultProtocolError)
		return
	}

	// Anonymous bind — allowed only when LDAPAllowAnonymous is true (the default).
	if msg.UserName == "" {
		// RFC 4513 §5.1.2: a non-empty password with an empty DN is an
		// "unauthenticated bind" which MUST be rejected to prevent clients
		// from accidentally treating a failed password as a successful
		// anonymous bind.
		if msg.Password != "" {
			slog.Warn("LDAP_BIND_REJECTED unauthenticated bind attempt (empty DN with password)", "conn", req.ConnectionID())
			resp.SetResultCode(gldap.ResultUnwillingToPerform)
			return
		}
		if !s.cfg.LDAPAllowAnonymous {
			slog.Warn("LDAP_BIND_REJECTED anonymous bind not allowed", "conn", req.ConnectionID())
			resp.SetResultCode(gldap.ResultInsufficientAccessRights)
			return
		}
		// Anonymous bind succeeds but is intentionally NOT registered in
		// authedConns — anonymous sessions must not pass the authenticated
		// connection check in the search handler.
		slog.Info("LDAP_BIND_OK anonymous", "conn", req.ConnectionID())
		resp.SetResultCode(gldap.ResultSuccess)
		return
	}

	// Service-account bind — must match configured bind DN and password.
	// RFC 4511 §2.1 requires case-insensitive DN comparison.
	if s.cfg.LDAPBindDN != "" && strings.EqualFold(msg.UserName, s.cfg.LDAPBindDN) {
		if s.cfg.LDAPBindPassword != "" && subtle.ConstantTimeCompare([]byte(msg.Password), []byte(s.cfg.LDAPBindPassword)) == 1 {
			s.authedConns.Store(req.ConnectionID(), struct{}{})
			slog.Info("LDAP_BIND_OK service account", "dn", msg.UserName, "conn", req.ConnectionID())
			resp.SetResultCode(gldap.ResultSuccess)
		} else {
			slog.Warn("LDAP_BIND_REJECTED bad password for service account", "dn", msg.UserName, "conn", req.ConnectionID())
			ldapBindFailures.Inc()
		}
		// Otherwise stays InvalidCredentials
		return
	}

	// Per-host provisioned bind — DN format: uid=<hostname>,ou=identree-hosts,<base_dn>
	//
	// When mTLS is active (LDAPS with RequireAndVerifyClientCert), the TLS
	// handshake already verified the client certificate against the mTLS CA.
	// Every connection that reaches this handler has a valid cert — the bind
	// succeeds without checking the password because the certificate IS the
	// credential. The LDAP directory is read-only and does not filter results
	// per-host, so all authenticated connections see the same data.
	//
	// When mTLS is NOT active, password-based auth continues: the password is
	// derived as HMAC(deriveSubkey(sharedSecret,"ldap-bind"), hostname).
	if s.cfg.LDAPProvisionEnabled && s.cfg.LDAPBaseDN != "" {
		if hostname, ok := s.parseProvisionBindDN(msg.UserName); ok {
			// mTLS path: TLS layer already verified the client cert.
			// Accept the bind — the cert is the credential.
			if s.mtlsAllVerified {
				// Check host registry: reject decommissioned hosts whose
				// certs are still cryptographically valid.
				if s.hostChecker != nil && !s.hostChecker(hostname) {
					slog.Warn("LDAP_BIND_REJECTED mTLS hostname not registered", "hostname", hostname, "conn", req.ConnectionID())
					ldapBindFailures.Inc()
					return
				}
				// Cross-check: verify the bind DN hostname matches a cert CN
				// we've seen during TLS handshake. This prevents a host with
				// cert CN=hostA from binding as uid=hostB. Note: gldap does
				// not expose per-connection TLS state, so we check against all
				// known cert CNs — this is the strongest check possible.
				if _, known := s.mtlsKnownCNs.Load(strings.ToLower(hostname)); !known {
					slog.Warn("LDAP_BIND_REJECTED bind DN hostname has no matching cert CN", "hostname", hostname, "conn", req.ConnectionID())
					ldapBindFailures.Inc()
					return
				}
				s.authedConns.Store(req.ConnectionID(), struct{}{})
				slog.Info("LDAP_BIND_OK mTLS provisioned host", "hostname", hostname, "conn", req.ConnectionID())
				resp.SetResultCode(gldap.ResultSuccess)
				return
			}
			// Password-based path (no mTLS).
			if s.cfg.LDAPSecret != "" {
				expected := config.DeriveLDAPBindPassword(s.cfg.LDAPSecret, hostname)
				if subtle.ConstantTimeCompare([]byte(msg.Password), []byte(expected)) == 1 {
					s.authedConns.Store(req.ConnectionID(), struct{}{})
					slog.Info("LDAP_BIND_OK provisioned host", "hostname", hostname, "conn", req.ConnectionID())
					resp.SetResultCode(gldap.ResultSuccess)
				} else {
					slog.Warn("LDAP_BIND_REJECTED bad password for provisioned host", "hostname", hostname, "conn", req.ConnectionID())
					ldapBindFailures.Inc()
				}
				return
			}
		}
	}

	// All other binds rejected — identree is a read-only directory
	slog.Warn("LDAP_BIND_REJECTED unknown DN", "dn", msg.UserName, "conn", req.ConnectionID())
	ldapBindFailures.Inc()
}

// parseProvisionBindDN returns the hostname from a DN of the form
// uid=<hostname>,ou=identree-hosts,<base_dn>. Returns ("", false) if the DN
// does not match this pattern.
func (s *LDAPServer) parseProvisionBindDN(dn string) (string, bool) {
	// Expected: uid=<hostname>,ou=identree-hosts,<base_dn>
	suffix := ",ou=identree-hosts," + s.cfg.LDAPBaseDN
	if !strings.EqualFold(dn[max(0, len(dn)-len(suffix)):], suffix) {
		return "", false
	}
	prefix := dn[:len(dn)-len(suffix)]
	if !strings.HasPrefix(strings.ToLower(prefix), "uid=") {
		return "", false
	}
	hostname := prefix[4:]
	if hostname == "" {
		return "", false
	}
	return hostname, true
}

// ── Search handler ────────────────────────────────────────────────────────────

func (s *LDAPServer) handleSearch(w *gldap.ResponseWriter, req *gldap.Request) {
	resp := req.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultSuccess))
	defer func() { w.Write(resp) }()

	msg, err := req.GetSearchMessage()
	if err != nil {
		resp.SetResultCode(gldap.ResultProtocolError)
		return
	}

	// RFC 2696 SimplePagedResults — identree holds the full directory in memory
	// and always returns results in a single pass, so paging is a no-op here.
	// We detect and acknowledge the control so clients (SSSD in particular) do
	// not treat the missing response control as an error.
	//
	// RFC 2696 §3 requires the server to return a paging response control in the
	// SearchResultDone. We return one with an empty cookie (indicating end of
	// results) and total==0 (server does not track the total). This satisfies
	// strict clients like SSSD that treat a missing response control as an error.
	var hasPagingControl bool
	for _, ctrl := range msg.Controls {
		if ctrl.GetControlType() == gldap.ControlTypePaging {
			hasPagingControl = true
			if pc, ok := ctrl.(*gldap.ControlPaging); ok {
				slog.Info("ldap: SimplePagedResults control received — returning all results in one page",
					"requested_page_size", pc.PagingSize)
			} else {
				slog.Info("ldap: SimplePagedResults control received")
			}
			// No break — log all controls for observability.
		} else {
			oid := ctrl.GetControlType()
			// RFC 4511 §4.1.11: if an unknown control is marked critical the
			// server MUST return unavailableCriticalExtension and MUST NOT
			// process the request. Check ControlString (the gldap catch-all for
			// unknown OIDs) and any other control type that exposes Criticality.
			critical := false
			if cs, ok := ctrl.(*gldap.ControlString); ok {
				critical = cs.Criticality
			}
			if critical {
				slog.Warn("ldap: unknown critical control received, rejecting request",
					"oid", oid)
				resp.SetResultCode(gldap.ResultUnavailableCriticalExtension)
				return
			}
			slog.Debug("ldap: unknown control received (ignored)", "oid", oid)
		}
	}
	if hasPagingControl {
		// Return a paging response control with empty cookie (end of results).
		// PagingSize==0 in the response indicates no more pages.
		if pc, err := gldap.NewControlPaging(0); err == nil {
			resp.SetControls(pc)
		}
	}

	// Enforce authentication requirement: if anonymous access is disabled,
	// reject any search from a connection that has not completed a successful
	// authenticated bind.
	if !s.cfg.LDAPAllowAnonymous {
		if _, authed := s.authedConns.Load(req.ConnectionID()); !authed {
			resp.SetResultCode(gldap.ResultInsufficientAccessRights)
			return
		}
	}

	base := s.cfg.LDAPBaseDN
	scope := strings.ToLower(msg.BaseDN)
	peopleDN := strings.ToLower("ou=people," + base)
	groupsDN := strings.ToLower("ou=groups," + base)
	sudoersDN := strings.ToLower("ou=sudoers," + base)
	baseLower := strings.ToLower(base)
	filter := msg.Filter

	// Determine query base label for metrics.
	queryBase := "root"
	switch {
	case scope == peopleDN || strings.HasSuffix(scope, ","+peopleDN):
		queryBase = "people"
	case scope == groupsDN || strings.HasSuffix(scope, ","+groupsDN):
		queryBase = "groups"
	case scope == sudoersDN || strings.HasSuffix(scope, ","+sudoersDN):
		queryBase = "sudoers"
	}
	ldapQueryTotal.WithLabelValues(queryBase).Inc()

	// Effective limit: honour the client's SizeLimit up to the server's hard cap.
	// SizeLimit == 0 means "no client limit"; server cap still applies.
	limit := maxLDAPSearchResults
	if msg.SizeLimit > 0 && int(msg.SizeLimit) < limit {
		limit = int(msg.SizeLimit)
	}

	// Bridge mode: serve only ou=sudoers from the local rules store.
	if s.sudoRules != nil {
		var truncated bool
		switch {
		case scope == baseLower && msg.Scope == gldap.BaseObject:
			s.sendRootDSE(w, req, base)
		case scope == sudoersDN || strings.HasSuffix(scope, ","+sudoersDN):
			truncated = s.searchSudoersFromStore(w, req, filter, msg.Attributes, base, limit)
		case scope == baseLower:
			// Subtree from root in bridge mode — only serve sudoers.
			truncated = s.searchSudoersFromStore(w, req, filter, msg.Attributes, base, limit)
		}
		if truncated {
			resp.SetResultCode(gldap.ResultSizeLimitExceeded)
		}
		return
	}

	// Full mode: require directory snapshot.
	s.mu.RLock()
	dir := s.dir
	userHosts := s.userHostMap
	s.mu.RUnlock()

	if dir == nil {
		resp.SetResultCode(gldap.ResultBusy)
		return
	}

	var truncated bool
	switch {
	case scope == baseLower && msg.Scope == gldap.BaseObject:
		s.sendRootDSE(w, req, base)

	case scope == peopleDN || strings.HasSuffix(scope, ","+peopleDN):
		truncated, _ = s.searchPeople(w, req, filter, msg.Attributes, dir, userHosts, base, limit)

	case scope == groupsDN || strings.HasSuffix(scope, ","+groupsDN):
		truncated, _ = s.searchGroups(w, req, filter, msg.Attributes, dir, base, limit)

	case scope == sudoersDN || strings.HasSuffix(scope, ","+sudoersDN):
		truncated = s.searchSudoers(w, req, filter, msg.Attributes, dir, base, limit)

	case scope == baseLower && msg.Scope == gldap.SingleLevel:
		// RFC 4511 SingleLevel from root: return only the immediate OU
		// containers (ou=People, ou=Groups, ou=Sudoers) — not their children.
		for _, ouDN := range []string{
			"ou=people," + base,
			"ou=groups," + base,
			"ou=sudoers," + base,
		} {
			ouName := strings.SplitN(ouDN, ",", 2)[0] // e.g. "ou=people"
			ouName = strings.TrimPrefix(strings.ToLower(ouName), "ou=")
			attrs := map[string][]string{
				"objectClass": {"top", "organizationalUnit"},
				"ou":          {ouName},
			}
			if matchesFilter(filter, ouDN, attrs) {
				w.Write(req.NewSearchResponseEntry(ouDN, gldap.WithAttributes(filterAttrs(attrs, msg.Attributes))))
			}
		}

	case scope == baseLower:
		// Subtree from root — serve everything. The size limit is tracked
		// cumulatively across all three branches so that the aggregate never
		// exceeds the client's stated SizeLimit.
		var n int
		remaining := limit
		truncated, n = s.searchPeople(w, req, filter, msg.Attributes, dir, userHosts, base, remaining)
		remaining = decrementLimit(remaining, n)
		if !truncated && (limit == 0 || remaining > 0) {
			truncated, n = s.searchGroups(w, req, filter, msg.Attributes, dir, base, remaining)
			remaining = decrementLimit(remaining, n)
		}
		if !truncated && (limit == 0 || remaining > 0) {
			truncated = s.searchSudoers(w, req, filter, msg.Attributes, dir, base, remaining)
		}
	}
	if truncated {
		resp.SetResultCode(gldap.ResultSizeLimitExceeded)
	}
}

func (s *LDAPServer) sendRootDSE(w *gldap.ResponseWriter, req *gldap.Request, base string) {
	entry := req.NewSearchResponseEntry(base,
		gldap.WithAttributes(map[string][]string{
			"objectClass":    {"top", "dcObject", "organization"},
			"dc":             {firstDC(base)},
			"o":              {base},
			"namingContexts": {base},
		}),
	)
	w.Write(entry)
}

// searchPeople sends posixAccount + shadowAccount entries.
// userHosts is the precomputed username→[]host map from the last Refresh().
// requestedAttrs is the client's Attributes list from the search message; used
// to filter the response via filterAttrs.
// Returns (truncated, count) where truncated is true if the result set was
// capped by limit and count is the number of entries written.
func (s *LDAPServer) searchPeople(w *gldap.ResponseWriter, req *gldap.Request, filter string, requestedAttrs []string, dir *pocketid.UserDirectory, userHosts map[string][]string, base string, limit int) (bool, int) {
	peopleDN := "ou=people," + base

	// OU container
	ouEntry := req.NewSearchResponseEntry(peopleDN,
		gldap.WithAttributes(map[string][]string{
			"objectClass": {"top", "organizationalUnit"},
			"ou":          {"people"},
		}),
	)
	if matchesFilter(filter, peopleDN, map[string][]string{
		"objectClass": {"top", "organizationalUnit"},
		"ou":          {"people"},
	}) {
		w.Write(ouEntry)
	}

	var sent int
	for _, u := range dir.Users {
		// Validate core user fields before placing them in LDAP attributes.
		// Null bytes and newlines would corrupt directory entries.
		if !isValidLDAPAttrValue(u.Username) || !validUsernameRe.MatchString(u.Username) {
			slog.Warn("ldap: skipping user with invalid characters in username", "user", sanitize.ForTerminal(u.Username))
			continue
		}
		if len(u.Username) > 64 {
			slog.Warn("ldap: skipping user with username exceeding 64 bytes", "user", u.Username[:32]+"...")
			continue
		}
		if reservedUsernames[u.Username] {
			slog.Warn("ldap: skipping user with reserved system username", "username", u.Username)
			continue
		}
		firstName := u.FirstName
		if !isValidLDAPAttrValue(firstName) {
			slog.Warn("ldap: stripping invalid characters from firstName", "user", u.Username)
			firstName = ""
		}
		lastName := u.LastName
		if !isValidLDAPAttrValue(lastName) {
			slog.Warn("ldap: stripping invalid characters from lastName", "user", u.Username)
			lastName = ""
		}
		email := u.Email
		if !isValidLDAPAttrValue(email) {
			slog.Warn("ldap: stripping invalid characters from email", "user", u.Username)
			email = ""
		}

		uid := s.uidmap.UID(u.ID)
		if uid == -1 {
			slog.Warn("ldap: skipping user — UID space exhausted", "user", u.Username)
			continue
		}
		// Assign a dedicated GID for the UPG via the GID map to avoid
		// collisions with regular group GIDs. The same UUID key is used in
		// searchGroups so the user's primary GID matches their UPG GID.
		gid := s.uidmap.GID(u.ID)
		if gid == -1 {
			slog.Warn("ldap: skipping user — GID space exhausted", "user", u.Username)
			continue
		}
		dn := fmt.Sprintf("uid=%s,%s", escapeDNValue(u.Username), peopleDN)
		fullName := strings.TrimSpace(firstName + " " + lastName)
		if fullName == "" {
			fullName = u.Username
		}
		sn := lastName
		if sn == "" {
			sn = u.Username
		}

		// Determine shell and home directory, with per-user claim overrides.
		shell := s.cfg.LDAPDefaultShell
		if shell == "" {
			shell = "/bin/bash"
		}
		homePattern := s.cfg.LDAPDefaultHome
		if homePattern == "" {
			homePattern = "/home/%s"
		}
		home := strings.Replace(homePattern, "%s", u.Username, 1)
		if !strings.HasPrefix(home, "/") {
			slog.Warn("ldap: constructed home path is not absolute, using /tmp", "user", u.Username, "pattern", homePattern)
			home = "/tmp"
		}
		if !isValidLDAPAttrValue(home) {
			slog.Warn("ldap: constructed home path has invalid characters, using /tmp", "user", u.Username)
			home = "/tmp"
		}
		for _, cl := range u.CustomClaims {
			switch cl.Key {
			case "loginShell":
				if cl.Value != "" {
					if !isValidLDAPAttrValue(cl.Value) {
						slog.Warn("ldap: ignoring loginShell claim with invalid characters", "user", u.Username)
					} else {
						shell = cl.Value
					}
				}
			case "homeDirectory":
				if cl.Value != "" {
					if !isValidLDAPAttrValue(cl.Value) {
						slog.Warn("ldap: ignoring homeDirectory claim with invalid characters", "user", u.Username)
					} else {
						home = cl.Value
					}
				}
			}
		}

		// Collect SSH public keys from claims.
		var sshKeys []string
		for _, cl := range u.CustomClaims {
			if len(sshKeys) >= maxSSHKeys {
				break
			}
			if sshKeyClaimRe.MatchString(cl.Key) && cl.Value != "" {
				if !isValidLDAPAttrValue(cl.Value) || !sshKeyPrefixRe.MatchString(cl.Value) {
					slog.Warn("ldap: ignoring malformed SSH public key claim", "user", u.Username, "claim", cl.Key)
					continue
				}
				sshKeys = append(sshKeys, cl.Value)
			}
		}

		accountStatus := "active"
		if u.Disabled {
			accountStatus = "inactive"
		}

		// NOTE: The DN uses uid=<username> which changes if the user renames in
		// PocketID. This breaks SSSD's cached identity. entryUUID below is the
		// PocketID UUID — it is stable across renames and SSSD can use it for
		// reliable identity tracking (ldap_search_base_by_entryuuid). The DN
		// format is kept as-is to avoid breaking existing SSSD deployments.
		attrs := map[string][]string{
			"objectClass":      {"top", "posixAccount", "shadowAccount", "inetOrgPerson"},
			"uid":              {u.Username},
			"cn":               {fullName},
			"sn":               {sn},
			"uidNumber":        {fmt.Sprintf("%d", uid)},
			"gidNumber":        {fmt.Sprintf("%d", gid)},
			"homeDirectory":    {home},
			"loginShell":       {shell},
			"gecos":            {fullName},
			"shadowLastChange": {"0"},
			"shadowMin":        {"0"},
			"shadowMax":        {"99999"},
			"shadowWarning":    {"7"},
			"accountStatus":    {accountStatus},
			"entryUUID":        {u.ID},
		}
		// RFC 4519 forbids empty attribute values; only emit optional attrs when non-empty.
		if firstName != "" {
			attrs["givenName"] = []string{firstName}
		}
		if email != "" {
			attrs["mail"] = []string{email}
		}

		// For disabled accounts, set shadowExpire=1 so that standard LDAP clients
		// (sssd, nslcd, pam_ldap) block access. accountStatus=inactive is a
		// non-standard attribute; shadowExpire is the RFC 2307 standard mechanism.
		if u.Disabled {
			attrs["shadowExpire"] = []string{"1"}
		}

		// Populate host attribute from accessHosts claim for pam_access.
		if hosts, ok := userHosts[u.Username]; ok && len(hosts) > 0 {
			attrs["host"] = hosts
		}

		// Add SSH public keys only for enabled accounts — disabled users must not
		// be able to authenticate via SSH keys even if their keys are still stored.
		if len(sshKeys) > 0 && !u.Disabled {
			attrs["objectClass"] = append(attrs["objectClass"], "ldapPublicKey")
			attrs["sshPublicKey"] = sshKeys
		}

		if !matchesFilter(filter, dn, attrs) {
			continue
		}
		if sent >= limit {
			slog.Warn("ldap: searchPeople result cap reached, truncating response", "limit", limit)
			return true, sent
		}
		entry := req.NewSearchResponseEntry(dn, gldap.WithAttributes(filterAttrs(attrs, requestedAttrs)))
		w.Write(entry)
		sent++
	}
	return false, sent
}

// searchGroups sends posixGroup entries for PocketID groups and User Private Groups.
// requestedAttrs is the client's Attributes list from the search message; used
// to filter the response via filterAttrs.
// Returns (truncated, count) where truncated is true if the result set was
// capped by limit and count is the number of entries written.
func (s *LDAPServer) searchGroups(w *gldap.ResponseWriter, req *gldap.Request, filter string, requestedAttrs []string, dir *pocketid.UserDirectory, base string, limit int) (bool, int) {
	groupsDN := "ou=groups," + base
	peopleDN := "ou=people," + base

	// OU container
	ouAttrs := map[string][]string{
		"objectClass": {"top", "organizationalUnit"},
		"ou":          {"groups"},
	}
	if matchesFilter(filter, groupsDN, ouAttrs) {
		w.Write(req.NewSearchResponseEntry(groupsDN, gldap.WithAttributes(ouAttrs)))
	}

	// PocketID groups
	var sent int
	for _, g := range dir.Groups {
		if !isValidGroupName(g.Name) {
			slog.Warn("ldap: skipping group with invalid name", "group", g.Name)
			continue
		}
		gid := s.uidmap.GID(g.ID)
		if gid == -1 {
			slog.Warn("ldap: skipping group — GID space exhausted", "group", g.Name)
			continue
		}
		dn := fmt.Sprintf("cn=%s,%s", escapeDNValue(g.Name), groupsDN)

		memberUids := buildMemberUids(g.Members, dir)
		memberDNs := buildMemberDNs(g.Members, dir, peopleDN)

		name := g.FriendlyName
		if name == "" {
			name = g.Name
		}
		if !isValidLDAPAttrValue(name) {
			slog.Warn("ldap: stripping invalid characters from group FriendlyName", "group", g.Name)
			name = g.Name
		}

		// NOTE: The DN uses cn=<groupname> which changes if the group is renamed
		// in PocketID. entryUUID (the PocketID group UUID) is stable across
		// renames and allows SSSD to track identity reliably.
		attrs := map[string][]string{
			"objectClass": {"top", "posixGroup"},
			"cn":          {g.Name},
			"description": {name},
			"gidNumber":   {fmt.Sprintf("%d", gid)},
			"entryUUID":   {g.ID},
		}
		if len(memberUids) > 0 {
			attrs["memberUid"] = memberUids
			attrs["member"] = memberDNs
		}

		if !matchesFilter(filter, dn, attrs) {
			continue
		}
		if sent >= limit {
			slog.Warn("ldap: searchGroups result cap reached, truncating response", "limit", limit)
			return true, sent
		}
		w.Write(req.NewSearchResponseEntry(dn, gldap.WithAttributes(filterAttrs(attrs, requestedAttrs))))
		sent++
	}

	// User Private Groups (one per user)
	for _, u := range dir.Users {
		if !isValidLDAPAttrValue(u.Username) {
			continue // same guard as searchPeople; keeps UPG consistent
		}
		if reservedUsernames[u.Username] {
			continue // same guard as searchPeople; keeps UPG consistent
		}
		uid := s.uidmap.UID(u.ID)
		if uid == -1 {
			slog.Warn("ldap: skipping UPG — UID space exhausted", "user", u.Username)
			continue
		}
		// Assign a dedicated GID via the GID map to avoid collisions with
		// regular group GIDs. The same UUID key is used in searchPeople so
		// the user's primary GID matches their UPG GID.
		gid := s.uidmap.GID(u.ID)
		if gid == -1 {
			slog.Warn("ldap: skipping UPG — GID space exhausted", "user", u.Username)
			continue
		}
		dn := fmt.Sprintf("cn=%s,%s", escapeDNValue(u.Username), groupsDN)
		// UPGs use the user's PocketID UUID as entryUUID for stable identity tracking.
		attrs := map[string][]string{
			"objectClass": {"top", "posixGroup"},
			"cn":          {u.Username},
			"gidNumber":   {fmt.Sprintf("%d", gid)},
			"memberUid":   {u.Username},
			"entryUUID":   {u.ID},
		}
		if !matchesFilter(filter, dn, attrs) {
			continue
		}
		if sent >= limit {
			slog.Warn("ldap: searchGroups (UPG) result cap reached, truncating response", "limit", limit)
			return true, sent
		}
		w.Write(req.NewSearchResponseEntry(dn, gldap.WithAttributes(filterAttrs(attrs, requestedAttrs))))
		sent++
	}
	return false, sent
}

// searchSudoers emits sudoRole entries for groups that have sudo-related custom claims.
// The following custom claims drive the output:
//
//	sudoHosts      — comma-separated hosts (default "ALL" if omitted)
//	sudoCommands   — comma-separated commands; required, no default
//	sudoRunAsUser  — comma-separated run-as users (default "root" if omitted)
//	sudoRunAsGroup — comma-separated run-as groups (optional)
//	sudoOptions    — comma-separated extra sudo options (validated against blocklist)
//
// A group is emitted only if it has at least one sudo-related claim and all
// required fields pass validation.
// requestedAttrs is the client's Attributes list from the search message; used
// to filter the response via filterAttrs.
// Returns true if the result set was truncated by limit.
func (s *LDAPServer) searchSudoers(w *gldap.ResponseWriter, req *gldap.Request, filter string, requestedAttrs []string, dir *pocketid.UserDirectory, base string, limit int) bool {
	sudoersDN := "ou=sudoers," + base

	ouAttrs := map[string][]string{
		"objectClass": {"top", "organizationalUnit"},
		"ou":          {"sudoers"},
	}
	if matchesFilter(filter, sudoersDN, ouAttrs) {
		w.Write(req.NewSearchResponseEntry(sudoersDN, gldap.WithAttributes(ouAttrs)))
	}

	noAuth := s.cfg.LDAPSudoNoAuthenticate
	if noAuth == config.SudoNoAuthTrue {
		slog.Warn("SECURITY: LDAPSudoNoAuthenticate=true — ALL sudo rules bypass PAM authentication entirely; users can sudo without any authentication prompt")
	}

	var sent int
	for _, g := range dir.Groups {
		if !isValidGroupName(g.Name) {
			continue
		}
		claims := g.ClaimsMap()
		if !hasSudoClaims(claims) {
			continue
		}

		// Members — skip rule entirely if no members
		uids := buildMemberUids(g.Members, dir)
		if len(uids) == 0 {
			continue
		}

		// sudoHost (default: ALL)
		sudoHosts := validatedSudoHostOrUser(claims, "sudoHosts", "ALL")
		if len(sudoHosts) == 0 {
			continue // all explicit values were invalid — fail-closed
		}
		if len(sudoHosts) == 1 && sudoHosts[0] == "ALL" {
			slog.Info("sudo rule has sudoHost=ALL (permits execution on any host)", "group", g.Name)
		}

		// sudoCommand — required, no default
		rawCmds := splitClaim(claims, "sudoCommands")
		if len(rawCmds) == 0 {
			continue
		}
		var cmds []string
		for _, c := range rawCmds {
			if validSudoCommand(c) {
				cmds = append(cmds, c)
			}
		}
		if len(cmds) == 0 {
			continue // all commands were invalid
		}

		// sudoRunAsUser (default: root)
		sudoRunAsUser := validatedSudoHostOrUser(claims, "sudoRunAsUser", "root")
		if len(sudoRunAsUser) == 0 {
			continue // all explicit values were invalid — fail-closed
		}

		dn := fmt.Sprintf("cn=%s,%s", escapeDNValue(g.Name), sudoersDN)
		attrs := map[string][]string{
			"objectClass":   {"top", "sudoRole"},
			"cn":            {g.Name},
			"sudoUser":      uids,
			"sudoHost":      sudoHosts,
			"sudoCommand":   cmds,
			"sudoRunAsUser": sudoRunAsUser,
		}

		// sudoRunAsGroup — optional
		if vals := splitClaim(claims, "sudoRunAsGroup"); len(vals) > 0 {
			var safe []string
			for _, v := range vals {
				if v == "ALL" || validGroupName.MatchString(v) {
					safe = append(safe, v)
				}
			}
			if len(safe) > 0 {
				attrs["sudoRunAsGroup"] = safe
			}
		}

		// sudoOptions: controlled by LDAPSudoNoAuthenticate + per-group claim
		var sudoOptions []string
		if noAuth == config.SudoNoAuthTrue {
			sudoOptions = append(sudoOptions, "!authenticate")
		}
		if extra := splitClaim(claims, "sudoOptions"); len(extra) > 0 {
			for _, opt := range extra {
				if isNoAuthOption(opt) {
					if noAuth == config.SudoNoAuthClaims {
						sudoOptions = append(sudoOptions, strings.TrimSpace(opt))
					}
					continue
				}
				if isSafeSudoOption(opt) {
					sudoOptions = append(sudoOptions, opt)
				}
			}
		}
		if len(sudoOptions) > 0 {
			attrs["sudoOption"] = sudoOptions
		}

		// sudoOrder ensures sudo applies rules in a deterministic order rather
		// than relying on LDAP return order (which is undefined per RFC 4511).
		// The index is 1-based and reflects the iteration order of dir.Groups.
		attrs["sudoOrder"] = []string{strconv.Itoa(sent + 1)}

		if !matchesFilter(filter, dn, attrs) {
			continue
		}
		if sent >= limit {
			slog.Warn("ldap: searchSudoers result cap reached, truncating response", "limit", limit)
			return true
		}
		w.Write(req.NewSearchResponseEntry(dn, gldap.WithAttributes(filterAttrs(attrs, requestedAttrs))))
		sent++
	}
	return false
}

// searchSudoersFromStore emits sudoRole entries from the bridge-mode rules store.
// sudoUser is set to %groupname (LDAP group membership syntax for sudoers) since
// individual usernames are not known in bridge mode.
// requestedAttrs is the client's Attributes list from the search message; used
// to filter the response via filterAttrs.
// Returns true if the result set was truncated by limit.
func (s *LDAPServer) searchSudoersFromStore(w *gldap.ResponseWriter, req *gldap.Request, filter string, requestedAttrs []string, base string, limit int) bool {
	sudoersDN := "ou=sudoers," + base

	ouAttrs := map[string][]string{
		"objectClass": {"top", "organizationalUnit"},
		"ou":          {"sudoers"},
	}
	if matchesFilter(filter, sudoersDN, ouAttrs) {
		w.Write(req.NewSearchResponseEntry(sudoersDN, gldap.WithAttributes(ouAttrs)))
	}

	noAuth := s.cfg.LDAPSudoNoAuthenticate
	if noAuth == config.SudoNoAuthTrue {
		slog.Warn("SECURITY: LDAPSudoNoAuthenticate=true — ALL sudo rules bypass PAM authentication entirely; users can sudo without any authentication prompt")
	}
	rules := s.sudoRules.Rules()

	var sent int
	for _, rule := range rules {
		if !isValidGroupName(rule.Group) {
			continue
		}
		if rule.Commands == "" {
			continue
		}

		// sudoHost (default: ALL)
		rawHosts := splitComma(rule.Hosts)
		var sudoHosts []string
		if len(rawHosts) == 0 {
			sudoHosts = []string{"ALL"}
		} else {
			for _, h := range rawHosts {
				if h == "ALL" || validSudoHostOrUser.MatchString(h) {
					sudoHosts = append(sudoHosts, h)
				}
			}
		}
		if len(sudoHosts) == 0 {
			continue // all explicit values were invalid — fail-closed
		}
		if len(sudoHosts) == 1 && sudoHosts[0] == "ALL" {
			slog.Info("sudo rule has sudoHost=ALL (permits execution on any host)", "group", rule.Group)
		}

		// sudoCommand
		rawCmds := splitComma(rule.Commands)
		var cmds []string
		for _, c := range rawCmds {
			if validSudoCommand(c) {
				cmds = append(cmds, c)
			}
		}
		if len(cmds) == 0 {
			continue
		}

		// sudoRunAsUser (default: root)
		rawRunAs := splitComma(rule.RunAsUser)
		var sudoRunAsUser []string
		if len(rawRunAs) == 0 {
			sudoRunAsUser = []string{"root"}
		} else {
			for _, u := range rawRunAs {
				if u == "ALL" || validSudoHostOrUser.MatchString(u) {
					sudoRunAsUser = append(sudoRunAsUser, u)
				}
			}
		}
		if len(sudoRunAsUser) == 0 {
			continue
		}

		dn := fmt.Sprintf("cn=%s,%s", escapeDNValue(rule.Group), sudoersDN)
		attrs := map[string][]string{
			"objectClass":   {"top", "sudoRole"},
			"cn":            {rule.Group},
			"sudoUser":      {"%" + rule.Group},
			"sudoHost":      sudoHosts,
			"sudoCommand":   cmds,
			"sudoRunAsUser": sudoRunAsUser,
		}

		// sudoRunAsGroup — optional
		if rawRG := splitComma(rule.RunAsGroup); len(rawRG) > 0 {
			var safe []string
			for _, v := range rawRG {
				if v == "ALL" || validGroupName.MatchString(v) {
					safe = append(safe, v)
				}
			}
			if len(safe) > 0 {
				attrs["sudoRunAsGroup"] = safe
			}
		}

		// sudoOptions
		var sudoOptions []string
		if noAuth == config.SudoNoAuthTrue {
			sudoOptions = append(sudoOptions, "!authenticate")
		}
		if extra := splitComma(rule.Options); len(extra) > 0 {
			for _, opt := range extra {
				if isNoAuthOption(opt) {
					if noAuth == config.SudoNoAuthClaims {
						sudoOptions = append(sudoOptions, strings.TrimSpace(opt))
					}
					continue
				}
				if isSafeSudoOption(opt) {
					sudoOptions = append(sudoOptions, opt)
				}
			}
		}
		if len(sudoOptions) > 0 {
			attrs["sudoOption"] = sudoOptions
		}

		// sudoOrder ensures sudo applies rules in a deterministic order rather
		// than relying on LDAP return order (which is undefined per RFC 4511).
		// The index is 1-based and reflects the iteration order of rules.
		attrs["sudoOrder"] = []string{strconv.Itoa(sent + 1)}

		if !matchesFilter(filter, dn, attrs) {
			continue
		}
		if sent >= limit {
			slog.Warn("ldap: searchSudoersFromStore result cap reached, truncating response", "limit", limit)
			return true
		}
		w.Write(req.NewSearchResponseEntry(dn, gldap.WithAttributes(filterAttrs(attrs, requestedAttrs))))
		sent++
	}
	return false
}

// decrementLimit subtracts used from the current limit and returns the new
// remaining capacity. A limit of 0 means "unlimited" (no client SizeLimit was
// set) and is returned unchanged. For positive limits the result is
// max(0, limit-used); callers should stop dispatching further branches when
// the return value is 0.
func decrementLimit(limit, used int) int {
	if limit == 0 {
		return 0 // unlimited; never decrement
	}
	if remaining := limit - used; remaining > 0 {
		return remaining
	}
	return 0
}

// splitComma splits a comma-separated string into trimmed non-empty values.
func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ── Group / user name validation ─────────────────────────────────────────────

// validGroupName matches safe POSIX group names (max 32 chars per POSIX).
var validGroupName = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// reservedGroupNames are system group names that must not be shadowed by IDP groups.
var reservedGroupNames = map[string]bool{
	"root": true, "wheel": true, "sudo": true, "admin": true, "adm": true,
	"shadow": true, "disk": true, "kmem": true, "tty": true, "tape": true,
	"daemon": true, "bin": true, "sys": true, "staff": true, "operator": true,
	"sshd": true, "docker": true, "lxd": true, "libvirt": true, "kvm": true,
	"all": true, // sudoers ALL keyword
}

// reservedUsernames are system user names that must not be shadowed by IDP users.
// An IDP user with one of these names would override a POSIX system account on
// the client host, potentially granting unintended access.
var reservedUsernames = map[string]bool{
	"root": true, "daemon": true, "bin": true, "sys": true, "sync": true,
	"games": true, "man": true, "lp": true, "mail": true, "news": true,
	"uucp": true, "proxy": true, "www-data": true, "backup": true,
	"list": true, "irc": true, "gnats": true, "nobody": true, "sshd": true,
	"systemd-network": true, "systemd-resolve": true, "messagebus": true,
	"_apt": true, "ntp": true, "postfix": true, "dovecot": true,
}

// isValidGroupName returns true if the group name is safe for use in LDAP entries.
// Group names must be strictly lowercase — case-folding is intentionally rejected
// to avoid silent shadowing of system groups (e.g. "Root" → "root").
func isValidGroupName(name string) bool {
	if !utf8.ValidString(name) {
		return false
	}
	if len(name) > 256 {
		return false
	}
	if reservedGroupNames[strings.ToLower(name)] {
		return false
	}
	return validGroupName.MatchString(name)
}

// ── Sudo claim security validation ───────────────────────────────────────────

// validSudoHostOrUser matches safe values for sudoHost, sudoRunAsUser, sudoRunAsGroup.
var validSudoHostOrUser = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,253}$`)

// validHostname matches safe hostnames for accessHosts (max 255 chars per RFC 1035).
var validHostname = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,255}$`)

// sudoClaimKeys are the custom claim keys that indicate a group defines sudo permissions.
var sudoClaimKeys = []string{"sudoCommands", "sudoHosts", "sudoRunAsUser", "sudoRunAsGroup", "sudoOptions"}

// dangerousSudoOptions are sudo options that enable privilege escalation beyond
// what the allowed commands grant. Blocked from claims input.
var dangerousSudoOptions = map[string]bool{
	"!env_reset": true, "setenv": true, "!requiretty": true,
	"!env_check": true, "!env_delete": true, "!log_output": true,
	"!log_input": true, "!noexec": true, "!use_pty": true,
	"!closefrom": true, "!authenticate": true, "authenticate": true,
	"!syslog": true, "!pam_session": true,
	// These options change which password is prompted for, potentially
	// bypassing the user's own authentication requirement:
	"rootpw": true, "targetpw": true, "runaspw": true,
	// Displays typed passwords in plaintext:
	"visiblepw": true,
	// Without arguments, spawns an interactive shell from a restricted command:
	"shell_noargs": true,
}

// dangerousSudoOptionPrefixesRaw are the human-readable prefix list.
// normalizedDangerousPrefixes is pre-computed at init() time to avoid
// per-call normalization in the hot LDAP path.
var dangerousSudoOptionPrefixesRaw = []string{
	"env_keep+=ld_preload", "env_keep+=ld_library_path", "env_keep+=pythonpath",
	"env_keep+=perl5lib", "env_keep+=rubylib", "env_keep+=node_path",
	"env_keep+=classpath", "env_keep+=gopath", "env_keep+=bash_env",
	"env_keep+=env", "env_keep+=dyld_", "env_keep+=perl5opt",
	"env_keep+=pythonstartup", "env_keep+=java_tool_options",
	"env_keep+=http_proxy", "env_keep+=https_proxy", "env_keep+=cargo_home",
	"env_keep+=gem_path", "env_keep+=path", "env_keep+=home",
	"env_keep+=editor", "env_keep+=visual", "env_keep+=sudo_editor",
	"env_keep+=tmpdir", "env_keep+=ifs", "env_keep+=ld_audit",
	"env_keep+=ld_profile", "env_keep+=prompt_command", "env_keep+=shellopts",
	"env_keep+=bashopts", "env_keep+=cdpath", "env_keep+=globignore",
	"env_keep+=_java_options", "secure_path", "mailerpath", "logfile",
	"lecture_file", "timestamp_timeout", "env_check+=", "env_delete+=",
}

// normalizedDangerousPrefixes is dangerousSudoOptionPrefixesRaw with each
// entry pre-normalized once at package init, avoiding per-call allocation
// in the LDAP hot path.
var normalizedDangerousPrefixes []string

func init() {
	normalizedDangerousPrefixes = make([]string, len(dangerousSudoOptionPrefixesRaw))
	for i, p := range dangerousSudoOptionPrefixesRaw {
		normalizedDangerousPrefixes[i] = strings.ToLower(normalizeSudoOption(p))
	}
}

// hasSudoClaims returns true if the group has any sudo-related custom claims.
func hasSudoClaims(claims map[string]string) bool {
	for _, key := range sudoClaimKeys {
		if v := claims[key]; v != "" {
			return true
		}
	}
	return false
}

// isNoAuthOption returns true if the option is !authenticate or authenticate.
func isNoAuthOption(opt string) bool {
	// Check for control characters before TrimSpace — TrimSpace strips \n and \r but not \t.
	if strings.ContainsAny(opt, "\n\r\t\x00") {
		return false
	}
	normalized := strings.ToLower(strings.TrimSpace(opt))
	normalized = strings.ReplaceAll(normalized, " ", "")
	return normalized == "!authenticate" || normalized == "authenticate"
}

// normalizeSudoOption strips all whitespace and quotes from a sudo option string.
func normalizeSudoOption(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsSpace(r) || r == '"' || r == '\'' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isSafeSudoOption returns true if the sudo option is safe to pass through.
func isSafeSudoOption(opt string) bool {
	// Check for control characters before any trimming — TrimSpace would hide them.
	if strings.ContainsAny(opt, "\n\r\t\x00") {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(opt))
	if lower == "" {
		return false
	}
	if dangerousSudoOptions[lower] {
		return false
	}
	normalized := normalizeSudoOption(lower)
	if dangerousSudoOptions[normalized] {
		return false
	}
	for _, prefix := range normalizedDangerousPrefixes {
		if strings.HasPrefix(normalized, prefix) {
			return false
		}
	}
	return true
}

// validSudoCommand checks that a sudo command value is safe.
func validSudoCommand(cmd string) bool {
	// Check for control characters before TrimSpace — TrimSpace strips \n and \r but not \t.
	if strings.ContainsAny(cmd, "\n\r\t\x00") {
		return false
	}
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false
	}
	if cmd == "ALL" {
		return true
	}
	if strings.HasPrefix(cmd, "!") {
		return false
	}
	if strings.EqualFold(cmd, "sudoedit") || strings.HasPrefix(strings.ToLower(cmd), "sudoedit ") {
		return false
	}
	if !strings.HasPrefix(cmd, "/") {
		return false
	}
	if strings.Contains(cmd, "..") {
		return false
	}
	return true
}

// maxClaimItems caps the number of comma-separated items accepted from a single
// OIDC claim to prevent resource exhaustion from a pathologically large claim.
const maxClaimItems = 500

// maxSSHKeys caps the number of SSH public key claims collected per user.
const maxSSHKeys = 100

// splitClaim splits a comma-separated claim value into trimmed, non-empty values.
func splitClaim(claims map[string]string, key string) []string {
	v := claims[key]
	if v == "" {
		return nil
	}
	var vals []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			vals = append(vals, s)
			if len(vals) >= maxClaimItems {
				break
			}
		}
	}
	return vals
}

// validatedSudoHostOrUser filters a claim's comma-separated values, keeping only
// safe entries. Returns nil if a claim was explicitly set but all values were
// rejected — callers should skip the sudo rule entirely (fail-closed).
func validatedSudoHostOrUser(claims map[string]string, key, def string) []string {
	explicit := splitClaim(claims, key)
	if len(explicit) == 0 {
		return []string{def}
	}
	var safe []string
	for _, v := range explicit {
		if v == "ALL" || validSudoHostOrUser.MatchString(v) {
			safe = append(safe, v)
		}
	}
	return safe // nil means fail-closed
}

// escapeDNValue escapes special characters in an LDAP DN value per RFC 4514.
func escapeDNValue(val string) string {
	var b strings.Builder
	for i, r := range val {
		switch {
		case r == ',' || r == '+' || r == '"' || r == '\\' || r == '<' || r == '>' || r == ';' || r == '=':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '#' && i == 0:
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == ' ' && (i == 0 || i == len(val)-1):
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == 0:
			b.WriteString("\\00")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ── Access host map ───────────────────────────────────────────────────────────

// buildUserHostMap builds a map of username → []hostnames from groups that
// have the accessHosts custom claim. Used to populate the "host" attribute on
// posixAccount entries, which pam_access uses for host-based access control.
func buildUserHostMap(groups []pocketid.PocketIDAdminGroup, dir *pocketid.UserDirectory) map[string][]string {
	userHosts := make(map[string][]string)
	for _, g := range groups {
		if !isValidGroupName(g.Name) {
			continue
		}
		claims := g.ClaimsMap()
		rawHosts := splitClaim(claims, "accessHosts")
		var hosts []string
		for _, h := range rawHosts {
			// Reject "ALL" — could be misinterpreted as wildcard by pam_access.
			if strings.EqualFold(h, "ALL") {
				continue
			}
			// Reject leading-dot hostnames (domain wildcards in pam_access).
			if strings.HasPrefix(h, ".") {
				continue
			}
			if validHostname.MatchString(h) {
				hosts = append(hosts, h)
			}
		}
		if len(hosts) == 0 {
			continue
		}
		for _, m := range g.Members {
			if u, ok := dir.ByUserID[m.ID]; ok {
				userHosts[u.Username] = append(userHosts[u.Username], hosts...)
			}
		}
	}
	// Deduplicate and sort each user's host list.
	for user, hosts := range userHosts {
		seen := make(map[string]struct{}, len(hosts))
		var deduped []string
		for _, h := range hosts {
			if _, ok := seen[h]; !ok {
				seen[h] = struct{}{}
				deduped = append(deduped, h)
			}
		}
		sort.Strings(deduped)
		userHosts[user] = deduped
	}
	return userHosts
}

// ── Attribute filtering ───────────────────────────────────────────────────────

// filterAttrs filters an attribute map to only include attributes requested by
// the client (msg.Attributes). This enforces correctness (clients only see what
// they ask for) and ensures future sensitive fields are not accidentally returned.
//
// Special values per RFC 4511 §4.5.1:
//   - empty slice  → return all attributes (client made no restriction)
//   - "*"          → return all user attributes (same as empty for identree)
//   - "1.1"        → return no attributes (only the DN is meaningful)
//
// "objectClass" is always included as it is operationally required by most LDAP
// clients and is never sensitive.
func filterAttrs(attrs map[string][]string, requested []string) map[string][]string {
	if len(requested) == 0 {
		return attrs // no restriction — return everything
	}
	for _, r := range requested {
		switch r {
		case "*":
			return attrs // explicit "all user attributes"
		case "1.1":
			// Return no attributes — only the DN itself is meaningful.
			result := make(map[string][]string, 1)
			if oc, ok := attrs["objectClass"]; ok {
				result["objectClass"] = oc
			}
			return result
		}
	}
	reqSet := make(map[string]bool, len(requested))
	for _, r := range requested {
		reqSet[strings.ToLower(r)] = true
	}
	result := make(map[string][]string, len(reqSet))
	for k, v := range attrs {
		if reqSet[strings.ToLower(k)] {
			result[k] = v
		}
	}
	// Always include objectClass — required by most clients and not sensitive.
	if _, included := result["objectClass"]; !included {
		if oc, ok := attrs["objectClass"]; ok {
			result["objectClass"] = oc
		}
	}
	return result
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func buildMemberUids(members []struct{ ID string `json:"id"` }, dir *pocketid.UserDirectory) []string {
	var out []string
	for _, m := range members {
		if u, ok := dir.ByUserID[m.ID]; ok {
			if !isValidLDAPAttrValue(u.Username) {
				continue
			}
			// Also validate against the full username regex so that names with
			// special characters (%, @, etc.) cannot appear in sudoUser values
			// where % is the LDAP group-membership syntax for sudoers.
			if !validUsernameRe.MatchString(u.Username) {
				slog.Warn("ldap: skipping user with unsafe username in sudoUser context", "username", u.Username)
				continue
			}
			out = append(out, u.Username)
		}
	}
	return out
}

func buildMemberDNs(members []struct{ ID string `json:"id"` }, dir *pocketid.UserDirectory, peopleDN string) []string {
	var out []string
	for _, m := range members {
		if u, ok := dir.ByUserID[m.ID]; ok {
			if !isValidLDAPAttrValue(u.Username) {
				continue
			}
			out = append(out, fmt.Sprintf("uid=%s,%s", escapeDNValue(u.Username), peopleDN))
		}
	}
	return out
}

// firstDC extracts the first dc= value from a base DN.
func firstDC(baseDN string) string {
	for _, part := range strings.SplitN(baseDN, ",", 2) {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "dc=") {
			return part[3:]
		}
	}
	return baseDN
}

// ── LDAP filter matching ──────────────────────────────────────────────────────
// The gldap library exposes the raw filter string from the client.
// We implement a minimal parser sufficient for nslcd/sssd query patterns.
//
// Supported patterns:
//   - (attr=value)                  equality
//   - (attr=*value*)                substring (contains)
//   - (attr=*)                      presence
//   - (&(f1)(f2)...)                AND
//   - (|(f1)(f2)...)                OR
//   - (!(f))                        NOT
//   - objectClass=value             shorthand objectClass filter

// maxFilterDepth caps recursive filter evaluation to prevent stack exhaustion
// from maliciously nested filters sent by authenticated LDAP clients.
const maxFilterDepth = 32

func matchesFilter(filter, dn string, attrs map[string][]string) bool {
	if filter == "" || filter == "(objectClass=*)" {
		return true
	}
	if len(filter) > maxFilterLength {
		slog.Warn("ldap: rejecting filter exceeding maximum length", "len", len(filter))
		return false
	}
	filter = strings.TrimSpace(filter)
	ok, _ := evalFilterStr(filter, attrs, 0)
	return ok
}

// evalFilterStr evaluates a single LDAP filter expression against an attribute map.
// Returns (match, rest) where rest is the unconsumed portion of the string.
func evalFilterStr(s string, attrs map[string][]string, depth int) (bool, string) {
	if depth > maxFilterDepth {
		return false, "" // fail closed on excessively nested filters
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return true, ""
	}

	// Wrapped filter: (...)
	if !strings.HasPrefix(s, "(") {
		// Bare attr=value (legacy shorthand)
		return evalSimple(s, attrs), ""
	}

	// Find matching close paren, handling nesting
	parenDepth := 0
	end := -1
	for i, c := range s {
		if c == '(' {
			parenDepth++
		} else if c == ')' {
			parenDepth--
			if parenDepth == 0 {
				end = i
				break
			}
		}
	}
	if end < 0 {
		return false, "" // malformed filter — fail closed rather than exposing all entries
	}

	inner := s[1:end]
	rest := s[end+1:]

	switch {
	case strings.HasPrefix(inner, "&"):
		return evalAnd(inner[1:], attrs, depth+1), rest
	case strings.HasPrefix(inner, "|"):
		return evalOr(inner[1:], attrs, depth+1), rest
	case strings.HasPrefix(inner, "!"):
		ok, _ := evalFilterStr(strings.TrimSpace(inner[1:]), attrs, depth+1)
		return !ok, rest
	default:
		return evalSimple(inner, attrs), rest
	}
}

func evalAnd(s string, attrs map[string][]string, depth int) bool {
	s = strings.TrimSpace(s)
	for s != "" {
		if !strings.HasPrefix(s, "(") {
			break
		}
		ok, rest := evalFilterStr(s, attrs, depth)
		if !ok {
			return false
		}
		s = strings.TrimSpace(rest)
	}
	return true
}

func evalOr(s string, attrs map[string][]string, depth int) bool {
	s = strings.TrimSpace(s)
	for s != "" {
		if !strings.HasPrefix(s, "(") {
			break
		}
		ok, rest := evalFilterStr(s, attrs, depth)
		if ok {
			return true
		}
		s = strings.TrimSpace(rest)
	}
	return false
}

// unescapeFilterValue decodes RFC 4515 escape sequences (\XX where XX is a hex
// byte) in an LDAP filter assertion value, converting them to their literal byte
// equivalents.  Any malformed escape sequence is left as-is.
func unescapeFilterValue(s string) string {
	if !strings.Contains(s, `\`) {
		return s // fast path: no escape sequences present
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+2 < len(s) && isLDAPHexByte(s[i+1]) && isLDAPHexByte(s[i+2]) {
			b.WriteByte(ldapHexVal(s[i+1])<<4 | ldapHexVal(s[i+2]))
			i += 3
		} else {
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

// containsUnescapedStar reports whether s contains a literal unescaped '*' character.
// An '*' immediately following a valid \XX escape is treated as escaped (\2a → '*')
// and does NOT count.
func containsUnescapedStar(s string) bool {
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+2 < len(s) && isLDAPHexByte(s[i+1]) && isLDAPHexByte(s[i+2]) {
			i += 3 // skip the escape sequence
		} else if s[i] == '*' {
			return true
		} else {
			i++
		}
	}
	return false
}

func isLDAPHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func ldapHexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default: // 'A'-'F'
		return c - 'A' + 10
	}
}

// evalSimple evaluates a bare attr=value, attr=*, or attr=*sub* expression.
func evalSimple(expr string, attrs map[string][]string) bool {
	idx := strings.IndexByte(expr, '=')
	if idx < 0 {
		return false // unparseable — fail closed
	}
	name := strings.TrimSpace(strings.ToLower(expr[:idx]))
	value := expr[idx+1:]

	// Presence: attr=*
	if value == "*" {
		vals, ok := attrs[name]
		if !ok {
			// Try case-insensitive key lookup
			vals, ok = attrValuesCaseInsensitive(attrs, name)
		}
		return ok && len(vals) > 0
	}

	vals, ok := attrs[name]
	if !ok {
		vals, ok = attrValuesCaseInsensitive(attrs, name)
	}
	if !ok {
		return false
	}

	// Substring: *value*, value*, *value
	if containsUnescapedStar(value) {
		for _, v := range vals {
			if ldapSubstringMatchRaw(strings.ToLower(v), value) {
				return true
			}
		}
		return false
	}

	// Equality (case-insensitive for LDAP)
	lv := strings.ToLower(unescapeFilterValue(value))
	for _, v := range vals {
		if strings.ToLower(v) == lv {
			return true
		}
	}
	return false
}

// attrValuesCaseInsensitive looks up an attribute with case-insensitive key matching.
func attrValuesCaseInsensitive(attrs map[string][]string, name string) ([]string, bool) {
	for k, v := range attrs {
		if strings.ToLower(k) == name {
			return v, true
		}
	}
	return nil, false
}

// ldapSubstringMatchRaw implements RFC 4515 substring filter matching against a
// normalised (lowercased) attribute value.  rawPattern is the raw filter
// assertion value — it may contain RFC 4515 escape sequences (\XX) and uses
// unescaped '*' characters as wildcard separators.
func ldapSubstringMatchRaw(value, rawPattern string) bool {
	// Split rawPattern on unescaped '*' characters, unescaping each segment.
	var parts []string
	var cur strings.Builder
	i := 0
	for i < len(rawPattern) {
		if rawPattern[i] == '\\' && i+2 < len(rawPattern) && isLDAPHexByte(rawPattern[i+1]) && isLDAPHexByte(rawPattern[i+2]) {
			cur.WriteByte(ldapHexVal(rawPattern[i+1])<<4 | ldapHexVal(rawPattern[i+2]))
			i += 3
		} else if rawPattern[i] == '*' {
			parts = append(parts, strings.ToLower(cur.String()))
			cur.Reset()
			i++
		} else {
			cur.WriteByte(rawPattern[i])
			i++
		}
	}
	parts = append(parts, strings.ToLower(cur.String()))

	// RFC 4515 §4.5.1: parts[0]=initial, parts[1:-1]=any, parts[-1]=final.
	pos := 0
	for idx, part := range parts {
		if part == "" {
			continue
		}
		switch {
		case idx == 0: // initial — value must start with this part
			if !strings.HasPrefix(value[pos:], part) {
				return false
			}
			pos += len(part)
		case idx == len(parts)-1: // final — value must end with this part
			if !strings.HasSuffix(value[pos:], part) {
				return false
			}
		default: // any — part must appear somewhere after pos
			rel := strings.Index(value[pos:], part)
			if rel < 0 {
				return false
			}
			pos += rel + len(part)
		}
	}
	return true
}

