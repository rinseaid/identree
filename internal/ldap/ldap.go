package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jimlambrt/gldap"

	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/pocketid"
	"github.com/rinseaid/identree/internal/uidmap"
)

// LDAPServer embeds an RFC 4519 LDAP server exposing posixAccount/posixGroup/sudoRole
// entries derived from a live PocketID user directory.
//
// Schema layout (assuming base DN "dc=example,dc=com"):
//
//	ou=people,dc=example,dc=com      — posixAccount + shadowAccount per user
//	ou=groups,dc=example,dc=com      — posixGroup per group + one UPG per user
//	ou=sudoers,dc=example,dc=com     — sudoRole entries derived from group names
type LDAPServer struct {
	cfg    *config.ServerConfig
	uidmap *uidmap.UIDMap

	mu  sync.RWMutex
	dir *pocketid.UserDirectory // refreshed periodically

	srv *gldap.Server
}

// NewLDAPServer creates (but does not start) the LDAP server.
func NewLDAPServer(cfg *config.ServerConfig, uidmap *uidmap.UIDMap) (*LDAPServer, error) {
	return &LDAPServer{
		cfg:    cfg,
		uidmap: uidmap,
	}, nil
}

// Refresh replaces the cached directory snapshot atomically.
// It eagerly assigns UIDs/GIDs for all entries so the map stays current.
func (s *LDAPServer) Refresh(dir *pocketid.UserDirectory) {
	for _, u := range dir.Users {
		s.uidmap.UID(u.ID)
	}
	for _, g := range dir.Groups {
		s.uidmap.GID(g.ID)
	}
	_ = s.uidmap.Flush()

	s.mu.Lock()
	s.dir = dir
	s.mu.Unlock()

	slog.Info("ldap: directory refreshed",
		"users", len(dir.Users),
		"groups", len(dir.Groups),
	)
}

// Start launches the LDAP listener. It blocks until ctx is cancelled.
func (s *LDAPServer) Start(ctx context.Context) error {
	srv, err := gldap.NewServer(gldap.WithDisablePanicRecovery())
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

	slog.Info("ldap: listening", "addr", s.cfg.LDAPListenAddr)
	return srv.Run(s.cfg.LDAPListenAddr)
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

	// Anonymous bind — always allowed (read-only directory)
	if msg.UserName == "" {
		resp.SetResultCode(gldap.ResultSuccess)
		return
	}

	// Service-account bind — must match configured bind DN and password
	if s.cfg.LDAPBindDN != "" && msg.UserName == s.cfg.LDAPBindDN {
		if s.cfg.LDAPBindPassword != "" && string(msg.Password) == s.cfg.LDAPBindPassword {
			resp.SetResultCode(gldap.ResultSuccess)
		}
		// Otherwise stays InvalidCredentials
		return
	}

	// All other binds rejected — identree is a read-only directory
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

	s.mu.RLock()
	dir := s.dir
	s.mu.RUnlock()

	if dir == nil {
		resp.SetResultCode(gldap.ResultBusy)
		return
	}

	base := s.cfg.LDAPBaseDN
	scope := strings.ToLower(msg.BaseDN)
	peopleDN := strings.ToLower("ou=people," + base)
	groupsDN := strings.ToLower("ou=groups," + base)
	sudoersDN := strings.ToLower("ou=sudoers," + base)
	baseLower := strings.ToLower(base)

	filter := msg.Filter

	switch {
	case scope == baseLower && msg.Scope == gldap.BaseObject:
		s.sendRootDSE(w, req, base)

	case scope == peopleDN || strings.HasSuffix(scope, ","+peopleDN):
		s.searchPeople(w, req, filter, dir, base)

	case scope == groupsDN || strings.HasSuffix(scope, ","+groupsDN):
		s.searchGroups(w, req, filter, dir, base)

	case scope == sudoersDN || strings.HasSuffix(scope, ","+sudoersDN):
		s.searchSudoers(w, req, filter, dir, base)

	case scope == baseLower:
		// Subtree from root — serve everything
		s.searchPeople(w, req, filter, dir, base)
		s.searchGroups(w, req, filter, dir, base)
		s.searchSudoers(w, req, filter, dir, base)
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
func (s *LDAPServer) searchPeople(w *gldap.ResponseWriter, req *gldap.Request, filter string, dir *pocketid.UserDirectory, base string) {
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

	// Pre-compute host access restrictions from accessHosts claims.
	userHosts := buildUserHostMap(dir.Groups, dir)

	for _, u := range dir.Users {
		uid := s.uidmap.UID(u.ID)
		gid := uid // UPG: primary group GID == UID
		dn := fmt.Sprintf("uid=%s,%s", u.Username, peopleDN)
		fullName := strings.TrimSpace(u.FirstName + " " + u.LastName)
		if fullName == "" {
			fullName = u.Username
		}
		sn := u.LastName
		if sn == "" {
			sn = u.Username
		}

		attrs := map[string][]string{
			"objectClass":      {"top", "posixAccount", "shadowAccount", "inetOrgPerson"},
			"uid":              {u.Username},
			"cn":               {fullName},
			"sn":               {sn},
			"givenName":        {u.FirstName},
			"mail":             {u.Email},
			"uidNumber":        {fmt.Sprintf("%d", uid)},
			"gidNumber":        {fmt.Sprintf("%d", gid)},
			"homeDirectory":    {fmt.Sprintf("/home/%s", u.Username)},
			"loginShell":       {"/bin/bash"},
			"gecos":            {fullName},
			"shadowLastChange": {"0"},
			"shadowMax":        {"99999"},
			"shadowWarning":    {"7"},
		}

		// Populate host attribute from accessHosts claim for pam_access.
		if hosts, ok := userHosts[u.Username]; ok && len(hosts) > 0 {
			attrs["host"] = hosts
		}

		if !matchesFilter(filter, dn, attrs) {
			continue
		}
		entry := req.NewSearchResponseEntry(dn, gldap.WithAttributes(attrs))
		w.Write(entry)
	}
}

// searchGroups sends posixGroup entries for PocketID groups and User Private Groups.
func (s *LDAPServer) searchGroups(w *gldap.ResponseWriter, req *gldap.Request, filter string, dir *pocketid.UserDirectory, base string) {
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
	for _, g := range dir.Groups {
		gid := s.uidmap.GID(g.ID)
		dn := fmt.Sprintf("cn=%s,%s", g.Name, groupsDN)

		memberUids := buildMemberUids(g.Members, dir)
		memberDNs := buildMemberDNs(g.Members, dir, peopleDN)

		name := g.FriendlyName
		if name == "" {
			name = g.Name
		}

		attrs := map[string][]string{
			"objectClass": {"top", "posixGroup"},
			"cn":          {g.Name},
			"description": {name},
			"gidNumber":   {fmt.Sprintf("%d", gid)},
		}
		if len(memberUids) > 0 {
			attrs["memberUid"] = memberUids
			attrs["member"] = memberDNs
		}

		if !matchesFilter(filter, dn, attrs) {
			continue
		}
		w.Write(req.NewSearchResponseEntry(dn, gldap.WithAttributes(attrs)))
	}

	// User Private Groups (one per user, GID == UID)
	for _, u := range dir.Users {
		uid := s.uidmap.UID(u.ID)
		dn := fmt.Sprintf("cn=%s,%s", u.Username, groupsDN)
		attrs := map[string][]string{
			"objectClass": {"top", "posixGroup"},
			"cn":          {u.Username},
			"gidNumber":   {fmt.Sprintf("%d", uid)},
			"memberUid":   {u.Username},
		}
		if !matchesFilter(filter, dn, attrs) {
			continue
		}
		w.Write(req.NewSearchResponseEntry(dn, gldap.WithAttributes(attrs)))
	}
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
// required fields pass validation. Security validation mirrors glauth-pocketid.
func (s *LDAPServer) searchSudoers(w *gldap.ResponseWriter, req *gldap.Request, filter string, dir *pocketid.UserDirectory, base string) {
	sudoersDN := "ou=sudoers," + base

	ouAttrs := map[string][]string{
		"objectClass": {"top", "organizationalUnit"},
		"ou":          {"sudoers"},
	}
	if matchesFilter(filter, sudoersDN, ouAttrs) {
		w.Write(req.NewSearchResponseEntry(sudoersDN, gldap.WithAttributes(ouAttrs)))
	}

	noAuth := s.cfg.LDAPSudoNoAuthenticate

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
				if v == "ALL" || validSudoHostOrUser.MatchString(v) {
					safe = append(safe, v)
				}
			}
			if len(safe) > 0 {
				attrs["sudoRunAsGroup"] = safe
			}
		}

		// sudoOptions: controlled by LDAPSudoNoAuthenticate + per-group claim
		var sudoOptions []string
		if noAuth == "true" {
			sudoOptions = append(sudoOptions, "!authenticate")
		}
		if extra := splitClaim(claims, "sudoOptions"); len(extra) > 0 {
			for _, opt := range extra {
				if isNoAuthOption(opt) {
					if noAuth == "claims" {
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

		if !matchesFilter(filter, dn, attrs) {
			continue
		}
		w.Write(req.NewSearchResponseEntry(dn, gldap.WithAttributes(attrs)))
	}
}

// ── Group / user name validation ─────────────────────────────────────────────

// validGroupName matches safe POSIX group names.
var validGroupName = regexp.MustCompile(`^[a-z_][a-z0-9_.-]*$`)

// reservedGroupNames are system group names that must not be shadowed by IDP groups.
var reservedGroupNames = map[string]bool{
	"root": true, "wheel": true, "sudo": true, "admin": true, "adm": true,
	"shadow": true, "disk": true, "kmem": true, "tty": true, "tape": true,
	"daemon": true, "bin": true, "sys": true, "staff": true, "operator": true,
	"sshd": true, "docker": true, "lxd": true, "libvirt": true, "kvm": true,
	"all": true, // sudoers ALL keyword
}

// isValidGroupName returns true if the group name is safe for use in LDAP entries.
func isValidGroupName(name string) bool {
	if !utf8.ValidString(name) {
		return false
	}
	if len(name) > 256 {
		return false
	}
	lower := strings.ToLower(name)
	if reservedGroupNames[lower] {
		return false
	}
	return validGroupName.MatchString(lower)
}

// ── Sudo claim security validation ───────────────────────────────────────────

// validSudoHostOrUser matches safe values for sudoHost, sudoRunAsUser, sudoRunAsGroup.
var validSudoHostOrUser = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// validHostname matches safe hostnames for accessHosts.
var validHostname = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

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
}

// dangerousSudoOptionPrefixes are prefixes of sudo options that are blocked.
var dangerousSudoOptionPrefixes = []string{
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
	lower := strings.ToLower(strings.TrimSpace(opt))
	if lower == "" {
		return false
	}
	if strings.ContainsAny(lower, "\n\r") {
		return false
	}
	if dangerousSudoOptions[lower] {
		return false
	}
	normalized := normalizeSudoOption(lower)
	if dangerousSudoOptions[normalized] {
		return false
	}
	for _, prefix := range dangerousSudoOptionPrefixes {
		if strings.HasPrefix(normalized, strings.ToLower(normalizeSudoOption(prefix))) {
			return false
		}
	}
	return true
}

// validSudoCommand checks that a sudo command value is safe.
func validSudoCommand(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false
	}
	if strings.ContainsRune(cmd, 0) {
		return false
	}
	if strings.ContainsAny(cmd, "\n\r") {
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
		case r == ',' || r == '+' || r == '"' || r == '\\' || r == '<' || r == '>' || r == ';':
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

// ── Helpers ───────────────────────────────────────────────────────────────────

type memberRef struct{ ID string }

func buildMemberUids(members []struct{ ID string `json:"id"` }, dir *pocketid.UserDirectory) []string {
	var out []string
	for _, m := range members {
		if u, ok := dir.ByUserID[m.ID]; ok {
			out = append(out, u.Username)
		}
	}
	return out
}

func buildMemberDNs(members []struct{ ID string `json:"id"` }, dir *pocketid.UserDirectory, peopleDN string) []string {
	var out []string
	for _, m := range members {
		if u, ok := dir.ByUserID[m.ID]; ok {
			out = append(out, fmt.Sprintf("uid=%s,%s", u.Username, peopleDN))
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

func matchesFilter(filter, dn string, attrs map[string][]string) bool {
	if filter == "" || filter == "(objectClass=*)" {
		return true
	}
	filter = strings.TrimSpace(filter)
	ok, _ := evalFilterStr(filter, attrs)
	return ok
}

// evalFilterStr evaluates a single LDAP filter expression against an attribute map.
// Returns (match, rest) where rest is the unconsumed portion of the string.
func evalFilterStr(s string, attrs map[string][]string) (bool, string) {
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
	depth := 0
	end := -1
	for i, c := range s {
		if c == '(' {
			depth++
		} else if c == ')' {
			depth--
			if depth == 0 {
				end = i
				break
			}
		}
	}
	if end < 0 {
		return true, "" // malformed — pass through
	}

	inner := s[1:end]
	rest := s[end+1:]

	switch {
	case strings.HasPrefix(inner, "&"):
		return evalAnd(inner[1:], attrs), rest
	case strings.HasPrefix(inner, "|"):
		return evalOr(inner[1:], attrs), rest
	case strings.HasPrefix(inner, "!"):
		ok, _ := evalFilterStr(strings.TrimSpace(inner[1:]), attrs)
		return !ok, rest
	default:
		return evalSimple(inner, attrs), rest
	}
}

func evalAnd(s string, attrs map[string][]string) bool {
	s = strings.TrimSpace(s)
	for s != "" {
		if !strings.HasPrefix(s, "(") {
			break
		}
		ok, rest := evalFilterStr(s, attrs)
		if !ok {
			return false
		}
		s = strings.TrimSpace(rest)
	}
	return true
}

func evalOr(s string, attrs map[string][]string) bool {
	s = strings.TrimSpace(s)
	for s != "" {
		if !strings.HasPrefix(s, "(") {
			break
		}
		ok, rest := evalFilterStr(s, attrs)
		if ok {
			return true
		}
		s = strings.TrimSpace(rest)
	}
	return false
}

// evalSimple evaluates a bare attr=value, attr=*, or attr=*sub* expression.
func evalSimple(expr string, attrs map[string][]string) bool {
	idx := strings.IndexByte(expr, '=')
	if idx < 0 {
		return true // unparseable — pass through
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
	if strings.Contains(value, "*") {
		for _, v := range vals {
			if ldapSubstringMatch(strings.ToLower(v), strings.ToLower(value)) {
				return true
			}
		}
		return false
	}

	// Equality (case-insensitive for LDAP)
	lv := strings.ToLower(value)
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

// ldapSubstringMatch implements simple glob matching for LDAP substring filters.
// Pattern uses * as wildcard, e.g. "alice*" or "*@example.com" or "*alice*".
func ldapSubstringMatch(value, pattern string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return value == pattern
	}
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(value[pos:], part)
		if idx < 0 {
			return false
		}
		if i == 0 && !strings.HasPrefix(value, part) {
			return false
		}
		if i == len(parts)-1 && !strings.HasSuffix(value, part) {
			return false
		}
		pos += idx + len(part)
	}
	return true
}

// ── Directory refresh loop ────────────────────────────────────────────────────

// RunRefreshLoop polls the PocketID API and updates the LDAP directory.
// refreshCh receives signals for immediate refresh (from webhook events).
func (s *LDAPServer) RunRefreshLoop(ctx context.Context, client *pocketid.PocketIDClient, refreshCh <-chan struct{}) {
	interval := s.cfg.LDAPRefreshInterval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	doRefresh := func() {
		users, err := client.AllAdminUsers()
		if err != nil {
			slog.Error("ldap: refresh users", "err", err)
			return
		}
		groups, err := client.AllAdminGroups()
		if err != nil {
			slog.Error("ldap: refresh groups", "err", err)
			return
		}
		s.Refresh(pocketid.NewUserDirectory(users, groups))
	}

	doRefresh() // initial load

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			doRefresh()
		case <-refreshCh:
			slog.Info("ldap: webhook-triggered refresh")
			doRefresh()
			ticker.Reset(interval)
		}
	}
}
