package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jimlambrt/gldap"
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
	cfg    *ServerConfig
	uidmap *UIDMap

	mu  sync.RWMutex
	dir *UserDirectory // refreshed periodically

	srv *gldap.Server
}

// NewLDAPServer creates (but does not start) the LDAP server.
func NewLDAPServer(cfg *ServerConfig, uidmap *UIDMap) (*LDAPServer, error) {
	return &LDAPServer{
		cfg:    cfg,
		uidmap: uidmap,
	}, nil
}

// Refresh replaces the cached directory snapshot atomically.
// It eagerly assigns UIDs/GIDs for all entries so the map stays current.
func (s *LDAPServer) Refresh(dir *UserDirectory) {
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
func (s *LDAPServer) searchPeople(w *gldap.ResponseWriter, req *gldap.Request, filter string, dir *UserDirectory, base string) {
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
			"objectClass":    {"top", "posixAccount", "shadowAccount", "inetOrgPerson"},
			"uid":            {u.Username},
			"cn":             {fullName},
			"sn":             {sn},
			"givenName":      {u.FirstName},
			"mail":           {u.Email},
			"uidNumber":      {fmt.Sprintf("%d", uid)},
			"gidNumber":      {fmt.Sprintf("%d", gid)},
			"homeDirectory":  {fmt.Sprintf("/home/%s", u.Username)},
			"loginShell":     {"/bin/bash"},
			"gecos":          {fullName},
			"shadowLastChange": {"0"},
			"shadowMax":      {"99999"},
			"shadowWarning":  {"7"},
		}

		if !matchesFilter(filter, dn, attrs) {
			continue
		}
		entry := req.NewSearchResponseEntry(dn, gldap.WithAttributes(attrs))
		w.Write(entry)
	}
}

// searchGroups sends posixGroup entries for PocketID groups and User Private Groups.
func (s *LDAPServer) searchGroups(w *gldap.ResponseWriter, req *gldap.Request, filter string, dir *UserDirectory, base string) {
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

// searchSudoers emits sudoRole entries for groups that follow the sudo naming convention:
//   - group "sudo" / "sudoers" / "wheel"  → Host: ALL
//   - group "sudo-<hostname>"              → Host: <hostname>
func (s *LDAPServer) searchSudoers(w *gldap.ResponseWriter, req *gldap.Request, filter string, dir *UserDirectory, base string) {
	sudoersDN := "ou=sudoers," + base

	ouAttrs := map[string][]string{
		"objectClass": {"top", "organizationalUnit"},
		"ou":          {"sudoers"},
	}
	if matchesFilter(filter, sudoersDN, ouAttrs) {
		w.Write(req.NewSearchResponseEntry(sudoersDN, gldap.WithAttributes(ouAttrs)))
	}

	for _, g := range dir.Groups {
		var sudoHost string
		lower := strings.ToLower(g.Name)
		switch {
		case lower == "sudo" || lower == "sudoers" || lower == "wheel":
			sudoHost = "ALL"
		case strings.HasPrefix(lower, "sudo-"):
			sudoHost = g.Name[len("sudo-"):]
		default:
			continue
		}

		dn := fmt.Sprintf("cn=%s,%s", g.Name, sudoersDN)
		uids := buildMemberUids(g.Members, dir)

		attrs := map[string][]string{
			"objectClass": {"top", "sudoRole"},
			"cn":          {g.Name},
			"sudoHost":    {sudoHost},
			"sudoCommand": {"ALL"},
			"sudoOption":  {"!authenticate"},
		}
		if len(uids) > 0 {
			attrs["sudoUser"] = uids
		}

		if !matchesFilter(filter, dn, attrs) {
			continue
		}
		w.Write(req.NewSearchResponseEntry(dn, gldap.WithAttributes(attrs)))
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

type memberRef struct{ ID string }

func buildMemberUids(members []struct{ ID string `json:"id"` }, dir *UserDirectory) []string {
	var out []string
	for _, m := range members {
		if u, ok := dir.ByUserID[m.ID]; ok {
			out = append(out, u.Username)
		}
	}
	return out
}

func buildMemberDNs(members []struct{ ID string `json:"id"` }, dir *UserDirectory, peopleDN string) []string {
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
func (s *LDAPServer) RunRefreshLoop(ctx context.Context, client *PocketIDClient, refreshCh <-chan struct{}) {
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
		s.Refresh(NewUserDirectory(users, groups))
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
