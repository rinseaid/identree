package server

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/pocketid"
)

// handleThemeToggle sets the theme preference cookie based on the "set" query
// param and redirects back.
// GET /theme?set=dark|light|system&from=/path
func (s *Server) handleThemeToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	target := r.URL.Query().Get("set")
	secure := strings.HasPrefix(s.cfg.ExternalURL, "https://")
	switch target {
	case "dark":
		http.SetCookie(w, &http.Cookie{Name: "identree_theme", Value: "dark", Path: "/", MaxAge: 31536000, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secure})
	case "light":
		http.SetCookie(w, &http.Cookie{Name: "identree_theme", Value: "light", Path: "/", MaxAge: 31536000, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secure})
	default: // "system" or anything else — delete cookie
		http.SetCookie(w, &http.Cookie{Name: "identree_theme", Value: "", Path: "/", MaxAge: -1, Secure: secure})
	}

	dest := r.URL.Query().Get("from")
	if dest == "" || !strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "//") || strings.ContainsAny(dest, "?#\\") {
		dest = "/"
	}
	http.Redirect(w, r, s.baseURL+dest, http.StatusSeeOther)
}

// handleSignOut clears the session cookie and redirects to OIDC login.
// POST /signout
func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, Secure: strings.HasPrefix(s.cfg.ExternalURL, "https://")})
	loginURL := s.baseURL + "/sessions/login"
	http.Redirect(w, r, loginURL, http.StatusSeeOther)
}

// handleDevLogin bypasses OIDC and sets a session cookie directly.
// Only registered when IDENTREE_DEV_LOGIN=true. Never use in production.
// GET /dev/login?user=alice&role=admin
func (s *Server) handleDevLogin(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DevLoginEnabled {
		http.NotFound(w, r)
		return
	}
	user := r.URL.Query().Get("user")
	role := r.URL.Query().Get("role")
	if user == "" || !validUsername.MatchString(user) {
		http.Error(w, "missing or invalid user param", http.StatusBadRequest)
		return
	}
	if role != "admin" && role != "user" {
		role = "user"
	}
	s.setSessionCookie(w, user, role)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleDevSeedHistory injects action log entries at a given timestamp offset.
// Only registered when IDENTREE_DEV_LOGIN=true. Never use in production.
// POST /dev/seed-history  body: [{"username":"alice","action":"approved","hostname":"prod-web-01","actor":"testadmin","minutes_ago":90}]
func (s *Server) handleDevSeedHistory(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DevLoginEnabled {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var entries []struct {
		Username   string `json:"username"`
		Action     string `json:"action"`
		Hostname   string `json:"hostname"`
		Actor      string `json:"actor"`
		MinutesAgo int    `json:"minutes_ago"`
	}
	if err := json.NewDecoder(r.Body).Decode(&entries); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	now := time.Now()
	for _, e := range entries {
		at := now.Add(-time.Duration(e.MinutesAgo) * time.Minute)
		s.store.LogActionAt(e.Username, e.Action, e.Hostname, "", e.Actor, at)
	}
	w.WriteHeader(http.StatusCreated)
}

// handleDevSeedSession creates a grace session directly for testing.
// Only registered when IDENTREE_DEV_LOGIN=true. Never use in production.
// POST /dev/seed-session  body: {"username":"alice","hostname":"prod-web-01"}
func (s *Server) handleDevSeedSession(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DevLoginEnabled {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Hostname string `json:"hostname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	s.store.CreateGraceSession(req.Username, req.Hostname, s.cfg.GracePeriod)
	w.WriteHeader(http.StatusCreated)
}

// handleDashboard renders the main dashboard page.
// GET /
// pendingView is the template representation of a pending sudo challenge.
type pendingView struct {
	ID            string
	Username      string
	Hostname      string
	Code          string
	ExpiresIn     string
	AdminRequired bool
}

// buildPendingViews fetches pending challenges for username and converts them
// to template-ready views, sorted by expiry (most urgent first).
func (s *Server) buildPendingViews(username, lang string) []pendingView {
	t := T(lang)
	pending := s.store.PendingChallenges(username)
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].ExpiresAt.Before(pending[j].ExpiresAt)
	})
	var views []pendingView
	for _, c := range pending {
		hostname := c.Hostname
		if hostname == "" {
			hostname = t("unknown_host")
		}
		views = append(views, pendingView{
			ID:            c.ID,
			Username:      c.Username,
			Hostname:      hostname,
			Code:          c.UserCode,
			ExpiresIn:     formatDuration(time.Until(c.ExpiresAt)),
			AdminRequired: s.requiresAdminApproval(c.Hostname),
		})
	}
	return views
}

// buildAllPendingViews returns pending challenges across all users for the
// admin queue panel. Sorted by expiry (most urgent first).
func (s *Server) buildAllPendingViews(lang string) []pendingView {
	t := T(lang)
	pending := s.store.AllPendingChallenges()
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].ExpiresAt.Before(pending[j].ExpiresAt)
	})
	var views []pendingView
	for _, c := range pending {
		hostname := c.Hostname
		if hostname == "" {
			hostname = t("unknown_host")
		}
		views = append(views, pendingView{
			ID:            c.ID,
			Username:      c.Username,
			Hostname:      hostname,
			Code:          c.UserCode,
			ExpiresIn:     formatDuration(time.Until(c.ExpiresAt)),
			AdminRequired: s.requiresAdminApproval(c.Hostname),
		})
	}
	return views
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// The "/" pattern is a catch-all in Go's ServeMux. Only handle exact "/" path.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
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

	// Read and clear flash BEFORE auth check so login page can show flash messages.
	var flashes []string
	if flashParam := s.getAndClearFlash(w, r); flashParam != "" {
		for _, f := range strings.Split(flashParam, ",") {
			parts := strings.SplitN(f, ":", 5)
			if len(parts) < 2 {
				continue
			}
			switch parts[0] {
			case "approved":
				if len(parts) == 4 {
					flashes = append(flashes, t("approved_sudo_on")+" "+parts[1]+" ("+parts[2]+") "+t("until")+" "+formatFlashTime(parts[3]))
				} else {
					flashes = append(flashes, t("approved_sudo_on")+" "+parts[1])
				}
			case "revoked":
				if len(parts) == 3 {
					flashes = append(flashes, t("revoked_session_on")+" "+parts[1]+" ("+parts[2]+")")
				} else {
					flashes = append(flashes, t("revoked_session_on")+" "+parts[1])
				}
			case "approved_all":
				flashes = append(flashes, fmt.Sprintf(t("approved_n_requests"), atoi(parts[1])))
			case "revoked_all":
				flashes = append(flashes, fmt.Sprintf(t("revoked_n_sessions"), atoi(parts[1])))
			case "rejected":
				flashes = append(flashes, t("rejected_sudo_on")+" "+parts[1])
			case "rejected_all":
				flashes = append(flashes, fmt.Sprintf(t("rejected_n_requests"), atoi(parts[1])))
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
				msg := fmt.Sprintf(t("extended_n_sessions"), atoi(parts[1]))
				if len(parts) >= 3 {
					msg += " " + t("until") + " " + formatFlashTime(parts[2])
				}
				flashes = append(flashes, msg)
			case "expired":
				flashes = append(flashes, t("session_expired_sign_in"))
			}
		}
	}

	username := s.getSessionUser(r)
	if username == "" {
		// Auto-redirect to OIDC login — no intermediate page
		loginURL := s.baseURL + "/sessions/login"
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}

	// Refresh session cookie on every dashboard page load (sliding 30-min window).
	role := s.getSessionRole(r)
	s.setSessionCookie(w, username, role)
	isAdmin := role == "admin"

	var allHistoryWithUsers []challpkg.ActionLogEntryWithUser
	for _, e := range s.store.ActionHistory(username, 6) {
		allHistoryWithUsers = append(allHistoryWithUsers, challpkg.ActionLogEntryWithUser{
			Username:  username,
			Actor:     e.Actor,
			Timestamp: e.Timestamp,
			Action:    e.Action,
			Hostname:  e.Hostname,
			Code:      e.Code,
		})
	}
	// Limit dashboard to most recent 5 entries
	dashHistory := allHistoryWithUsers
	if len(dashHistory) > 5 {
		dashHistory = dashHistory[:5]
	}

	now := time.Now()
	csrfTs := strconv.FormatInt(now.Unix(), 10)
	csrfToken := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)

	pendingViews := s.buildPendingViews(username, lang)

	// Fetch Pocket ID permissions for this user to build host-access view
	var userPerms map[string][]pocketid.GroupInfo
	pocketIDUnavailable := false
	if s.pocketIDClient != nil {
		if perms, err := s.pocketIDClient.GetUserPermissions(); err == nil {
			userPerms = perms
		} else {
			pocketIDUnavailable = true
		}
	}

	// Build the host list: known hosts + any explicitly listed in Pocket ID claims
	knownHosts := s.store.KnownHosts(username)
	hostSet := make(map[string]bool)
	for _, h := range knownHosts {
		hostSet[h] = true
	}
	for _, g := range userPerms[username] {
		if g.SudoHosts == "" || g.SudoHosts == "ALL" {
			continue // "ALL" / unrestricted doesn't list specific hosts
		}
		for _, part := range strings.Split(g.SudoHosts, ",") {
			h := strings.TrimSpace(part)
			if h != "" && !hostSet[h] {
				hostSet[h] = true
				knownHosts = append(knownHosts, h)
			}
		}
	}
	sort.Strings(knownHosts)

	// Duration options for extend/elevate dropdowns.
	type durationOption struct {
		Value int
		Label string
	}
	allDurations := []durationOption{
		{3600, "1h"},
		{7200, "2h"},
		{14400, "4h"},
		{28800, "8h"},
		{86400, "1d"},
	}
	graceSec := int(s.cfg.GracePeriod.Seconds())
	if graceSec <= 0 {
		graceSec = 86400
	}
	// extendDurationsFor returns only the options where the extension would
	// fit within the remaining grace period headroom.
	extendDurationsFor := func(remainingSec int) []durationOption {
		headroom := graceSec - remainingSec
		var out []durationOption
		for _, d := range allDurations {
			if d.Value <= headroom {
				out = append(out, d)
			}
		}
		return out
	}

	// Build active-session map for quick lookup (hostname -> remaining time)
	type activeInfo struct {
		remaining    string
		remainingSec int
	}
	activeMap := make(map[string]activeInfo)
	for _, sess := range s.store.ActiveSessions(username) {
		rem := time.Until(sess.ExpiresAt)
		activeMap[sess.Hostname] = activeInfo{formatDuration(rem), int(rem.Seconds())}
	}

	type hostAccessView struct {
		Hostname       string
		Active         bool
		Remaining      string
		SudoSummary    string
		ExtendDurations []durationOption
	}
	var hostAccessViews []hostAccessView
	for _, h := range knownHosts {
		info, active := activeMap[h]
		remaining := info.remaining
		// Build sudo summary for this specific host
		var rules []string
		seen := make(map[string]bool)
		for _, g := range userPerms[username] {
			if g.SudoCommands == "" {
				continue
			}
			sudoH := strings.TrimSpace(g.SudoHosts)
			applies := sudoH == "" || sudoH == "ALL"
			if !applies {
				for _, part := range strings.Split(sudoH, ",") {
					if strings.TrimSpace(part) == h {
						applies = true
						break
					}
				}
			}
			if !applies {
				continue
			}
			rule := g.SudoCommands
			if g.SudoRunAs != "" && g.SudoRunAs != "root" {
				rule += " as " + g.SudoRunAs
			}
			if !seen[rule] {
				seen[rule] = true
				rules = append(rules, rule)
			}
		}
		displayH := h
		if displayH == "(unknown)" {
			displayH = t("unknown_host")
		}
		hostAccessViews = append(hostAccessViews, hostAccessView{
			Hostname:        displayH,
			Active:          active,
			Remaining:       remaining,
			SudoSummary:     strings.Join(rules, "; "),
			ExtendDurations: extendDurationsFor(activeMap[h].remainingSec),
		})
	}
	// Sort alphabetically — user can filter to active-only via the UI toggle.
	sort.Slice(hostAccessViews, func(i, j int) bool {
		return hostAccessViews[i].Hostname < hostAccessViews[j].Hostname
	})

	hasActiveSessions := false
	for _, hav := range hostAccessViews {
		if hav.Active {
			hasActiveSessions = true
			break
		}
	}

	// Admin: build all-users active sessions view, with optional ?user= / ?host= filters.
	type allSessionView struct {
		Username        string
		Hostname        string
		Remaining       string
		ExtendDurations []durationOption
	}
	var allSessions []allSessionView
	filterUser := ""
	filterHost := ""
	if isAdmin {
		filterUser = r.URL.Query().Get("user")
		filterHost = r.URL.Query().Get("host")
		if filterUser != "" && !validUsername.MatchString(filterUser) {
			filterUser = ""
		}
		if filterHost != "" && !validHostname.MatchString(filterHost) {
			filterHost = ""
		}
		for _, sess := range s.store.AllActiveSessions() {
			if filterUser != "" && sess.Username != filterUser {
				continue
			}
			if filterHost != "" && sess.Hostname != filterHost {
				continue
			}
			remSec := int(time.Until(sess.ExpiresAt).Seconds())
			allSessions = append(allSessions, allSessionView{
				Username:        sess.Username,
				Hostname:        sess.Hostname,
				Remaining:       formatDuration(time.Until(sess.ExpiresAt)),
				ExtendDurations: extendDurationsFor(remSec),
			})
		}
		sort.Slice(allSessions, func(i, j int) bool {
			if allSessions[i].Hostname != allSessions[j].Hostname {
				return allSessions[i].Hostname < allSessions[j].Hostname
			}
			return allSessions[i].Username < allSessions[j].Username
		})
	}

	// Build elevate duration options filtered by GracePeriod.
	var elevateDurations []durationOption
	for _, d := range allDurations {
		if d.Value <= graceSec {
			elevateDurations = append(elevateDurations, d)
		}
	}
	if len(elevateDurations) == 0 {
		elevateDurations = []durationOption{{graceSec, formatDuration(s.cfg.GracePeriod)}}
	}

	// Read timezone from cookie for profile dropdown display
	dashTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err := time.LoadLocation(c.Value); err == nil {
			dashTZ = c.Value
		}
	}

	w.Header().Set("Content-Type", "text/html")
	if err := dashboardTmpl.Execute(w, map[string]interface{}{
		"Username":          username,
		"Initial":           strings.ToUpper(username[:1]),
		"Avatar":            getAvatar(r),
		"Timezone":          dashTZ,
		"Flashes":           flashes,
		"Pending":           pendingViews,
		"HostAccess":        hostAccessViews,
		"History":           dashHistory,
		"HasMoreHistory":    len(allHistoryWithUsers) > 5,
		"HasActiveSessions": hasActiveSessions,
		"CSRFToken":         csrfToken,
		"CSRFTs":            csrfTs,
		"ActivePage":        "sessions",
		"AllSessions":       allSessions,
		"FilterUser":        filterUser,
		"FilterHost":        filterHost,
		"Theme":             getTheme(r),
		"CSPNonce":          cspNonce(r),
		"T":                 T(lang),
		"Lang":              lang,
		"Languages":         supportedLanguages,
		"IsAdmin":           isAdmin,
		"AdminTab":          "",
		"BridgeMode":          s.isBridgeMode(),
		"DefaultPageSize":     s.cfg.DefaultPageSize,
		"Durations":           elevateDurations,
		"PocketIDUnavailable": pocketIDUnavailable,
	}); err != nil {
		slog.Error("template execution", "err", err)
	}
}

// handleSessionsRedirect redirects /sessions to the dashboard.
func (s *Server) handleSessionsRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
}

// handleAccess renders the /access page showing per-host sudo permissions
// and providing elevate/extend/revoke actions.
// Users see their own access; admins can select any user via ?user=X.
func (s *Server) handleAccess(w http.ResponseWriter, r *http.Request) {
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
	s.setSessionCookie(w, username, role)
	isAdmin := role == "admin"

	// Target user: admin can view any user, others view themselves.
	targetUser := username
	accessFilterUser := ""
	if isAdmin {
		if u := r.URL.Query().Get("user"); u != "" && validUsername.MatchString(u) {
			targetUser = u
			accessFilterUser = u
		}
	}

	// Build snapshot of recently-removed users to exclude from PocketID merge.
	s.removedUsersMu.Lock()
	for u, t := range s.removedUsers {
		if time.Since(t) > 10*time.Minute {
			delete(s.removedUsers, u)
		}
	}
	accessRemovedUsers := make(map[string]bool, len(s.removedUsers))
	for u := range s.removedUsers {
		accessRemovedUsers[u] = true
	}
	s.removedUsersMu.Unlock()

	// Build AllUsers list for admin dropdown.
	var allUsers []string
	if isAdmin {
		allUsers = s.store.AllUsers()
		if s.pocketIDClient != nil {
			if perms, err := s.pocketIDClient.GetUserPermissions(); err == nil {
				userSet := make(map[string]bool, len(allUsers))
				for _, u := range allUsers {
					userSet[u] = true
				}
				for u := range perms {
					if !userSet[u] && !accessRemovedUsers[u] {
						allUsers = append(allUsers, u)
					}
				}
				sort.Strings(allUsers)
			}
		}
		// Ensure targetUser appears in the list even if they have no history yet.
		found := false
		for _, u := range allUsers {
			if u == targetUser {
				found = true
				break
			}
		}
		if !found {
			allUsers = append(allUsers, targetUser)
			sort.Strings(allUsers)
		}
	}

	// Fetch group permissions from Pocket ID (cached).
	var userPerms map[string][]pocketid.GroupInfo
	if s.pocketIDClient != nil {
		if perms, err := s.pocketIDClient.GetUserPermissions(); err == nil {
			userPerms = perms
		}
	}

	// Build known host list for targetUser.
	// allHostsFn returns all registered/known hosts for ALL-access users.
	allHostsFn := func() []string {
		if s.hostRegistry.IsEnabled() {
			return s.hostRegistry.RegisteredHosts()
		}
		return s.store.AllKnownHosts()
	}
	knownHosts := s.store.KnownHosts(targetUser)
	hostSet := make(map[string]bool)
	for _, h := range knownHosts {
		hostSet[h] = true
	}
	hasAllHosts := false
	for _, g := range userPerms[targetUser] {
		sudoH := strings.TrimSpace(g.SudoHosts)
		if sudoH == "" || sudoH == "ALL" {
			hasAllHosts = true
			continue
		}
		for _, part := range strings.Split(sudoH, ",") {
			h := strings.TrimSpace(part)
			if h != "" && !hostSet[h] {
				hostSet[h] = true
				knownHosts = append(knownHosts, h)
			}
		}
	}
	if hasAllHosts {
		for _, h := range allHostsFn() {
			if !hostSet[h] {
				hostSet[h] = true
				knownHosts = append(knownHosts, h)
			}
		}
	}
	sort.Strings(knownHosts)

	// Active sessions for targetUser.
	activeMap := make(map[string]string)
	for _, sess := range s.store.ActiveSessions(targetUser) {
		activeMap[sess.Hostname] = formatDuration(time.Until(sess.ExpiresAt))
	}

	// Duration options for access page extend dropdowns.
	type durationOption struct {
		Value int
		Label string
	}
	accessAllDurations := []durationOption{
		{3600, "1h"},
		{7200, "2h"},
		{14400, "4h"},
		{28800, "8h"},
		{86400, "1d"},
	}
	accessGraceSec := int(s.cfg.GracePeriod.Seconds())
	if accessGraceSec <= 0 {
		accessGraceSec = 86400
	}
	accessExtendDurationsFor := func(remainingSec int) []durationOption {
		headroom := accessGraceSec - remainingSec
		var out []durationOption
		for _, d := range accessAllDurations {
			if d.Value <= headroom {
				out = append(out, d)
			}
		}
		return out
	}

	type accessView struct {
		Username        string
		Hostname        string
		Active          bool
		Remaining       string
		Commands        []string
		AllCmds         bool
		ExtendDurations []durationOption
	}

	type userAccessGroup struct {
		Username    string
		Hosts       []accessView
		ActiveCount int
	}

	// buildAccessViews builds the host access list for a single user.
	buildAccessViews := func(u string, hosts []string) []accessView {
		type uSessionInfo struct {
			remaining    string
			remainingSec int
		}
		uActiveMap := make(map[string]uSessionInfo)
		for _, sess := range s.store.ActiveSessions(u) {
			rem := time.Until(sess.ExpiresAt)
			uActiveMap[sess.Hostname] = uSessionInfo{formatDuration(rem), int(rem.Seconds())}
		}
		var views []accessView
		for _, h := range hosts {
			info, active := uActiveMap[h]
			remaining := info.remaining
			var cmds []string
			allCmds := false
			seen := make(map[string]bool)
			for _, g := range userPerms[u] {
				if g.SudoCommands == "" {
					continue
				}
				sudoH := strings.TrimSpace(g.SudoHosts)
				applies := sudoH == "" || sudoH == "ALL"
				if !applies {
					for _, part := range strings.Split(sudoH, ",") {
						if strings.TrimSpace(part) == h {
							applies = true
							break
						}
					}
				}
				if !applies {
					continue
				}
				if strings.TrimSpace(g.SudoCommands) == "ALL" {
					allCmds = true
					continue
				}
				for _, c := range strings.Split(g.SudoCommands, ",") {
					c = strings.TrimSpace(c)
					if c != "" && !seen[c] {
						seen[c] = true
						cmds = append(cmds, c)
					}
				}
			}
			displayH := h
			if displayH == "(unknown)" {
				displayH = t("unknown_host")
			}
			views = append(views, accessView{
				Username:        u,
				Hostname:        displayH,
				Active:          active,
				Remaining:       remaining,
				Commands:        cmds,
				AllCmds:         allCmds,
				ExtendDurations: accessExtendDurationsFor(uActiveMap[h].remainingSec),
			})
		}
		sort.Slice(views, func(i, j int) bool {
			return views[i].Hostname < views[j].Hostname
		})
		return views
	}

	// Per-user view for non-admins (or admin single-user view, unused now).
	accessViews := buildAccessViews(targetUser, knownHosts)

	// Admin combined view: one group per user, each with all their hosts.
	var allUserGroups []userAccessGroup
	if isAdmin {
		for _, u := range allUsers {
			uHosts := s.store.KnownHosts(u)
			uHostSet := make(map[string]bool)
			for _, h := range uHosts {
				uHostSet[h] = true
			}
			uHasAll := false
			for _, g := range userPerms[u] {
				sudoH := strings.TrimSpace(g.SudoHosts)
				if sudoH == "" || sudoH == "ALL" {
					uHasAll = true
					continue
				}
				for _, part := range strings.Split(sudoH, ",") {
					h := strings.TrimSpace(part)
					if h != "" && !uHostSet[h] {
						uHostSet[h] = true
						uHosts = append(uHosts, h)
					}
				}
			}
			if uHasAll {
				for _, h := range allHostsFn() {
					if !uHostSet[h] {
						uHostSet[h] = true
						uHosts = append(uHosts, h)
					}
				}
			}
			sort.Strings(uHosts)
			views := buildAccessViews(u, uHosts)
			activeCount := 0
			for _, v := range views {
				if v.Active {
					activeCount++
				}
			}
			allUserGroups = append(allUserGroups, userAccessGroup{
				Username:    u,
				Hosts:       views,
				ActiveCount: activeCount,
			})
		}
	}

	csrfTs := strconv.FormatInt(time.Now().Unix(), 10)
	csrfToken := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)

	// Elevate duration options clamped to GracePeriod.
	var elevateDurations []durationOption
	for _, d := range accessAllDurations {
		if d.Value <= accessGraceSec {
			elevateDurations = append(elevateDurations, d)
		}
	}
	if len(elevateDurations) == 0 {
		elevateDurations = []durationOption{{accessGraceSec, formatDuration(s.cfg.GracePeriod)}}
	}

	dashTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err := time.LoadLocation(c.Value); err == nil {
			dashTZ = c.Value
		}
	}

	w.Header().Set("Content-Type", "text/html")
	if err := accessTmpl.Execute(w, map[string]interface{}{
		"Username":   username,
		"Initial":    strings.ToUpper(username[:1]),
		"Avatar":     getAvatar(r),
		"Timezone":   dashTZ,
		"TargetUser":      targetUser,
		"AllUsers":        allUsers,
		"HostAccess":      accessViews,
		"AllUserGroups":   allUserGroups,
		"CSRFToken":  csrfToken,
		"CSRFTs":     csrfTs,
		"ActivePage": "access",
		"Theme":      getTheme(r),
		"CSPNonce":   cspNonce(r),
		"T":          T(lang),
		"Lang":       lang,
		"Languages":  supportedLanguages,
		"IsAdmin":    isAdmin,
		"AdminTab":        "",
		"BridgeMode":      s.isBridgeMode(),
		"DefaultPageSize": s.cfg.DefaultPageSize,
		"Durations":       elevateDurations,
		"FilterUser":      accessFilterUser,
		"Pending":         s.buildPendingViews(username, lang),
	}); err != nil {
		slog.Error("template execution", "err", err)
	}
}

// handleApprovalPage validates the code and redirects to OIDC login.
// After OIDC, the user lands on the dashboard where they can approve or reject.
// GET /approve/{user_code}
func (s *Server) handleApprovalPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := strings.TrimPrefix(r.URL.Path, "/approve/")
	if code == "" {
		http.Error(w, "code required", http.StatusBadRequest)
		return
	}

	// Validate user code format to prevent injection (e.g., ABCDEF-123456)
	if len(code) != 13 || code[6] != '-' {
		http.Error(w, "invalid code format", http.StatusBadRequest)
		return
	}

	slog.Info("ACCESS", "path", "/approve/", "remote_addr", remoteAddr(r), "code_prefix", code[:6])

	challenge, ok := s.store.GetByCode(code)
	if !ok {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		lang := detectLanguage(r)
		if err := approvalExpiredTmpl.Execute(w, map[string]interface{}{
			"Theme": getTheme(r),
			"Lang":  lang,
			"T":     T(lang),
		}); err != nil {
			slog.Error("template execution", "err", err)
		}
		return
	}

	if challenge.Status != challpkg.StatusPending {
		w.Header().Set("Content-Type", "text/html")
		lang := detectLanguage(r)
		t := T(lang)
		if err := approvalAlreadyTmpl.Execute(w, map[string]interface{}{
			"Status": t(string(challenge.Status)),
			"Theme":  getTheme(r),
			"Lang":   lang,
			"T":      t,
		}); err != nil {
			slog.Error("template execution", "err", err)
		}
		return
	}

	// Redirect to OIDC login — after authentication the user lands on the
	// dashboard where they can explicitly approve or reject the pending challenge.
	loginURL := s.baseURL + "/sessions/login"
	http.Redirect(w, r, loginURL, http.StatusSeeOther)
}

// revokeErrorPage renders a styled error page for revoke failures.
// titleKey and messageKey are i18n translation keys.
func revokeErrorPage(w http.ResponseWriter, r *http.Request, status int, titleKey, messageKey string) {
	lang := detectLanguage(r)
	t := T(lang)
	theme := getTheme(r)
	title := t(titleKey)
	message := t(messageKey)
	themeClass := ""
	if theme == "dark" {
		themeClass = ` class="theme-dark"`
	} else if theme == "light" {
		themeClass = ` class="theme-light"`
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	io.WriteString(w, `<!DOCTYPE html>
<html lang="`+lang+`"`+themeClass+`>
<head>
  <title>`+template.HTMLEscapeString(title)+`</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>`+sharedCSS+`
    .icon-warning { background: var(--warning-bg); border: 2px solid var(--warning-border); color: var(--warning); }
    h2 { color: var(--warning); }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon icon-warning" aria-hidden="true">&#x26a0;</div>
    <h2>`+template.HTMLEscapeString(title)+`</h2>
    <p>`+template.HTMLEscapeString(message)+`</p>
    <p style="margin-top:16px"><a href="/" style="color:var(--primary);text-decoration:underline">`+template.HTMLEscapeString(t("back_to_dashboard"))+`</a></p>
  </div>
</body>
</html>`)
}

// revokeErrorPageWithLink renders a styled error page with an optional action link.
// titleKey, messageKey, and linkTextKey are i18n translation keys.
func revokeErrorPageWithLink(w http.ResponseWriter, r *http.Request, status int, titleKey, messageKey, linkURL, linkTextKey string) {
	lang := detectLanguage(r)
	t := T(lang)
	theme := getTheme(r)
	title := t(titleKey)
	message := t(messageKey)
	linkText := t(linkTextKey)
	themeClass := ""
	if theme == "dark" {
		themeClass = ` class="theme-dark"`
	} else if theme == "light" {
		themeClass = ` class="theme-light"`
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	linkHTML := ""
	if linkURL != "" && linkText != "" {
		linkHTML = `<p style="margin-top:16px"><a href="` + template.HTMLEscapeString(linkURL) + `" style="color:var(--primary);text-decoration:underline;font-weight:600">` + template.HTMLEscapeString(linkText) + `</a></p>`
	}
	io.WriteString(w, `<!DOCTYPE html>
<html lang="`+lang+`"`+themeClass+`>
<head>
  <title>`+template.HTMLEscapeString(title)+`</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>`+sharedCSS+`
    .icon-warning { background: var(--warning-bg); border: 2px solid var(--warning-border); color: var(--warning); }
    h2 { color: var(--warning); }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon icon-warning" aria-hidden="true">&#x26a0;</div>
    <h2>`+template.HTMLEscapeString(title)+`</h2>
    <p>`+template.HTMLEscapeString(message)+`</p>`+linkHTML+`
    <p style="margin-top:16px"><a href="/" style="color:var(--primary);text-decoration:underline">`+template.HTMLEscapeString(t("back_to_dashboard"))+`</a></p>
  </div>
</body>
</html>`)
}

// handleHistoryPage renders the full action history with search and filter.
// GET /history
func (s *Server) handleHistoryPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Handle language change via query param
	if setLanguageCookie(w, r) {
		return
	}
	lang := detectLanguage(r)

	username := s.getSessionUser(r)
	if username == "" {
		s.setFlashCookie(w, "expired:")
		http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
		return
	}
	role := s.getSessionRole(r)
	s.setSessionCookie(w, username, role)
	isAdmin := role == "admin"

	// Timezone handling: set cookie if tz param provided, then read from cookie
	tzName := "UTC"
	if tzParam := r.URL.Query().Get("tz"); tzParam != "" {
		if loc, err := time.LoadLocation(tzParam); err == nil {
			_ = loc
			tzName = tzParam
			http.SetCookie(w, &http.Cookie{
				Name:     "pam_tz",
				Value:    tzParam,
				Path:     "/",
				MaxAge:   86400,
				HttpOnly: false, // must be readable by JS for auto-detection
				SameSite: http.SameSiteLaxMode,
			})
		}
	} else if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if loc, err := time.LoadLocation(c.Value); err == nil {
			_ = loc
			tzName = c.Value
		}
	}
	tzLoc, _ := time.LoadLocation(tzName)

	query := r.URL.Query().Get("q")
	actionFilter := r.URL.Query().Get("action")
	hostFilter := r.URL.Query().Get("hostname")
	userFilter := ""
	if isAdmin {
		userFilter = r.URL.Query().Get("user")
	}

	// Parse sort and order params
	sortField := r.URL.Query().Get("sort")
	validSort := map[string]bool{"timestamp": true, "action": true, "hostname": true, "code": true}
	if isAdmin {
		validSort["user"] = true
	}
	if !validSort[sortField] {
		sortField = "timestamp"
	}
	sortOrder := r.URL.Query().Get("order")
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "desc"
	}

	page := 1
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 0 {
		page = p
	}

	// Parse per_page with validation
	perPage := s.cfg.DefaultPageSize
	if pp, err := strconv.Atoi(r.URL.Query().Get("per_page")); err == nil {
		validSizes := map[int]bool{15: true, 30: true, 50: true, 100: true}
		if validSizes[pp] {
			perPage = pp
		}
	}

	// Admins see all users' history; others see only their own.
	var allHistory []challpkg.ActionLogEntryWithUser
	if isAdmin {
		allHistory = s.store.AllActionHistoryWithUsers()
	} else {
		for _, e := range s.store.ActionHistory(username, 0) {
			if e.Action == "rotated_breakglass" {
				continue // server-level event; not shown to non-admins
			}
			allHistory = append(allHistory, challpkg.ActionLogEntryWithUser{
				Username:  username,
				Actor:     e.Actor,
				Timestamp: e.Timestamp,
				Action:    e.Action,
				Hostname:  e.Hostname,
				Code:      e.Code,
			})
		}
	}

	// Collect unique action types, hostnames, and (for admins) users from FULL unfiltered history
	actionSet := make(map[string]bool)
	hostSet := make(map[string]bool)
	userSet := make(map[string]bool)
	for _, e := range allHistory {
		actionSet[e.Action] = true
		if e.Hostname != "" {
			hostSet[e.Hostname] = true
		}
		if isAdmin && e.Username != "" {
			userSet[e.Username] = true
		}
	}

	// Build ActionOptions
	t := T(lang)
	var actionOptions []ActionOption
	actionOrder := []string{"approved", "auto_approved", "rejected", "revoked", "elevated", "extended", "rotated_breakglass"}
	for _, a := range actionOrder {
		if actionSet[a] {
			actionOptions = append(actionOptions, ActionOption{Value: a, Label: t(a)})
		}
	}
	// Include any action types not in the predefined order
	for a := range actionSet {
		found := false
		for _, known := range actionOrder {
			if a == known {
				found = true
				break
			}
		}
		if !found {
			actionOptions = append(actionOptions, ActionOption{Value: a, Label: t(a)})
		}
	}

	// Build sorted HostOptions
	var hostOptions []string
	for h := range hostSet {
		hostOptions = append(hostOptions, h)
	}
	sort.Strings(hostOptions)

	// Build sorted UserOptions (admin only)
	var userOptions []string
	for u := range userSet {
		userOptions = append(userOptions, u)
	}
	sort.Strings(userOptions)

	// Build 24-hour activity timeline from the full unfiltered history.
	// This always shows the complete 24h view so users can see the overall pattern.
	nowInTZ := time.Now().In(tzLoc)
	var timeline []timelineEntry
	activeHoursAgo := -1 // which bar is currently active (-1 = none)
	for i := 23; i >= 0; i-- {
		hourInTZ := nowInTZ.Add(-time.Duration(i+1) * time.Hour)
		hourStart := hourInTZ.Truncate(time.Hour)
		hourEnd := hourStart.Add(time.Hour)
		hoursAgo := i // bar at i=0 is the current (most recent) hour

		count := 0
		type timelineEvent struct{ hostname, username string }
		actionEvents := make(map[string][]timelineEvent) // action -> events
		for _, e := range allHistory {
			if e.Timestamp.After(hourStart) && e.Timestamp.Before(hourEnd) {
				count++
				actionEvents[e.Action] = append(actionEvents[e.Action], timelineEvent{e.Hostname, e.Username})
			}
		}

		// Build rich tooltip text
		var detailParts []string
		detailParts = append(detailParts, fmt.Sprintf("%d:00 – %d:00", hourStart.Hour(), hourEnd.Hour()))
		// Sort action keys for deterministic ordering
		var actionKeys []string
		for a := range actionEvents {
			actionKeys = append(actionKeys, a)
		}
		sort.Strings(actionKeys)
		for _, action := range actionKeys {
			events := actionEvents[action]
			var parts []string
			seen := make(map[string]bool)
			for _, ev := range events {
				var key string
				if isAdmin && ev.username != "" {
					if ev.hostname != "" {
						key = ev.username + ": " + ev.hostname
					} else {
						key = ev.username
					}
				} else if ev.hostname != "" {
					key = ev.hostname
				}
				if key != "" && !seen[key] {
					seen[key] = true
					parts = append(parts, key)
				}
			}
			sort.Strings(parts)
			if len(parts) > 0 {
				detailParts = append(detailParts, fmt.Sprintf("%d %s (%s)", len(events), t(action), strings.Join(parts, ", ")))
			} else {
				detailParts = append(detailParts, fmt.Sprintf("%d %s", len(events), t(action)))
			}
		}

		height := 2
		if count > 0 {
			height = count * 8
			if height > 40 {
				height = 40
			}
		}
		timeline = append(timeline, timelineEntry{
			Hour:         hourStart.Hour(),
			HourLabel:    fmt.Sprintf("%d:00", hourStart.Hour()),
			Count:        count,
			Height:       height,
			IsNow:        i == 0,
			HoursAgo:     hoursAgo,
			Details:      strings.Join(detailParts, "\n"),
			HourStartISO: hourStart.Format("2006-01-02T15:04"),
			HourEndISO:   hourEnd.Format("2006-01-02T15:04"),
		})
	}

	// Parse from/to datetime filter (datetime-local format in user's timezone).
	const dtLocalFmt = "2006-01-02T15:04"
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	var filterFrom, filterTo time.Time
	if fromStr != "" {
		if t, err := time.ParseInLocation(dtLocalFmt, fromStr, tzLoc); err == nil {
			filterFrom = t
		} else {
			fromStr = ""
		}
	}
	if toStr != "" {
		if t, err := time.ParseInLocation(dtLocalFmt, toStr, tzLoc); err == nil {
			filterTo = t
		} else {
			toStr = ""
		}
	}
	// Backwards compat: support legacy hours_ago for timeline bar links.
	if fromStr == "" && toStr == "" {
		hoursAgoStr := r.URL.Query().Get("hours_ago")
		if hoursAgoStr != "" {
			if h, err := strconv.Atoi(hoursAgoStr); err == nil && h >= 0 && h < 24 {
				activeHoursAgo = h
				hourStart := nowInTZ.Add(-time.Duration(h+1) * time.Hour).Truncate(time.Hour)
				hourEnd := hourStart.Add(time.Hour)
				filterFrom = hourStart
				filterTo = hourEnd
				fromStr = hourStart.Format(dtLocalFmt)
				toStr = hourEnd.Format(dtLocalFmt)
			}
		}
	}
	if !filterFrom.IsZero() || !filterTo.IsZero() {
		var filtered []challpkg.ActionLogEntryWithUser
		for _, e := range allHistory {
			ts := e.Timestamp
			if !filterFrom.IsZero() && ts.Before(filterFrom) {
				continue
			}
			if !filterTo.IsZero() && ts.After(filterTo) {
				continue
			}
			filtered = append(filtered, e)
		}
		allHistory = filtered
	}

	history := allHistory

	// Filter by user (admin only)
	if isAdmin && userFilter != "" {
		var filtered []challpkg.ActionLogEntryWithUser
		for _, e := range history {
			if e.Username == userFilter {
				filtered = append(filtered, e)
			}
		}
		history = filtered
	}

	// Filter by action type
	if actionFilter != "" {
		var filtered []challpkg.ActionLogEntryWithUser
		for _, e := range history {
			if e.Action == actionFilter {
				filtered = append(filtered, e)
			}
		}
		history = filtered
	}

	// Filter by hostname
	if hostFilter != "" {
		var filtered []challpkg.ActionLogEntryWithUser
		for _, e := range history {
			if e.Hostname == hostFilter {
				filtered = append(filtered, e)
			}
		}
		history = filtered
	}

	// Filter by search term (case-insensitive match on hostname, code, or username for admins)
	if query != "" {
		q := strings.ToLower(query)
		var filtered []challpkg.ActionLogEntryWithUser
		for _, e := range history {
			if strings.Contains(strings.ToLower(e.Hostname), q) ||
				strings.Contains(strings.ToLower(e.Code), q) ||
				(isAdmin && strings.Contains(strings.ToLower(e.Username), q)) {
				filtered = append(filtered, e)
			}
		}
		history = filtered
	}

	// Sort results
	asc := sortOrder == "asc"
	sort.SliceStable(history, func(i, j int) bool {
		switch sortField {
		case "action":
			if asc {
				return history[i].Action < history[j].Action
			}
			return history[i].Action > history[j].Action
		case "hostname":
			if asc {
				return history[i].Hostname < history[j].Hostname
			}
			return history[i].Hostname > history[j].Hostname
		case "code":
			if asc {
				return history[i].Code < history[j].Code
			}
			return history[i].Code > history[j].Code
		case "user":
			if asc {
				return history[i].Username < history[j].Username
			}
			return history[i].Username > history[j].Username
		default: // timestamp
			if asc {
				return history[i].Timestamp.Before(history[j].Timestamp)
			}
			return history[i].Timestamp.After(history[j].Timestamp)
		}
	})

	// Paginate
	totalPages := (len(history) + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}
	start := (page - 1) * perPage
	end := start + perPage
	if end > len(history) {
		end = len(history)
	}
	pageHistory := history[start:end]

	// Pre-format entries with timezone
	var viewEntries []historyViewEntry
	for _, e := range pageHistory {
		viewEntries = append(viewEntries, historyViewEntry{
			Action:        e.Action,
			ActionLabel:   t(e.Action),
			Hostname:      e.Hostname,
			Code:          e.Code,
			Actor:         e.Actor,
			Username:      e.Username,
			FormattedTime: e.Timestamp.In(tzLoc).Format("2006-01-02 15:04"),
			TimeAgo:       timeAgoI18n(e.Timestamp, t),
		})
	}

	perPageOptions := []int{15, 30, 50, 100}

	historyCSRFTs := strconv.FormatInt(time.Now().Unix(), 10)
	historyCSRFToken := computeCSRFToken(s.cfg.SharedSecret, username, historyCSRFTs)

	w.Header().Set("Content-Type", "text/html")
	if err := historyTmpl.Execute(w, map[string]interface{}{
		"Username":        username,
		"Initial":         strings.ToUpper(username[:1]),
		"Avatar":          getAvatar(r),
		"History":         viewEntries,
		"Query":           query,
		"ActionFilter":    actionFilter,
		"HostFilter":      hostFilter,
		"UserFilter":      userFilter,
		"ActionOptions":   actionOptions,
		"HostOptions":     hostOptions,
		"UserOptions":     userOptions,
		"ActivePage":      "history",
		"Theme":           getTheme(r),
		"Page":            page,
		"TotalPages":      totalPages,
		"HasPrev":         page > 1,
		"HasNext":         page < totalPages,
		"Sort":            sortField,
		"Order":           sortOrder,
		"PerPage":         perPage,
		"PerPageOptions":  perPageOptions,
		"TZName":          tzName,
		"Timezone":        tzName,
		"CSPNonce":        cspNonce(r),
		"T":               T(lang),
		"Lang":            lang,
		"Languages":       supportedLanguages,
		"Timeline":        timeline,
		"ActiveHoursAgo":  activeHoursAgo,
		"FilterFrom":      fromStr,
		"FilterTo":        toStr,
		"IsAdmin":         isAdmin,
		"AdminTab":        "",
		"BridgeMode":      s.isBridgeMode(),
		"DefaultPageSize": s.cfg.DefaultPageSize,
		"CSRFToken":       historyCSRFToken,
		"CSRFTs":          historyCSRFTs,
		"Pending":         s.buildPendingViews(username, lang),
	}); err != nil {
		slog.Error("template execution", "err", err)
	}
}

// handleHistoryExport exports action history as CSV or JSON.
// Session-authenticated users see their own history.
// API key callers (Authorization: Bearer <key>) see all users' combined history.
// GET /api/history/export?format=csv|json
func (s *Server) handleHistoryExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := s.getSessionUser(r)
	apiKeyAccess := false
	if username == "" {
		if !s.verifyAPIKey(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// API key access — export ALL users' history (admin-level)
		apiKeyAccess = true
	}

	format := r.URL.Query().Get("format")

	if apiKeyAccess {
		// Return all-users history with username field included.
		allHistory := s.store.AllActionHistoryWithUsers()
		switch format {
		case "csv":
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", "attachment; filename=identree-history.csv")
			cw := csv.NewWriter(w)
			cw.Write([]string{"username", "timestamp", "action", "hostname", "code", "actor"})
			for _, e := range allHistory {
				cw.Write([]string{e.Username, e.Timestamp.Format(time.RFC3339), string(e.Action), e.Hostname, e.Code, e.Actor})
			}
			cw.Flush()
		case "json":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", "attachment; filename=identree-history.json")
			json.NewEncoder(w).Encode(allHistory)
		default:
			http.Error(w, "format must be csv or json", http.StatusBadRequest)
		}
		return
	}

	// Session-based access: export the authenticated user's own history.
	history := s.store.ActionHistory(username, 0)
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=identree-history.csv")
		cw := csv.NewWriter(w)
		cw.Write([]string{"timestamp", "action", "hostname", "code", "actor"})
		for _, e := range history {
			cw.Write([]string{e.Timestamp.Format(time.RFC3339), string(e.Action), e.Hostname, e.Code, e.Actor})
		}
		cw.Flush()
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=identree-history.json")
		json.NewEncoder(w).Encode(history)
	default:
		http.Error(w, "format must be csv or json", http.StatusBadRequest)
	}
}
