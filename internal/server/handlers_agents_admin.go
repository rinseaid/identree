package server

import (
	"log/slog"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// agentRow is the per-row view-model used by the agents tab template.
type agentRow struct {
	Hostname      string
	Version       string
	OSInfo        string
	IP            string
	FirstSeenISO  string
	LastSeenISO   string
	FirstSeenAgo  string
	LastSeenAgo   string
	Status        string // "green" / "amber" / "red"
}

// handleAdminAgents renders /admin/agents — the live fleet view of every
// host that has ever sent an agent heartbeat.
func (s *Server) handleAdminAgents(w http.ResponseWriter, r *http.Request) {
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

	adminTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err := time.LoadLocation(c.Value); err == nil {
			adminTZ = c.Value
		}
	}

	csrfTs := strconv.FormatInt(time.Now().Unix(), 10)
	csrfToken := computeCSRFToken(s.hmacBase(), username, csrfTs)

	now := time.Now()
	rows := []agentRow{}
	for _, a := range s.store.ListAgents() {
		rows = append(rows, agentRow{
			Hostname:     a.Hostname,
			Version:      a.Version,
			OSInfo:       a.OSInfo,
			IP:           a.IP,
			FirstSeenISO: a.FirstSeen.UTC().Format(time.RFC3339),
			LastSeenISO:  a.LastSeen.UTC().Format(time.RFC3339),
			FirstSeenAgo: formatAgo(now.Sub(a.FirstSeen)),
			LastSeenAgo:  formatAgo(now.Sub(a.LastSeen)),
			Status:       agentStatus(now, a.LastSeen),
		})
	}

	w.Header().Set("Content-Type", "text/html")
	if err := adminTmpl.Execute(w, map[string]interface{}{
		"Username":             username,
		"Initial":              strings.ToUpper(username[:1]),
		"Avatar":               getAvatar(r),
		"Timezone":             adminTZ,
		"Flashes":              []string(nil),
		"FlashErrors":          []string(nil),
		"ActivePage":           "admin",
		"AdminTab":             "agents",
		"BridgeMode":           s.isBridgeMode(),
		"DefaultPageSize":      s.cfg.DefaultPageSize,
		"Theme":                getTheme(r),
		"CSPNonce":             cspNonce(r),
		"T":                    t,
		"Lang":                 lang,
		"Languages":            supportedLanguages,
		"IsAdmin":              true,
		"CSRFToken":            csrfToken,
		"CSRFTs":               csrfTs,
		"Pending":              s.buildAllPendingViews(username, lang),
		"AllPendingQueue":      s.buildAllPendingViews(username, lang),
		"JustificationChoices": func() []string { c, _ := s.justificationTemplateData(); return c }(),
		"RequireJustification": func() bool { _, r := s.justificationTemplateData(); return r }(),
		"Agents":               rows,
		// Required by the shared admin template even if unused on this tab.
		"Version":              version,
		"CommitShort":          commitShort(commit),
		"Commit":               commit,
		"Uptime":               formatDuration(t, time.Since(serverStartTime)),
		"GoVersion":            runtime.Version(),
		"OSArch":               runtime.GOOS + "/" + runtime.GOARCH,
		"Goroutines":           runtime.NumGoroutine(),
		"MemUsage":             "",
		"ActiveSessionsCount":  len(s.store.AllActiveSessions()),
		"ActiveChallengeCount": len(s.store.AllPendingChallenges()),
	}); err != nil {
		slog.Error("template execution", "err", err)
	}
}
