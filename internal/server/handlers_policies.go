package server

import (
	"log/slog"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rinseaid/identree/internal/policy"
)

// policyNameRe validates policy names.
var policyNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// handleAdminPolicies renders the approval policies management page.
// GET /admin/policies
func (s *Server) handleAdminPolicies(w http.ResponseWriter, r *http.Request) {
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
	if role != "admin" {
		http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
		return
	}

	var flashes []string
	var flashErrors []string
	if flashParam := s.getAndClearFlash(w, r); flashParam != "" {
		for _, f := range strings.Split(flashParam, ",") {
			parts := strings.SplitN(f, ":", 2)
			if len(parts) != 2 {
				continue
			}
			switch parts[0] {
			case "policy_added":
				flashes = append(flashes, "Policy added: "+parts[1])
			case "policy_deleted":
				flashes = append(flashes, "Policy deleted: "+parts[1])
			case "policy_error":
				flashErrors = append(flashErrors, parts[1])
			}
		}
	}

	now := time.Now()
	csrfTs := strconv.FormatInt(now.Unix(), 10)
	csrfToken := computeCSRFToken(s.hmacBase(), username, csrfTs)

	adminTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, tzErr := time.LoadLocation(c.Value); tzErr == nil {
			adminTZ = c.Value
		}
	}

	s.policyCfgMu.RLock()
	policies := s.policyEngine.Policies()
	s.policyCfgMu.RUnlock()

	// Get notification channel names for the dropdown.
	var channelNames []string
	s.notifyCfgMu.RLock()
	for _, ch := range s.notifyCfg.Channels {
		channelNames = append(channelNames, ch.Name)
	}
	s.notifyCfgMu.RUnlock()

	// Get host groups from registry.
	var hostGroups []string
	seen := make(map[string]bool)
	for _, h := range s.hostRegistry.RegisteredHosts() {
		_, group, _, ok := s.hostRegistry.GetHost(h)
		if ok && group != "" && !seen[group] {
			hostGroups = append(hostGroups, group)
			seen[group] = true
		}
	}

	w.Header().Set("Content-Type", "text/html")
	if err := adminTmpl.Execute(w, map[string]interface{}{
		"Username":             username,
		"Initial":              strings.ToUpper(username[:1]),
		"Avatar":               getAvatar(r),
		"Timezone":             adminTZ,
		"Flashes":              flashes,
		"FlashErrors":          flashErrors,
		"ActivePage":           "admin",
		"AdminTab":             "policies",
		"BridgeMode":           s.isBridgeMode(),
		"Theme":                getTheme(r),
		"CSPNonce":             cspNonce(r),
		"T":                    t,
		"Lang":                 lang,
		"Languages":            supportedLanguages,
		"IsAdmin":              true,
		"Policies":             policies,
		"HostGroups":           hostGroups,
		"ChannelNames":         channelNames,
		"Pending":              s.buildAllPendingViews(lang),
		"JustificationChoices": func() []string { c, _ := s.justificationTemplateData(); return c }(),
		"RequireJustification": func() bool { _, r := s.justificationTemplateData(); return r }(),
		"CSRFToken":            csrfToken,
		"CSRFTs":               csrfTs,
	}); err != nil {
		slog.Error("template execution", "err", err)
	}
}

// handlePolicyAdd adds a new approval policy.
// POST /api/policies/add
func (s *Server) handlePolicyAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminUser := s.verifyFormAuth(w, r)
	if adminUser == "" {
		return
	}
	if s.getSessionRole(r) != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if !policyNameRe.MatchString(name) {
		s.setFlashCookie(w, "policy_error:invalid policy name (lowercase alphanumeric, hyphens, dots)")
		http.Redirect(w, r, s.baseURL+"/admin/policies", http.StatusSeeOther)
		return
	}

	// Validate host patterns.
	matchHosts := splitTrimmed(r.FormValue("match_hosts"))
	for _, p := range matchHosts {
		if _, err := filepath.Match(p, ""); err != nil {
			s.setFlashCookie(w, "policy_error:invalid glob pattern: "+p)
			http.Redirect(w, r, s.baseURL+"/admin/policies", http.StatusSeeOther)
			return
		}
	}

	matchUsers := splitTrimmed(r.FormValue("match_users"))
	for _, p := range matchUsers {
		if _, err := filepath.Match(p, ""); err != nil {
			s.setFlashCookie(w, "policy_error:invalid user glob pattern: "+p)
			http.Redirect(w, r, s.baseURL+"/admin/policies", http.StatusSeeOther)
			return
		}
	}

	minApprovals := 1
	if v := r.FormValue("min_approvals"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			minApprovals = n
		}
	}

	p := policy.Policy{
		Name:             name,
		MatchHostGroups:  splitTrimmed(r.FormValue("match_host_groups")),
		MatchHosts:       matchHosts,
		MatchUsers:       matchUsers,
		RequireAdmin:     r.FormValue("require_admin") == "on" || r.FormValue("require_admin") == "true",
		MinApprovals:     minApprovals,
		AutoApproveGrace: r.FormValue("auto_approve_grace") == "on" || r.FormValue("auto_approve_grace") == "true",
		AllowedHours:     strings.TrimSpace(r.FormValue("allowed_hours")),
		AllowedDays:      strings.TrimSpace(r.FormValue("allowed_days")),
		NotifyChannels:   splitTrimmed(r.FormValue("notify_channels")),
	}

	// Check for duplicate name.
	s.policyCfgMu.RLock()
	existing := s.policyEngine.Policies()
	s.policyCfgMu.RUnlock()
	for _, ep := range existing {
		if ep.Name == name {
			s.setFlashCookie(w, "policy_error:policy name already exists: "+name)
			http.Redirect(w, r, s.baseURL+"/admin/policies", http.StatusSeeOther)
			return
		}
	}

	existing = append(existing, p)

	s.cfgMu.RLock()
	path := s.cfg.ApprovalPoliciesFile
	s.cfgMu.RUnlock()

	if err := policy.SavePolicies(path, existing); err != nil {
		slog.Error("policy: save failed", "err", err)
		s.setFlashCookie(w, "policy_error:failed to save policies")
		http.Redirect(w, r, s.baseURL+"/admin/policies", http.StatusSeeOther)
		return
	}

	s.policyCfgMu.Lock()
	s.policyEngine = policy.NewEngine(existing)
	s.policyCfgMu.Unlock()

	slog.Info("POLICY_ADDED", "name", name, "actor", adminUser)
	s.emitAuditEvent("config_changed", adminUser, "", "", "policy_added", name, "")

	s.setFlashCookie(w, "policy_added:"+name)
	http.Redirect(w, r, s.baseURL+"/admin/policies", http.StatusSeeOther)
}

// handlePolicyDelete deletes an approval policy by name.
// POST /api/policies/delete
func (s *Server) handlePolicyDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminUser := s.verifyFormAuth(w, r)
	if adminUser == "" {
		return
	}
	if s.getSessionRole(r) != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		s.setFlashCookie(w, "policy_error:missing policy name")
		http.Redirect(w, r, s.baseURL+"/admin/policies", http.StatusSeeOther)
		return
	}

	s.policyCfgMu.RLock()
	existing := s.policyEngine.Policies()
	s.policyCfgMu.RUnlock()

	var updated []policy.Policy
	found := false
	for _, p := range existing {
		if p.Name == name {
			found = true
			continue
		}
		updated = append(updated, p)
	}
	if !found {
		s.setFlashCookie(w, "policy_error:policy not found: "+name)
		http.Redirect(w, r, s.baseURL+"/admin/policies", http.StatusSeeOther)
		return
	}

	s.cfgMu.RLock()
	path := s.cfg.ApprovalPoliciesFile
	s.cfgMu.RUnlock()

	if err := policy.SavePolicies(path, updated); err != nil {
		slog.Error("policy: save failed", "err", err)
		s.setFlashCookie(w, "policy_error:failed to save policies")
		http.Redirect(w, r, s.baseURL+"/admin/policies", http.StatusSeeOther)
		return
	}

	s.policyCfgMu.Lock()
	s.policyEngine = policy.NewEngine(updated)
	s.policyCfgMu.Unlock()

	slog.Info("POLICY_DELETED", "name", name, "actor", adminUser)
	s.emitAuditEvent("config_changed", adminUser, "", "", "policy_deleted", name, "")

	s.setFlashCookie(w, "policy_deleted:"+name)
	http.Redirect(w, r, s.baseURL+"/admin/policies", http.StatusSeeOther)
}

// splitTrimmed is defined in handlers_notify.go.
