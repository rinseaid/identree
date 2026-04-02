package server

import (
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/sudorules"
)

// posixGroupName mirrors the validation in the ldap package: lowercase, no
// uppercase, starts with a letter or underscore, max 256 chars.
var posixGroupName = regexp.MustCompile(`^[a-z_][a-z0-9_.-]*$`)

// maxSudoFieldLen is the maximum byte length for a single sudo rule field
// (hosts, commands, run_as_user, run_as_group, options). The entire request
// body is already limited by verifyFormAuth's MaxBytesReader, but per-field
// caps provide defence-in-depth and clearer error messages.
const maxSudoFieldLen = 4096

// validateSudoRuleFields checks that the free-form fields of a sudo rule do
// not exceed maxSudoFieldLen and do not contain ASCII control characters
// (null bytes, newlines, carriage returns) that could cause issues in stored
// JSON or downstream LDAP attribute values.
func validateSudoRuleFields(rule sudorules.SudoRule) bool {
	for _, f := range []string{rule.Hosts, rule.Commands, rule.RunAsUser, rule.RunAsGroup, rule.Options} {
		if len(f) > maxSudoFieldLen {
			return false
		}
		if strings.ContainsAny(f, "\x00\n\r") {
			return false
		}
	}
	return true
}

// handleAdminSudoRules renders the sudo rules admin tab (bridge mode only).
// GET /admin/sudo-rules
func (s *Server) handleAdminSudoRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isBridgeMode() {
		http.Redirect(w, r, s.baseURL+"/admin/users", http.StatusSeeOther)
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

	// Parse flash messages
	var flashes []string
	if flashParam := s.getAndClearFlash(w, r); flashParam != "" {
		for _, f := range strings.Split(flashParam, ",") {
			parts := strings.SplitN(f, ":", 2)
			if len(parts) != 2 {
				continue
			}
			switch parts[0] {
			case "sudo_added":
				flashes = append(flashes, t("sudo_rules_added")+": "+parts[1])
			case "sudo_updated":
				flashes = append(flashes, t("sudo_rules_updated")+": "+parts[1])
			case "sudo_deleted":
				flashes = append(flashes, t("sudo_rules_deleted")+": "+parts[1])
			}
		}
	}

	now := time.Now()
	csrfTs := strconv.FormatInt(now.Unix(), 10)
	csrfToken := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)

	adminTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, tzErr := time.LoadLocation(c.Value); tzErr == nil {
			adminTZ = c.Value
		}
	}

	w.Header().Set("Content-Type", "text/html")
	if err := adminTmpl.Execute(w, map[string]interface{}{
		"Username":   username,
		"Initial":    strings.ToUpper(username[:1]),
		"Avatar":     getAvatar(r),
		"Timezone":   adminTZ,
		"Flashes":    flashes,
		"ActivePage": "admin",
		"AdminTab":   "sudo-rules",
		"BridgeMode": s.isBridgeMode(),
		"Theme":      getTheme(r),
		"CSPNonce":   cspNonce(r),
		"T":          t,
		"Lang":       lang,
		"Languages":  supportedLanguages,
		"IsAdmin":    true,
		"SudoRules":  s.sudoRules.Rules(),
		"CSRFToken":  csrfToken,
		"CSRFTs":     csrfTs,
	}); err != nil {
		slog.Error("template execution", "err", err)
	}
}

// handleSudoRuleAdd adds a new sudo rule.
// POST /api/sudo-rules/add
func (s *Server) handleSudoRuleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isBridgeMode() {
		http.Error(w, "not available", http.StatusNotFound)
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

	rule := sudorules.SudoRule{
		Group:      strings.TrimSpace(r.FormValue("group")),
		Hosts:      strings.TrimSpace(r.FormValue("hosts")),
		Commands:   strings.TrimSpace(r.FormValue("commands")),
		RunAsUser:  strings.TrimSpace(r.FormValue("run_as_user")),
		RunAsGroup: strings.TrimSpace(r.FormValue("run_as_group")),
		Options:    strings.TrimSpace(r.FormValue("options")),
	}

	if rule.Group == "" || rule.Commands == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return
	}
	if len(rule.Group) > 256 || !posixGroupName.MatchString(rule.Group) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}
	if !validateSudoRuleFields(rule) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}

	if err := s.sudoRules.Add(rule); err != nil {
		revokeErrorPage(w, r, http.StatusConflict, "sudo_rule_conflict", "sudo_rule_conflict_message")
		return
	}

	s.store.LogAction(adminUser, challpkg.ActionSudoRuleModified, rule.Group, "", adminUser)
	slog.Info("SUDO_RULE_ADDED", "admin", adminUser, "group", rule.Group, "remote_addr", remoteAddr(r))
	s.setFlashCookie(w, "sudo_added:"+rule.Group)
	http.Redirect(w, r, s.baseURL+"/admin/sudo-rules", http.StatusSeeOther)
}

// handleSudoRuleUpdate updates an existing sudo rule.
// POST /api/sudo-rules/update
func (s *Server) handleSudoRuleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isBridgeMode() {
		http.Error(w, "not available", http.StatusNotFound)
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

	rule := sudorules.SudoRule{
		Group:      strings.TrimSpace(r.FormValue("group")),
		Hosts:      strings.TrimSpace(r.FormValue("hosts")),
		Commands:   strings.TrimSpace(r.FormValue("commands")),
		RunAsUser:  strings.TrimSpace(r.FormValue("run_as_user")),
		RunAsGroup: strings.TrimSpace(r.FormValue("run_as_group")),
		Options:    strings.TrimSpace(r.FormValue("options")),
	}

	if rule.Group == "" || rule.Commands == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return
	}
	if len(rule.Group) > 256 || !posixGroupName.MatchString(rule.Group) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}
	if !validateSudoRuleFields(rule) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}

	if err := s.sudoRules.Update(rule); err != nil {
		revokeErrorPage(w, r, http.StatusNotFound, "sudo_rule_not_found", "sudo_rule_not_found_message")
		return
	}

	s.store.LogAction(adminUser, challpkg.ActionSudoRuleModified, rule.Group, "", adminUser)
	slog.Info("SUDO_RULE_UPDATED", "admin", adminUser, "group", rule.Group, "remote_addr", remoteAddr(r))
	s.setFlashCookie(w, "sudo_updated:"+rule.Group)
	http.Redirect(w, r, s.baseURL+"/admin/sudo-rules", http.StatusSeeOther)
}

// handleSudoRuleDelete deletes a sudo rule.
// POST /api/sudo-rules/delete
func (s *Server) handleSudoRuleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isBridgeMode() {
		http.Error(w, "not available", http.StatusNotFound)
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

	group := strings.TrimSpace(r.FormValue("group"))
	if group == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return
	}
	if len(group) > 256 || !posixGroupName.MatchString(group) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}

	if err := s.sudoRules.Remove(group); err != nil {
		revokeErrorPage(w, r, http.StatusNotFound, "sudo_rule_not_found", "sudo_rule_not_found_message")
		return
	}

	s.store.LogAction(adminUser, challpkg.ActionSudoRuleModified, group, "", adminUser)
	slog.Info("SUDO_RULE_DELETED", "admin", adminUser, "group", group, "remote_addr", remoteAddr(r))
	s.setFlashCookie(w, "sudo_deleted:"+group)
	http.Redirect(w, r, s.baseURL+"/admin/sudo-rules", http.StatusSeeOther)
}
