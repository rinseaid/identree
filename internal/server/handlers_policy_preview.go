package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// handlePolicyPreview performs a dry-run policy evaluation for a given
// host/user combination, returning the effective policy settings without
// creating a challenge.
// GET /api/policy/preview?host=<hostname>&user=<username>
func (s *Server) handlePolicyPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Auth: admin session OR shared secret (API key).
	isAdmin := s.getSessionRole(r) == "admin"
	isAPISecret := s.verifyAPISecret(r)
	if !isAdmin && !isAPISecret {
		apiError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	host := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host")))
	user := strings.TrimSpace(r.URL.Query().Get("user"))
	if host == "" || user == "" {
		apiError(w, http.StatusBadRequest, "host and user query parameters required")
		return
	}

	pr := s.evaluatePolicy(user, host)

	// Look up host group from registry for the response.
	_, hostGroup, _, _ := s.hostRegistry.GetHost(host)

	resp := map[string]interface{}{
		"policy_name":      pr.PolicyName,
		"require_admin":    pr.RequireAdmin,
		"min_approvals":    pr.MinApprovals,
		"auto_approve_grace": pr.GraceEligible,
		"time_window_ok":   pr.TimeWindowOK,
	}
	if pr.AllowedWindow != "" {
		resp["allowed_window"] = pr.AllowedWindow
	}
	if pr.RequireFreshOIDC > 0 {
		resp["require_fresh_oidc"] = pr.RequireFreshOIDC.String()
	}
	if pr.BreakglassBypass {
		resp["break_glass_bypass"] = true
	}
	if len(pr.NotifyChannels) > 0 {
		resp["notify_channels"] = pr.NotifyChannels
	}
	if hostGroup != "" {
		resp["host_group"] = hostGroup
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("writing JSON response", "err", err)
	}
}
