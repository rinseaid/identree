package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/rinseaid/identree/internal/challenge"
)

// agentHeartbeatRequest is the JSON body posted by a managed host to
// /api/agent/heartbeat. The IP comes from r.RemoteAddr; the agent is
// authenticated by its shared secret (global or per-host registry).
type agentHeartbeatRequest struct {
	Hostname string `json:"hostname"`
	Version  string `json:"version,omitempty"`
	OSInfo   string `json:"os_info,omitempty"`
}

// handleAgentHeartbeat records a single heartbeat from a managed host.
// POST /api/agent/heartbeat with X-Shared-Secret authentication.
func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode body before auth so we know the hostname for per-host secret
	// validation; the body is small and shared-secret-only flows already
	// pay this cost in the challenge handler.
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req agentHeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	req.Hostname = strings.TrimSpace(req.Hostname)
	if req.Hostname == "" {
		apiError(w, http.StatusBadRequest, "hostname is required")
		return
	}

	// Authentication: global shared secret or matching per-host secret.
	authed := false
	if s.verifySharedSecret(r) {
		authed = true
	} else if s.hostRegistry.IsEnabled() {
		provided := r.Header.Get("X-Shared-Secret")
		if provided != "" && s.hostRegistry.ValidateHost(req.Hostname, provided) {
			authed = true
		}
	}
	if !authed {
		apiError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	s.store.RecordHeartbeat(challenge.AgentHeartbeat{
		Hostname: req.Hostname,
		Version:  strings.TrimSpace(req.Version),
		OSInfo:   strings.TrimSpace(req.OSInfo),
		IP:       remoteAddr(r),
	})

	w.WriteHeader(http.StatusNoContent)
}

// agentListEntry is the JSON shape returned by /api/agents.
type agentListEntry struct {
	Hostname     string `json:"hostname"`
	Version      string `json:"version,omitempty"`
	OSInfo       string `json:"os_info,omitempty"`
	IP           string `json:"ip,omitempty"`
	FirstSeenISO string `json:"first_seen"`
	LastSeenISO  string `json:"last_seen"`
	LastSeenAgo  string `json:"last_seen_ago"`
	Status       string `json:"status"` // "green" / "amber" / "red"
}

// handleAgentList returns the current agent fleet as JSON.
// GET /api/agents — admin session required.
func (s *Server) handleAgentList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.getSessionUser(r) == "" || s.getSessionRole(r) != "admin" {
		apiError(w, http.StatusUnauthorized, "admin session required")
		return
	}

	now := time.Now()
	agents := s.store.ListAgents()
	out := make([]agentListEntry, 0, len(agents))
	for _, a := range agents {
		entry := agentListEntry{
			Hostname:     a.Hostname,
			Version:      a.Version,
			OSInfo:       a.OSInfo,
			IP:           a.IP,
			FirstSeenISO: a.FirstSeen.UTC().Format(time.RFC3339),
			LastSeenISO:  a.LastSeen.UTC().Format(time.RFC3339),
			LastSeenAgo:  formatAgo(now.Sub(a.LastSeen)),
			Status:       agentStatus(now, a.LastSeen),
		}
		out = append(out, entry)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"agents": out})
}

// agentStatus classifies the host's last_seen as green (<5m), amber
// (5–60m), or red (>60m).
func agentStatus(now, lastSeen time.Time) string {
	if lastSeen.IsZero() {
		return "red"
	}
	delta := now.Sub(lastSeen)
	switch {
	case delta < 5*time.Minute:
		return "green"
	case delta < 60*time.Minute:
		return "amber"
	default:
		return "red"
	}
}

// formatAgo renders a human-friendly relative duration ("12s", "5m", "2h").
func formatAgo(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return formatSeconds(d)
	case d < time.Hour:
		return formatMinutes(d)
	case d < 24*time.Hour:
		return formatHours(d)
	default:
		days := int(d / (24 * time.Hour))
		return formatInt(days) + "d"
	}
}

func formatSeconds(d time.Duration) string {
	return formatInt(int(d.Seconds())) + "s"
}
func formatMinutes(d time.Duration) string {
	return formatInt(int(d.Minutes())) + "m"
}
func formatHours(d time.Duration) string {
	return formatInt(int(d.Hours())) + "h"
}

// formatInt is a small helper to avoid pulling fmt for trivial concatenation.
func formatInt(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
