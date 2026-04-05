package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Policy defines a single approval policy with match criteria and requirements.
type Policy struct {
	Name             string   `json:"name"`
	MatchHostGroups  []string `json:"match_host_groups,omitempty"`  // host registry group labels
	MatchHosts       []string `json:"match_hosts,omitempty"`        // hostname glob patterns
	MatchUsers       []string `json:"match_users,omitempty"`        // username patterns
	RequireAdmin     bool     `json:"require_admin"`
	MinApprovals     int      `json:"min_approvals"`                // 0 or 1 = single
	AutoApproveGrace bool     `json:"auto_approve_grace"`
	AllowedHours     string   `json:"allowed_hours,omitempty"`      // "HH:MM-HH:MM" UTC
	AllowedDays      string   `json:"allowed_days,omitempty"`       // "Mon-Fri"
	NotifyChannels   []string `json:"notify_channels,omitempty"`
}

// EvalResult is the outcome of evaluating policies for a given request.
type EvalResult struct {
	PolicyName     string
	RequireAdmin   bool
	MinApprovals   int
	GraceEligible  bool
	TimeWindowOK   bool
	AllowedWindow  string
	NotifyChannels []string
}

// Engine evaluates approval policies against incoming challenge requests.
type Engine struct {
	policies []Policy
	fallback *Policy // the policy named "default", if any
}

// NewEngine creates a policy engine from the given policy list.
// If a policy named "default" exists, it becomes the fallback.
func NewEngine(policies []Policy) *Engine {
	e := &Engine{
		policies: policies,
	}
	for i := range policies {
		if policies[i].Name == "default" {
			p := policies[i]
			e.fallback = &p
			break
		}
	}
	return e
}

// Policies returns a copy of the engine's policy list.
func (e *Engine) Policies() []Policy {
	if e == nil {
		return nil
	}
	out := make([]Policy, len(e.policies))
	copy(out, e.policies)
	return out
}

// Evaluate checks policies in order and returns the result for the first match.
// hostGroup is the group label from the host registry (may be empty).
func (e *Engine) Evaluate(username, hostname, hostGroup string) EvalResult {
	if e == nil {
		return permissiveResult()
	}
	now := time.Now().UTC()
	for _, p := range e.policies {
		if p.Name == "default" {
			continue // default is only used as fallback
		}
		if matchPolicy(p, username, hostname, hostGroup) {
			return buildResult(p, now)
		}
	}
	if e.fallback != nil {
		return buildResult(*e.fallback, now)
	}
	return permissiveResult()
}

// EvaluateAt is like Evaluate but uses the given time for time-window checks.
// Useful for testing.
func (e *Engine) EvaluateAt(username, hostname, hostGroup string, now time.Time) EvalResult {
	if e == nil {
		return permissiveResult()
	}
	for _, p := range e.policies {
		if p.Name == "default" {
			continue
		}
		if matchPolicy(p, username, hostname, hostGroup) {
			return buildResult(p, now)
		}
	}
	if e.fallback != nil {
		return buildResult(*e.fallback, now)
	}
	return permissiveResult()
}

func permissiveResult() EvalResult {
	return EvalResult{
		PolicyName:    "",
		RequireAdmin:  false,
		MinApprovals:  1,
		GraceEligible: true,
		TimeWindowOK:  true,
	}
}

func matchPolicy(p Policy, username, hostname, hostGroup string) bool {
	// A policy must have at least one match criterion.
	hasAnyCriteria := len(p.MatchHostGroups) > 0 || len(p.MatchHosts) > 0 || len(p.MatchUsers) > 0
	if !hasAnyCriteria {
		return false
	}

	// Each non-empty criterion must match. If a criterion is empty, it is
	// not considered (allows matching on just hosts, just users, etc.).
	if len(p.MatchHostGroups) > 0 {
		if !matchAny(p.MatchHostGroups, hostGroup) {
			return false
		}
	}
	if len(p.MatchHosts) > 0 {
		if !matchAnyGlob(p.MatchHosts, hostname) {
			return false
		}
	}
	if len(p.MatchUsers) > 0 {
		if !matchAnyGlob(p.MatchUsers, username) {
			return false
		}
	}
	return true
}

// matchAny checks if value matches any of the given exact strings.
func matchAny(patterns []string, value string) bool {
	for _, p := range patterns {
		if p == value {
			return true
		}
	}
	return false
}

// matchAnyGlob checks if value matches any of the given glob patterns.
func matchAnyGlob(patterns []string, value string) bool {
	for _, p := range patterns {
		matched, err := filepath.Match(p, value)
		if err != nil {
			slog.Warn("policy: invalid glob pattern", "pattern", p, "err", err)
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

func buildResult(p Policy, now time.Time) EvalResult {
	minApprovals := p.MinApprovals
	if minApprovals < 1 {
		minApprovals = 1
	}
	twOK, window := checkTimeWindow(p, now)
	return EvalResult{
		PolicyName:     p.Name,
		RequireAdmin:   p.RequireAdmin,
		MinApprovals:   minApprovals,
		GraceEligible:  p.AutoApproveGrace,
		TimeWindowOK:   twOK,
		AllowedWindow:  window,
		NotifyChannels: p.NotifyChannels,
	}
}

// checkTimeWindow checks whether the given time falls within the policy's
// AllowedHours and AllowedDays. Returns (true, "") if no window is configured.
func checkTimeWindow(p Policy, now time.Time) (ok bool, window string) {
	hoursOK := true
	daysOK := true
	var parts []string

	if p.AllowedHours != "" {
		hoursOK = checkHours(p.AllowedHours, now)
		parts = append(parts, p.AllowedHours)
	}
	if p.AllowedDays != "" {
		daysOK = checkDays(p.AllowedDays, now)
		parts = append(parts, p.AllowedDays)
	}
	return hoursOK && daysOK, strings.Join(parts, " ")
}

// checkHours parses "HH:MM-HH:MM" and checks if now is within the range.
// Supports wrap-around (e.g. "22:00-06:00").
func checkHours(spec string, now time.Time) bool {
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		slog.Warn("policy: invalid AllowedHours format", "spec", spec)
		return true // permissive on parse failure
	}
	startMin, ok1 := parseHHMM(parts[0])
	endMin, ok2 := parseHHMM(parts[1])
	if !ok1 || !ok2 {
		slog.Warn("policy: invalid AllowedHours time", "spec", spec)
		return true
	}
	nowMin := now.Hour()*60 + now.Minute()
	if startMin <= endMin {
		return nowMin >= startMin && nowMin < endMin
	}
	// Wrap-around: e.g. 22:00-06:00
	return nowMin >= startMin || nowMin < endMin
}

func parseHHMM(s string) (minutes int, ok bool) {
	s = strings.TrimSpace(s)
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, false
	}
	var h, m int
	if _, err := fmt.Sscanf(parts[0], "%d", &h); err != nil || h < 0 || h > 23 {
		return 0, false
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &m); err != nil || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

// checkDays parses comma-separated day abbreviations (Mon,Tue,...,Sun) and
// checks if now's weekday is included.
func checkDays(spec string, now time.Time) bool {
	dayMap := map[string]time.Weekday{
		"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday,
		"wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday,
		"sat": time.Saturday,
	}
	today := now.Weekday()
	for _, part := range strings.Split(spec, ",") {
		d := strings.TrimSpace(strings.ToLower(part))
		// Support ranges like "Mon-Fri"
		if rangeParts := strings.SplitN(d, "-", 2); len(rangeParts) == 2 {
			start, ok1 := dayMap[strings.TrimSpace(rangeParts[0])]
			end, ok2 := dayMap[strings.TrimSpace(rangeParts[1])]
			if ok1 && ok2 {
				if start <= end {
					if today >= start && today <= end {
						return true
					}
				} else {
					// Wrap-around: e.g. Fri-Mon
					if today >= start || today <= end {
						return true
					}
				}
			}
			continue
		}
		if wd, ok := dayMap[d]; ok && wd == today {
			return true
		}
	}
	return false
}

// ── Config file I/O ────────────────────────────────────────────────────────

// PoliciesConfig is the top-level JSON structure for the policies file.
type PoliciesConfig struct {
	Policies []Policy `json:"policies"`
}

// LoadPolicies reads approval policies from a JSON file.
// Returns an empty list (not an error) if the file does not exist.
func LoadPolicies(path string) ([]Policy, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("policy: open %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("policy: stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("policy: %s is not a regular file", path)
	}
	if mode := info.Mode().Perm(); mode&0022 != 0 {
		return nil, fmt.Errorf("policy: %s is group/world writable (mode %04o)", path, mode)
	}
	data, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", path, err)
	}
	var cfg PoliciesConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("policy: parse %s: %w", path, err)
	}
	return cfg.Policies, nil
}

// SavePolicies writes approval policies atomically to a JSON file.
func SavePolicies(path string, policies []Policy) error {
	cfg := PoliciesConfig{Policies: policies}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("policy: marshal: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("policy: create dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".approval-policies-*.json")
	if err != nil {
		return fmt.Errorf("policy: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	if err := func() error {
		defer tmp.Close()
		if err := tmp.Chmod(0600); err != nil {
			return err
		}
		if _, err := tmp.Write(data); err != nil {
			return err
		}
		return tmp.Sync()
	}(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
