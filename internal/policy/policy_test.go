package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEvaluateFirstMatchWins(t *testing.T) {
	policies := []Policy{
		{Name: "prod", MatchHosts: []string{"*.prod"}, RequireAdmin: true, MinApprovals: 1},
		{Name: "staging", MatchHosts: []string{"*.staging"}, RequireAdmin: false, AutoApproveGrace: true},
	}
	e := NewEngine(policies)

	r := e.Evaluate("alice", "web1.prod", "")
	if r.PolicyName != "prod" {
		t.Errorf("expected policy 'prod', got %q", r.PolicyName)
	}
	if !r.RequireAdmin {
		t.Error("expected RequireAdmin=true for prod")
	}
	if r.GraceEligible {
		t.Error("expected GraceEligible=false for prod")
	}

	r = e.Evaluate("alice", "web1.staging", "")
	if r.PolicyName != "staging" {
		t.Errorf("expected policy 'staging', got %q", r.PolicyName)
	}
	if r.RequireAdmin {
		t.Error("expected RequireAdmin=false for staging")
	}
	if !r.GraceEligible {
		t.Error("expected GraceEligible=true for staging")
	}
}

func TestEvaluateDefaultFallback(t *testing.T) {
	policies := []Policy{
		{Name: "prod", MatchHosts: []string{"*.prod"}, RequireAdmin: true},
		{Name: "default", RequireAdmin: false, AutoApproveGrace: true, MinApprovals: 1},
	}
	e := NewEngine(policies)

	r := e.Evaluate("alice", "unknown-host", "")
	if r.PolicyName != "default" {
		t.Errorf("expected default policy, got %q", r.PolicyName)
	}
	if !r.GraceEligible {
		t.Error("expected GraceEligible=true for default policy")
	}
}

func TestEvaluateNoMatchPermissive(t *testing.T) {
	policies := []Policy{
		{Name: "prod", MatchHosts: []string{"*.prod"}, RequireAdmin: true},
	}
	e := NewEngine(policies)

	r := e.Evaluate("alice", "dev-host", "")
	if r.PolicyName != "" {
		t.Errorf("expected empty policy name, got %q", r.PolicyName)
	}
	if r.RequireAdmin {
		t.Error("expected permissive (RequireAdmin=false)")
	}
	if !r.GraceEligible {
		t.Error("expected permissive (GraceEligible=true)")
	}
	if !r.TimeWindowOK {
		t.Error("expected permissive (TimeWindowOK=true)")
	}
}

func TestEvaluateNilEngine(t *testing.T) {
	var e *Engine
	r := e.Evaluate("alice", "host1", "")
	if r.RequireAdmin {
		t.Error("nil engine should return permissive result")
	}
	if !r.GraceEligible {
		t.Error("nil engine should allow grace")
	}
}

func TestHostGroupMatch(t *testing.T) {
	policies := []Policy{
		{Name: "production", MatchHostGroups: []string{"production"}, RequireAdmin: true},
	}
	e := NewEngine(policies)

	r := e.Evaluate("alice", "web1.example.com", "production")
	if r.PolicyName != "production" {
		t.Errorf("expected 'production' policy, got %q", r.PolicyName)
	}
	if !r.RequireAdmin {
		t.Error("expected RequireAdmin=true")
	}

	r = e.Evaluate("alice", "web1.example.com", "staging")
	if r.PolicyName != "" {
		t.Errorf("expected no match for staging group, got %q", r.PolicyName)
	}
}

func TestUserMatch(t *testing.T) {
	policies := []Policy{
		{Name: "contractors", MatchUsers: []string{"contractor-*"}, RequireAdmin: true},
	}
	e := NewEngine(policies)

	r := e.Evaluate("contractor-alice", "host1", "")
	if r.PolicyName != "contractors" {
		t.Errorf("expected 'contractors', got %q", r.PolicyName)
	}

	r = e.Evaluate("alice", "host1", "")
	if r.PolicyName != "" {
		t.Errorf("expected no match for regular user, got %q", r.PolicyName)
	}
}

func TestCombinedCriteria(t *testing.T) {
	policies := []Policy{
		{
			Name:            "prod-contractors",
			MatchHosts:      []string{"*.prod"},
			MatchUsers:      []string{"contractor-*"},
			RequireAdmin:    true,
			MinApprovals:    2,
		},
	}
	e := NewEngine(policies)

	// Both criteria match
	r := e.Evaluate("contractor-alice", "web1.prod", "")
	if r.PolicyName != "prod-contractors" {
		t.Errorf("expected match, got %q", r.PolicyName)
	}
	if r.MinApprovals != 2 {
		t.Errorf("expected MinApprovals=2, got %d", r.MinApprovals)
	}

	// Only host matches
	r = e.Evaluate("alice", "web1.prod", "")
	if r.PolicyName != "" {
		t.Errorf("expected no match when user doesn't match, got %q", r.PolicyName)
	}

	// Only user matches
	r = e.Evaluate("contractor-alice", "dev-host", "")
	if r.PolicyName != "" {
		t.Errorf("expected no match when host doesn't match, got %q", r.PolicyName)
	}
}

func TestTimeWindowHours(t *testing.T) {
	policies := []Policy{
		{
			Name:         "business-hours",
			MatchHosts:   []string{"*"},
			RequireAdmin: true,
			AllowedHours: "09:00-17:00",
		},
	}
	e := NewEngine(policies)

	// 10:30 UTC = within window
	withinWindow := time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC) // Friday
	r := e.EvaluateAt("alice", "host1", "", withinWindow)
	if !r.TimeWindowOK {
		t.Error("expected TimeWindowOK=true at 10:30 UTC")
	}

	// 18:00 UTC = outside window
	outsideWindow := time.Date(2024, 3, 15, 18, 0, 0, 0, time.UTC)
	r = e.EvaluateAt("alice", "host1", "", outsideWindow)
	if r.TimeWindowOK {
		t.Error("expected TimeWindowOK=false at 18:00 UTC")
	}

	// 09:00 exactly = within window (inclusive start)
	atStart := time.Date(2024, 3, 15, 9, 0, 0, 0, time.UTC)
	r = e.EvaluateAt("alice", "host1", "", atStart)
	if !r.TimeWindowOK {
		t.Error("expected TimeWindowOK=true at 09:00 UTC (inclusive start)")
	}

	// 17:00 exactly = outside window (exclusive end)
	atEnd := time.Date(2024, 3, 15, 17, 0, 0, 0, time.UTC)
	r = e.EvaluateAt("alice", "host1", "", atEnd)
	if r.TimeWindowOK {
		t.Error("expected TimeWindowOK=false at 17:00 UTC (exclusive end)")
	}
}

func TestTimeWindowWrapAround(t *testing.T) {
	policies := []Policy{
		{
			Name:         "night-shift",
			MatchHosts:   []string{"*"},
			AllowedHours: "22:00-06:00",
		},
	}
	e := NewEngine(policies)

	night := time.Date(2024, 3, 15, 23, 0, 0, 0, time.UTC)
	r := e.EvaluateAt("alice", "host1", "", night)
	if !r.TimeWindowOK {
		t.Error("expected TimeWindowOK=true at 23:00 (within 22:00-06:00)")
	}

	earlyMorning := time.Date(2024, 3, 16, 3, 0, 0, 0, time.UTC)
	r = e.EvaluateAt("alice", "host1", "", earlyMorning)
	if !r.TimeWindowOK {
		t.Error("expected TimeWindowOK=true at 03:00 (within 22:00-06:00)")
	}

	noon := time.Date(2024, 3, 15, 12, 0, 0, 0, time.UTC)
	r = e.EvaluateAt("alice", "host1", "", noon)
	if r.TimeWindowOK {
		t.Error("expected TimeWindowOK=false at 12:00 (outside 22:00-06:00)")
	}
}

func TestTimeWindowDays(t *testing.T) {
	policies := []Policy{
		{
			Name:        "weekday-only",
			MatchHosts:  []string{"*"},
			AllowedDays: "Mon-Fri",
		},
	}
	e := NewEngine(policies)

	// Wednesday
	wed := time.Date(2024, 3, 13, 12, 0, 0, 0, time.UTC)
	r := e.EvaluateAt("alice", "host1", "", wed)
	if !r.TimeWindowOK {
		t.Error("expected TimeWindowOK=true on Wednesday")
	}

	// Saturday
	sat := time.Date(2024, 3, 16, 12, 0, 0, 0, time.UTC)
	r = e.EvaluateAt("alice", "host1", "", sat)
	if r.TimeWindowOK {
		t.Error("expected TimeWindowOK=false on Saturday")
	}

	// Sunday
	sun := time.Date(2024, 3, 17, 12, 0, 0, 0, time.UTC)
	r = e.EvaluateAt("alice", "host1", "", sun)
	if r.TimeWindowOK {
		t.Error("expected TimeWindowOK=false on Sunday")
	}
}

func TestTimeWindowCommaSeparatedDays(t *testing.T) {
	policies := []Policy{
		{
			Name:        "mon-wed-fri",
			MatchHosts:  []string{"*"},
			AllowedDays: "Mon,Wed,Fri",
		},
	}
	e := NewEngine(policies)

	// Monday
	mon := time.Date(2024, 3, 11, 12, 0, 0, 0, time.UTC)
	r := e.EvaluateAt("alice", "host1", "", mon)
	if !r.TimeWindowOK {
		t.Error("expected TimeWindowOK=true on Monday")
	}

	// Tuesday
	tue := time.Date(2024, 3, 12, 12, 0, 0, 0, time.UTC)
	r = e.EvaluateAt("alice", "host1", "", tue)
	if r.TimeWindowOK {
		t.Error("expected TimeWindowOK=false on Tuesday")
	}
}

func TestNotifyChannels(t *testing.T) {
	policies := []Policy{
		{
			Name:           "prod",
			MatchHosts:     []string{"*.prod"},
			NotifyChannels: []string{"slack-ops", "pagerduty"},
		},
	}
	e := NewEngine(policies)

	r := e.Evaluate("alice", "web1.prod", "")
	if len(r.NotifyChannels) != 2 || r.NotifyChannels[0] != "slack-ops" {
		t.Errorf("expected notify channels [slack-ops pagerduty], got %v", r.NotifyChannels)
	}
}

func TestLoadSavePolicies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	// Load nonexistent file returns nil.
	policies, err := LoadPolicies(path)
	if err != nil {
		t.Fatalf("LoadPolicies nonexistent: %v", err)
	}
	if policies != nil {
		t.Fatalf("expected nil, got %v", policies)
	}

	// Save and reload.
	policies = []Policy{
		{Name: "prod", MatchHosts: []string{"*.prod"}, RequireAdmin: true},
		{Name: "default", AutoApproveGrace: true},
	}
	if err := SavePolicies(path, policies); err != nil {
		t.Fatalf("SavePolicies: %v", err)
	}

	loaded, err := LoadPolicies(path)
	if err != nil {
		t.Fatalf("LoadPolicies after save: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(loaded))
	}
	if loaded[0].Name != "prod" || !loaded[0].RequireAdmin {
		t.Errorf("policy 0 mismatch: %+v", loaded[0])
	}
	if loaded[1].Name != "default" || !loaded[1].AutoApproveGrace {
		t.Errorf("policy 1 mismatch: %+v", loaded[1])
	}
}

func TestLoadPoliciesRejectsWorldWritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")
	if err := os.WriteFile(path, []byte(`{"policies":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	_, err := LoadPolicies(path)
	if err == nil {
		t.Fatal("expected error for world-writable file")
	}
}

func TestMinApprovalsDefault(t *testing.T) {
	policies := []Policy{
		{Name: "no-min", MatchHosts: []string{"*"}, MinApprovals: 0},
	}
	e := NewEngine(policies)
	r := e.Evaluate("alice", "host1", "")
	if r.MinApprovals != 1 {
		t.Errorf("expected MinApprovals=1 when configured as 0, got %d", r.MinApprovals)
	}
}

func TestAllowedWindowString(t *testing.T) {
	policies := []Policy{
		{
			Name:         "full-window",
			MatchHosts:   []string{"*"},
			AllowedHours: "09:00-17:00",
			AllowedDays:  "Mon-Fri",
		},
	}
	e := NewEngine(policies)
	r := e.EvaluateAt("alice", "host1", "", time.Date(2024, 3, 13, 10, 0, 0, 0, time.UTC))
	if r.AllowedWindow != "09:00-17:00 Mon-Fri" {
		t.Errorf("expected '09:00-17:00 Mon-Fri', got %q", r.AllowedWindow)
	}
}

func TestRequireFreshOIDCParsing(t *testing.T) {
	policies := []Policy{
		{
			Name:             "strict",
			MatchHosts:       []string{"*.prod"},
			RequireFreshOIDC: "5m",
		},
	}
	e := NewEngine(policies)

	r := e.Evaluate("alice", "web1.prod", "")
	if r.PolicyName != "strict" {
		t.Fatalf("expected policy 'strict', got %q", r.PolicyName)
	}
	if r.RequireFreshOIDC != 5*time.Minute {
		t.Errorf("expected RequireFreshOIDC=5m, got %v", r.RequireFreshOIDC)
	}
}

func TestRequireFreshOIDCOneHour(t *testing.T) {
	policies := []Policy{
		{
			Name:             "moderate",
			MatchHosts:       []string{"*.staging"},
			RequireFreshOIDC: "1h",
		},
	}
	e := NewEngine(policies)

	r := e.Evaluate("alice", "web1.staging", "")
	if r.RequireFreshOIDC != time.Hour {
		t.Errorf("expected RequireFreshOIDC=1h, got %v", r.RequireFreshOIDC)
	}
}

func TestRequireFreshOIDCEmpty(t *testing.T) {
	policies := []Policy{
		{
			Name:       "relaxed",
			MatchHosts: []string{"*.dev"},
		},
	}
	e := NewEngine(policies)

	r := e.Evaluate("alice", "web1.dev", "")
	if r.RequireFreshOIDC != 0 {
		t.Errorf("expected RequireFreshOIDC=0 when not set, got %v", r.RequireFreshOIDC)
	}
}

func TestRequireFreshOIDCInvalid(t *testing.T) {
	policies := []Policy{
		{
			Name:             "bad-duration",
			MatchHosts:       []string{"*.test"},
			RequireFreshOIDC: "not-a-duration",
		},
	}
	e := NewEngine(policies)

	r := e.Evaluate("alice", "web1.test", "")
	if r.RequireFreshOIDC != 0 {
		t.Errorf("expected RequireFreshOIDC=0 for invalid duration, got %v", r.RequireFreshOIDC)
	}
}

func TestRequireFreshOIDCDefaultPolicy(t *testing.T) {
	policies := []Policy{
		{
			Name:             "default",
			RequireFreshOIDC: "10m",
			AutoApproveGrace: true,
		},
	}
	e := NewEngine(policies)

	r := e.Evaluate("alice", "unknown-host", "")
	if r.PolicyName != "default" {
		t.Fatalf("expected default policy, got %q", r.PolicyName)
	}
	if r.RequireFreshOIDC != 10*time.Minute {
		t.Errorf("expected RequireFreshOIDC=10m from default, got %v", r.RequireFreshOIDC)
	}
}

func TestEnginePolicesCopy(t *testing.T) {
	policies := []Policy{
		{Name: "prod", MatchHosts: []string{"*.prod"}},
	}
	e := NewEngine(policies)
	out := e.Policies()
	out[0].Name = "modified"
	if e.policies[0].Name != "prod" {
		t.Error("Policies() should return a copy")
	}
}
