package policy

import (
	"fmt"
	"testing"
)

// makePolicies generates n policies with varying match patterns.
// Half match on hosts, half on users, all have notify channels and time windows.
func makePolicies(n int) []Policy {
	policies := make([]Policy, n)
	for i := range n {
		p := Policy{
			Name:         fmt.Sprintf("policy-%d", i),
			MinApprovals: 1,
		}
		if i%2 == 0 {
			p.MatchHosts = []string{fmt.Sprintf("host-%d-*", i)}
		} else {
			p.MatchUsers = []string{fmt.Sprintf("user-%d", i)}
		}
		if i%3 == 0 {
			p.AllowedHours = "08:00-18:00"
			p.AllowedDays = "Mon-Fri"
		}
		if i%4 == 0 {
			p.NotifyChannels = []string{"ops-slack", "pagerduty"}
		}
		policies[i] = p
	}
	return policies
}

func benchmarkEvaluate(b *testing.B, n int, match bool) {
	b.Helper()
	policies := makePolicies(n)
	engine := NewEngine(policies)

	// If match is true, use a username/hostname that matches the last policy.
	// If false, use values that won't match anything (worst case: all evaluated).
	var username, hostname string
	if match {
		// Match the first user-based policy (index 1)
		username = "user-1"
		hostname = "unrelated-host"
	} else {
		username = "no-match-user"
		hostname = "no-match-host"
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		engine.Evaluate(username, hostname, "")
	}
}

func BenchmarkEvaluate_1Policy(b *testing.B) {
	benchmarkEvaluate(b, 1, true)
}

func BenchmarkEvaluate_10Policies(b *testing.B) {
	benchmarkEvaluate(b, 10, true)
}

func BenchmarkEvaluate_50Policies(b *testing.B) {
	benchmarkEvaluate(b, 50, true)
}

func BenchmarkEvaluate_100Policies(b *testing.B) {
	benchmarkEvaluate(b, 100, true)
}

func BenchmarkEvaluate_100PoliciesNoMatch(b *testing.B) {
	benchmarkEvaluate(b, 100, false)
}

func BenchmarkEvaluate_WithTimeWindow(b *testing.B) {
	policies := []Policy{
		{
			Name:         "time-gated",
			MatchHosts:   []string{"prod-*"},
			AllowedHours: "08:00-18:00",
			AllowedDays:  "Mon-Fri",
			MinApprovals: 2,
		},
	}
	engine := NewEngine(policies)
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		engine.Evaluate("alice", "prod-web-01", "")
	}
}

func BenchmarkMatchAnyGlob_10Patterns(b *testing.B) {
	patterns := make([]string, 10)
	for i := range patterns {
		patterns[i] = fmt.Sprintf("host-%d-*", i)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		matchAnyGlob(patterns, "host-9-web01")
	}
}
