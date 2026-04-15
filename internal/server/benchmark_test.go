package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/policy"
)

// newBenchServer builds a minimal *Server suitable for benchmark tests.
func newBenchServer(b *testing.B, policies []policy.Policy) *Server {
	b.Helper()
	store := challpkg.NewChallengeStore(5*time.Minute, 10*time.Minute, b.TempDir())
	b.Cleanup(func() { store.Stop() })
	return &Server{
		cfg: &config.ServerConfig{
			SharedSecret:  "bench-secret",
			SessionSecret: "bench-secret",
			ChallengeTTL:  5 * time.Minute,
		},
		store:          store,
		hostRegistry:   NewHostRegistry(""),
		authFailRL:     newAuthFailTracker(),
		mutationRL:     newMutationRateLimiter(),
		sseBroadcaster: noopBroadcaster{},
		policyEngine:   policy.NewEngine(policies),
		notifyCfg:      &notify.NotificationConfig{},
	}
}

func BenchmarkChallengeCreate(b *testing.B) {
	s := newBenchServer(b, nil)

	b.ResetTimer()
	b.ReportAllocs()
	for i := range b.N {
		// Vary username and hostname per iteration to avoid the per-user
		// pending challenge rate limit (max 10 per user).
		body, _ := json.Marshal(map[string]string{
			"username": fmt.Sprintf("user-%d", i),
			"hostname": fmt.Sprintf("host-%d", i),
		})
		r := httptest.NewRequest(http.MethodPost, "/api/challenge", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Shared-Secret", "bench-secret")
		r.RemoteAddr = fmt.Sprintf("10.0.%d.%d:12345", (i/256)%256, i%256)
		w := httptest.NewRecorder()
		s.handleCreateChallenge(w, r)
		if w.Code != http.StatusOK && w.Code != http.StatusCreated {
			b.Fatalf("iteration %d: expected 200/201, got %d: %s", i, w.Code, w.Body.String())
		}
	}
}

func BenchmarkChallengePoll(b *testing.B) {
	s := newBenchServer(b, nil)

	// Create a challenge to poll
	createBody, _ := json.Marshal(map[string]string{
		"username": "alice",
		"hostname": "web-01",
	})
	r := httptest.NewRequest(http.MethodPost, "/api/challenge", bytes.NewReader(createBody))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Shared-Secret", "bench-secret")
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleCreateChallenge(w, r)
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		b.Fatalf("create: expected 200/201, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		ID string `json:"challenge_id"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := range b.N {
		pollReq := httptest.NewRequest(http.MethodGet, "/api/challenge/"+resp.ID+"?hostname=web-01", nil)
		pollReq.Header.Set("X-Shared-Secret", "bench-secret")
		pollReq.RemoteAddr = fmt.Sprintf("10.0.%d.%d:12345", (i/256)%256, i%256)
		pw := httptest.NewRecorder()
		s.handlePollChallenge(pw, pollReq)
		if pw.Code != http.StatusOK {
			b.Fatalf("iteration %d: expected 200, got %d: %s", i, pw.Code, pw.Body.String())
		}
	}
}

func BenchmarkPolicyEvaluate(b *testing.B) {
	for _, n := range []int{1, 10, 50, 100} {
		b.Run(fmt.Sprintf("%dPolicies", n), func(b *testing.B) {
			policies := make([]policy.Policy, n)
			for i := range n {
				policies[i] = policy.Policy{
					Name:         fmt.Sprintf("pol-%d", i),
					MatchHosts:   []string{fmt.Sprintf("host-%d-*", i)},
					MinApprovals: 1,
				}
			}
			engine := policy.NewEngine(policies)

			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				engine.Evaluate("alice", "host-5-web01", "")
			}
		})
	}
}

func BenchmarkPolicyEvaluate100Policies(b *testing.B) {
	policies := make([]policy.Policy, 100)
	for i := range 100 {
		policies[i] = policy.Policy{
			Name:             fmt.Sprintf("pol-%d", i),
			MatchHosts:       []string{fmt.Sprintf("host-%d-*", i)},
			MatchUsers:       []string{fmt.Sprintf("user-%d-*", i)},
			MinApprovals:     2,
			AllowedHours:     "08:00-18:00",
			AllowedDays:      "Mon-Fri",
			NotifyChannels:   []string{"slack", "pagerduty"},
			RequireFreshOIDC: "5m",
		}
	}
	engine := policy.NewEngine(policies)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		engine.Evaluate("user-50-admin", "host-50-prod01", "production")
	}
}

func BenchmarkNotificationRouteEvaluate(b *testing.B) {
	routes := make([]notify.Route, 50)
	for i := range 50 {
		routes[i] = notify.Route{
			Channels: []string{fmt.Sprintf("ch-%d", i)},
			Events:   []string{"challenge_created"},
			Hosts:    []string{fmt.Sprintf("host-%d-*", i)},
		}
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		notify.EvaluateRoutes(routes, "challenge_created", "host-25-web01", "alice")
	}
}
