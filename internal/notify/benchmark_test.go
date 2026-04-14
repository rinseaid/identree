package notify

import (
	"fmt"
	"testing"
)

// makeRoutes generates n routes with varying event/host/user patterns.
func makeRoutes(n int) []Route {
	routes := make([]Route, n)
	for i := range n {
		r := Route{
			Channels: []string{fmt.Sprintf("channel-%d", i)},
		}
		switch i % 4 {
		case 0:
			r.Events = []string{"challenge_created"}
			r.Hosts = []string{fmt.Sprintf("host-%d-*", i)}
		case 1:
			r.Events = []string{"challenge_approved", "challenge_rejected"}
			r.Users = []string{fmt.Sprintf("user-%d", i)}
		case 2:
			r.Events = []string{"*"}
			r.Hosts = []string{"prod-*"}
		case 3:
			r.Events = []string{"challenge_created"}
			r.Hosts = []string{"staging-*"}
			r.Users = []string{"deploy-*"}
		}
		routes[i] = r
	}
	return routes
}

func BenchmarkEvaluateRoutes_10Routes(b *testing.B) {
	routes := makeRoutes(10)
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		EvaluateRoutes(routes, "challenge_created", "prod-web-01", "alice")
	}
}

func BenchmarkEvaluateRoutes_50Routes(b *testing.B) {
	routes := makeRoutes(50)
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		EvaluateRoutes(routes, "challenge_created", "prod-web-01", "alice")
	}
}

func BenchmarkMatchesGlob_10Patterns(b *testing.B) {
	patterns := make([]string, 10)
	for i := range patterns {
		patterns[i] = fmt.Sprintf("host-%d-*", i)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		MatchesGlob("host-9-web01", patterns)
	}
}

func BenchmarkMatchesGlob_Empty(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		MatchesGlob("anything", nil)
	}
}

func BenchmarkFormatWebhookSlack(b *testing.B) {
	data := WebhookData{
		Event:       "challenge_created",
		Username:    "alice",
		Hostname:    "prod-web-01",
		UserCode:    "ABCD-1234",
		ApprovalURL: "https://identree.example.com/approve/ABCD-1234",
		ExpiresIn:   300,
		Timestamp:   "2025-01-01T00:00:00Z",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		FormatWebhookSlack(data)
	}
}

func BenchmarkFormatWebhookDiscord(b *testing.B) {
	data := WebhookData{
		Event:       "challenge_created",
		Username:    "alice",
		Hostname:    "prod-web-01",
		UserCode:    "ABCD-1234",
		ApprovalURL: "https://identree.example.com/approve/ABCD-1234",
		ExpiresIn:   300,
		Timestamp:   "2025-01-01T00:00:00Z",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		FormatWebhookDiscord(data)
	}
}
