package notify

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMatchesGlob(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		patterns []string
		want     bool
	}{
		{"empty patterns matches all", "anything", nil, true},
		{"empty patterns matches empty string", "", nil, true},
		{"wildcard matches", "challenge_created", []string{"*"}, true},
		{"exact match", "challenge_created", []string{"challenge_created"}, true},
		{"no match", "challenge_created", []string{"challenge_approved"}, false},
		{"glob prefix", "prod-web-01", []string{"prod-*"}, true},
		{"glob suffix", "prod-web-01", []string{"*-01"}, true},
		{"multiple patterns first match", "staging-db", []string{"prod-*", "staging-*"}, true},
		{"multiple patterns no match", "dev-app", []string{"prod-*", "staging-*"}, false},
		{"empty string no match with pattern", "", []string{"foo"}, false},
		{"empty string matches wildcard", "", []string{"*"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesGlob(tt.s, tt.patterns)
			if got != tt.want {
				t.Errorf("MatchesGlob(%q, %v) = %v, want %v", tt.s, tt.patterns, got, tt.want)
			}
		})
	}
}

func TestEvaluateRoutes(t *testing.T) {
	routes := []Route{
		{
			Channels: []string{"ops-slack"},
			Events:   []string{"challenge_created", "challenge_approved"},
			Hosts:    []string{"prod-*"},
		},
		{
			Channels: []string{"security-discord"},
			Events:   []string{"revealed_breakglass", "config_changed"},
		},
		{
			Channels: []string{"all-slack"},
			Events:   []string{"*"},
			Hosts:    []string{"*.staging"},
		},
	}

	tests := []struct {
		name     string
		event    string
		hostname string
		username string
		want     map[string]bool
	}{
		{
			"prod challenge matches ops",
			"challenge_created", "prod-web-01", "alice",
			map[string]bool{"ops-slack": true},
		},
		{
			"security event matches security channel",
			"revealed_breakglass", "any-host", "bob",
			map[string]bool{"security-discord": true},
		},
		{
			"staging matches wildcard route",
			"auto_approved", "app.staging", "carol",
			map[string]bool{"all-slack": true},
		},
		{
			"no match",
			"challenge_created", "dev-app-01", "alice",
			map[string]bool{},
		},
		{
			"multiple routes match",
			"challenge_created", "prod-web.staging", "alice",
			map[string]bool{"ops-slack": true, "all-slack": true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateRoutes(routes, tt.event, tt.hostname, tt.username)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for k := range tt.want {
				if !got[k] {
					t.Errorf("missing channel %q in result %v", k, got)
				}
			}
		})
	}
}

func TestEvaluateRoutesUserFilter(t *testing.T) {
	routes := []Route{
		{
			Channels: []string{"admin-only"},
			Events:   []string{"*"},
			Users:    []string{"admin-*"},
		},
	}
	got := EvaluateRoutes(routes, "test", "host", "admin-alice")
	if !got["admin-only"] {
		t.Errorf("expected admin-only channel for admin-alice, got %v", got)
	}
	got = EvaluateRoutes(routes, "test", "host", "regular-bob")
	if got["admin-only"] {
		t.Errorf("expected no match for regular-bob, got %v", got)
	}
}

func TestLoadSaveNotificationConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notify.json")

	// Load nonexistent file returns empty config.
	cfg, err := LoadNotificationConfig(path)
	if err != nil {
		t.Fatalf("LoadNotificationConfig nonexistent: %v", err)
	}
	if len(cfg.Channels) != 0 || len(cfg.Routes) != 0 {
		t.Fatalf("expected empty config, got %+v", cfg)
	}

	// Save and reload.
	cfg.Channels = []Channel{
		{Name: "test-slack", Backend: "slack", URL: "https://example.com"},
	}
	cfg.Routes = []Route{
		{Channels: []string{"test-slack"}, Events: []string{"*"}},
	}
	if err := SaveNotificationConfig(path, cfg); err != nil {
		t.Fatalf("SaveNotificationConfig: %v", err)
	}

	cfg2, err := LoadNotificationConfig(path)
	if err != nil {
		t.Fatalf("LoadNotificationConfig after save: %v", err)
	}
	if len(cfg2.Channels) != 1 || cfg2.Channels[0].Name != "test-slack" {
		t.Errorf("channels mismatch: %+v", cfg2.Channels)
	}
	if len(cfg2.Routes) != 1 || len(cfg2.Routes[0].Events) != 1 {
		t.Errorf("routes mismatch: %+v", cfg2.Routes)
	}
}

func TestInjectChannelSecrets(t *testing.T) {
	t.Setenv("IDENTREE_NOTIFY_CHANNEL_MY_SLACK_TOKEN", "secret-token")
	t.Setenv("IDENTREE_NOTIFY_CHANNEL_MY_SLACK_COMMAND", "/usr/bin/notify")

	channels := []Channel{
		{Name: "my-slack", Backend: "slack"},
	}
	InjectChannelSecrets(channels)

	if channels[0].Token != "secret-token" {
		t.Errorf("token not injected: got %q", channels[0].Token)
	}
	if channels[0].Command != "/usr/bin/notify" {
		t.Errorf("command not injected: got %q", channels[0].Command)
	}
}

func TestDeliverWebhook(t *testing.T) {
	ssrfCheckEnabled = false
	t.Cleanup(func() { ssrfCheckEnabled = true })

	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = json.Marshal(map[string]string{"ok": "true"})
		w.WriteHeader(200)
	}))
	defer srv.Close()

	ch := Channel{Name: "test", Backend: "webhook", URL: srv.URL}
	data := WebhookData{Event: "test", Username: "alice", Hostname: "host1", Timestamp: "2026-01-01T00:00:00Z"}

	if err := Deliver(ch, data, 5e9); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if received == nil {
		t.Error("server never received request")
	}
}

func TestDeliverWebhook4xxNeverRetried(t *testing.T) {
	ssrfCheckEnabled = false
	t.Cleanup(func() { ssrfCheckEnabled = true })

	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(403)
	}))
	defer srv.Close()

	ch := Channel{Name: "test", Backend: "webhook", URL: srv.URL}
	data := WebhookData{Event: "test"}

	err := Deliver(ch, data, 5e9)
	if err == nil {
		t.Fatal("expected error on 403")
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt (no retry on 4xx), got %d", attempts)
	}
}

func TestLoadNotificationConfigRejectsWorldWritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notify.json")
	if err := os.WriteFile(path, []byte(`{"channels":[],"routes":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	// Make it world-writable after creation.
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}

	_, err := LoadNotificationConfig(path)
	if err == nil {
		t.Fatal("expected error for world-writable file")
	}
}

func TestRunChannelCommandSuccess(t *testing.T) {
	// Use a command that prints its environment-derived value and exits 0.
	ch := Channel{Name: "custom", Backend: "custom", Command: `test "$NOTIFY_USERNAME" = "alice"`}
	data := WebhookData{Event: "challenge_created", Username: "alice", ApprovalURL: "https://a"}
	if err := runChannelCommand(ch, data, 5e9); err != nil {
		t.Fatalf("runChannelCommand: %v", err)
	}
}

func TestRunChannelCommandFailure(t *testing.T) {
	ch := Channel{Name: "fail", Backend: "custom", Command: `echo boom >&2; exit 7`}
	err := runChannelCommand(ch, WebhookData{}, 5e9)
	if err == nil {
		t.Fatal("expected error from failing command")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("error should include stderr: %v", err)
	}
}

func TestRunChannelCommandDeliverIntegration(t *testing.T) {
	ch := Channel{Name: "custom", Backend: "custom", Command: `exit 0`}
	if err := Deliver(ch, WebhookData{Event: "test"}, 5e9); err != nil {
		t.Fatalf("Deliver custom: %v", err)
	}
}

func TestLimitedWriter(t *testing.T) {
	var buf bytes.Buffer
	lw := &limitedWriter{w: &buf, n: 5}
	// First write fits.
	n, err := lw.Write([]byte("abc"))
	if err != nil || n != 3 {
		t.Fatalf("write1 n=%d err=%v", n, err)
	}
	// Second write is truncated to remaining budget.
	n, err = lw.Write([]byte("defgh"))
	if err != nil {
		t.Fatalf("write2 err=%v", n)
	}
	if buf.String() != "abcde" {
		t.Errorf("buf = %q, want %q", buf.String(), "abcde")
	}
	// Further writes silently discarded but report full length.
	n, err = lw.Write([]byte("xyz"))
	if err != nil || n != 3 {
		t.Errorf("discard write n=%d err=%v", n, err)
	}
	if buf.String() != "abcde" {
		t.Errorf("buf mutated after limit: %q", buf.String())
	}
}

func TestSanitizeEnv(t *testing.T) {
	got := sanitizeEnv("hello\nworld\x00!")
	if got != "helloworld!" {
		t.Errorf("sanitizeEnv = %q, want %q", got, "helloworld!")
	}
}
