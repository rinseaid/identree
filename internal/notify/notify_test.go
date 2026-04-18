package notify

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBestApprovalURL(t *testing.T) {
	tests := []struct {
		name string
		d    WebhookData
		want string
	}{
		{"prefers onetap", WebhookData{OneTapURL: "https://o", ApprovalURL: "https://a"}, "https://o"},
		{"falls back to approval", WebhookData{ApprovalURL: "https://a"}, "https://a"},
		{"both empty", WebhookData{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.d.BestApprovalURL(); got != tt.want {
				t.Errorf("BestApprovalURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// sampleData returns a WebhookData with all fields populated.
func sampleData() WebhookData {
	return WebhookData{
		Event:       "challenge_created",
		Username:    "alice",
		Hostname:    "prod-web-01",
		UserCode:    "ABC-123",
		ApprovalURL: "https://id.example.com/approve",
		OneTapURL:   "https://id.example.com/onetap?t=xyz",
		ExpiresIn:   60,
		Timestamp:   "2026-04-18T12:00:00Z",
		Reason:      "sudo rm -rf /",
		Actor:       "admin-bob",
	}
}

func TestFormatWebhookApprise(t *testing.T) {
	d := sampleData()
	raw, err := FormatWebhookApprise(d)
	if err != nil {
		t.Fatalf("FormatWebhookApprise: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
	if m["title"] != "Sudo approval needed" {
		t.Errorf("title = %v", m["title"])
	}
	if m["format"] != "markdown" {
		t.Errorf("format = %v", m["format"])
	}
	body, _ := m["body"].(string)
	// Must include the one-tap URL (preferred over approval URL).
	if !strings.Contains(body, d.OneTapURL) {
		t.Errorf("body missing one-tap URL: %q", body)
	}
	if !strings.Contains(body, d.Username) || !strings.Contains(body, d.Hostname) || !strings.Contains(body, d.UserCode) {
		t.Errorf("body missing required fields: %q", body)
	}

	// Test-event path.
	raw, err = FormatWebhookApprise(WebhookData{Event: "test", Actor: "tester", Timestamp: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["title"] != "Test notification from identree" {
		t.Errorf("test title = %v", m["title"])
	}
	if !strings.Contains(m["body"].(string), "tester") {
		t.Errorf("test body missing actor")
	}
}

func TestFormatWebhookDiscord(t *testing.T) {
	d := sampleData()
	raw, err := FormatWebhookDiscord(d)
	if err != nil {
		t.Fatalf("FormatWebhookDiscord: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	embeds, ok := m["embeds"].([]interface{})
	if !ok || len(embeds) != 1 {
		t.Fatalf("embeds missing or wrong shape: %v", m["embeds"])
	}
	embed := embeds[0].(map[string]interface{})
	if embed["title"] != "Sudo approval needed" {
		t.Errorf("title = %v", embed["title"])
	}
	if embed["url"] != d.OneTapURL {
		t.Errorf("url = %v, want %v", embed["url"], d.OneTapURL)
	}
	fields, ok := embed["fields"].([]interface{})
	if !ok || len(fields) != 4 {
		t.Fatalf("expected 4 fields, got %v", embed["fields"])
	}

	// Test-event path.
	raw, _ = FormatWebhookDiscord(WebhookData{Event: "test", Actor: "tester", Timestamp: "t"})
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	embeds = m["embeds"].([]interface{})
	embed = embeds[0].(map[string]interface{})
	if embed["title"] != "Test notification from identree" {
		t.Errorf("test title = %v", embed["title"])
	}
}

func TestFormatWebhookSlack(t *testing.T) {
	d := sampleData()
	raw, err := FormatWebhookSlack(d)
	if err != nil {
		t.Fatalf("FormatWebhookSlack: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	text := m["text"]
	if !strings.Contains(text, "Sudo approval needed") {
		t.Errorf("text missing header: %q", text)
	}
	if !strings.Contains(text, d.OneTapURL) {
		t.Errorf("text missing one-tap URL: %q", text)
	}
	if !strings.Contains(text, d.UserCode) {
		t.Errorf("text missing user code: %q", text)
	}

	// Falls back to ApprovalURL if OneTapURL empty.
	d2 := d
	d2.OneTapURL = ""
	raw, _ = FormatWebhookSlack(d2)
	_ = json.Unmarshal(raw, &m)
	if !strings.Contains(m["text"], d.ApprovalURL) {
		t.Errorf("fallback to ApprovalURL failed: %q", m["text"])
	}

	// Test event.
	raw, _ = FormatWebhookSlack(WebhookData{Event: "test", Actor: "tester", Timestamp: "ts"})
	_ = json.Unmarshal(raw, &m)
	if !strings.Contains(m["text"], "Test notification") || !strings.Contains(m["text"], "tester") {
		t.Errorf("test text = %q", m["text"])
	}
}

func TestFormatWebhookNtfy(t *testing.T) {
	d := sampleData()
	raw, err := FormatWebhookNtfy(d)
	if err != nil {
		t.Fatalf("FormatWebhookNtfy: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["title"] != "Sudo approval needed" {
		t.Errorf("title = %v", m["title"])
	}
	msg, _ := m["message"].(string)
	if !strings.Contains(msg, d.Username) || !strings.Contains(msg, d.UserCode) {
		t.Errorf("message missing fields: %q", msg)
	}
	actions, ok := m["actions"].([]interface{})
	if !ok || len(actions) != 1 {
		t.Fatalf("actions missing: %v", m["actions"])
	}
	action := actions[0].(map[string]interface{})
	if action["url"] != d.OneTapURL {
		t.Errorf("action url = %v, want %v", action["url"], d.OneTapURL)
	}

	// Test event.
	raw, _ = FormatWebhookNtfy(WebhookData{Event: "test", Actor: "tester", Timestamp: "ts"})
	var m2 map[string]interface{}
	if err := json.Unmarshal(raw, &m2); err != nil {
		t.Fatal(err)
	}
	if m2["title"] != "Test notification from identree" {
		t.Errorf("test title = %v", m2["title"])
	}
	if _, has := m2["actions"]; has {
		t.Errorf("test payload should not have actions")
	}
}

func TestFormatWebhookSpecialChars(t *testing.T) {
	// Ensures JSON encoding correctly escapes special characters.
	d := WebhookData{
		Event:       "challenge_created",
		Username:    `al"ice`,
		Hostname:    "host\nbreak",
		UserCode:    "A\tB",
		ApprovalURL: "https://x/?a=b&c=d",
	}
	for name, fn := range map[string]func(WebhookData) ([]byte, error){
		"apprise": FormatWebhookApprise,
		"discord": FormatWebhookDiscord,
		"slack":   FormatWebhookSlack,
		"ntfy":    FormatWebhookNtfy,
	} {
		raw, err := fn(d)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var v interface{}
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Errorf("%s produced invalid JSON: %v", name, err)
		}
	}
}

func TestWebhookStatusErrorError(t *testing.T) {
	e := &WebhookStatusError{Status: 403, Body: "forbidden"}
	s := e.Error()
	if !strings.Contains(s, "403") || !strings.Contains(s, "forbidden") {
		t.Errorf("Error() = %q", s)
	}
}
