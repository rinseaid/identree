package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"text/template"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// NotificationsTotal tracks notification outcomes.
var NotificationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "identree",
	Name:      "notifications_total",
	Help:      "Total push notification attempts.",
}, []string{"status"}) // sent, failed, skipped

func init() {
	NotificationsTotal.WithLabelValues("sent")
	NotificationsTotal.WithLabelValues("failed")
	NotificationsTotal.WithLabelValues("skipped")
}

// WebhookData holds all the fields available to webhook formatters.
type WebhookData struct {
	Event       string // e.g. "challenge_created", "challenge_approved", "challenge_rejected", "auto_approved"
	Username    string
	Hostname    string
	UserCode    string
	ApprovalURL string
	OneTapURL   string
	ExpiresIn   int
	Timestamp   string
}

// BestApprovalURL returns the one-tap URL if available, otherwise the dashboard URL.
func (d WebhookData) BestApprovalURL() string {
	if d.OneTapURL != "" {
		return d.OneTapURL
	}
	return d.ApprovalURL
}

// FormatWebhookRaw returns a generic JSON payload with all challenge fields.
func FormatWebhookRaw(d WebhookData) ([]byte, error) {
	event := d.Event
	if event == "" {
		event = "challenge_created"
	}
	return json.Marshal(map[string]interface{}{
		"event":        event,
		"username":     d.Username,
		"hostname":     d.Hostname,
		"user_code":    d.UserCode,
		"approval_url": d.ApprovalURL,
		"onetap_url":   d.OneTapURL,
		"expires_in":   d.ExpiresIn,
		"timestamp":    d.Timestamp,
	})
}

// FormatWebhookApprise returns a payload suitable for an Apprise API endpoint.
func FormatWebhookApprise(d WebhookData) ([]byte, error) {
	body := fmt.Sprintf("**User:** %s\n**Host:** %s\n**Code:** `%s`\n**Expires:** %ds\n\n[Approve](%s)",
		d.Username, d.Hostname, d.UserCode, d.ExpiresIn, d.BestApprovalURL())
	return json.Marshal(map[string]interface{}{
		"title":  "Sudo approval needed",
		"body":   body,
		"format": "markdown",
	})
}

// FormatWebhookDiscord returns a Discord webhook embed payload.
func FormatWebhookDiscord(d WebhookData) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"embeds": []map[string]interface{}{{
			"title": "Sudo approval needed",
			"color": 3447003, // blue
			"fields": []map[string]interface{}{
				{"name": "User", "value": d.Username, "inline": true},
				{"name": "Host", "value": d.Hostname, "inline": true},
				{"name": "Code", "value": "`" + d.UserCode + "`", "inline": false},
				{"name": "Expires", "value": fmt.Sprintf("%ds", d.ExpiresIn), "inline": true},
			},
			"url": d.BestApprovalURL(),
		}},
	})
}

// FormatWebhookSlack returns a Slack incoming-webhook payload.
func FormatWebhookSlack(d WebhookData) ([]byte, error) {
	text := fmt.Sprintf("*Sudo approval needed*\nUser: %s | Host: %s | Code: `%s` | Expires: %ds\n<%s|Approve>",
		d.Username, d.Hostname, d.UserCode, d.ExpiresIn, d.BestApprovalURL())
	return json.Marshal(map[string]string{"text": text})
}

// FormatWebhookNtfy returns a payload for an ntfy.sh server.
// The topic is read from the URL path (e.g., https://ntfy.sh/mytopic), not the body.
func FormatWebhookNtfy(d WebhookData) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"title":   "Sudo approval needed",
		"message": fmt.Sprintf("User: %s\nHost: %s\nCode: %s\nExpires: %ds", d.Username, d.Hostname, d.UserCode, d.ExpiresIn),
		"actions": []map[string]string{
			{"action": "view", "label": "Approve", "url": d.BestApprovalURL()},
		},
	})
}

// FormatWebhookCustom renders tmpl as a Go text/template with d as data and
// returns the result as the raw HTTP body (must be valid JSON for most receivers).
func FormatWebhookCustom(d WebhookData, tmpl string) ([]byte, error) {
	t, err := template.New("webhook").Parse(tmpl)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WebhookClient is a hardened HTTP client for webhook delivery:
// no proxy (prevents SSRF via proxy env vars) and no redirect following
// (prevents redirect-based SSRF to internal hosts).
var WebhookClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: &http.Transport{Proxy: nil},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}
