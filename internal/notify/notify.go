package notify

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// NotificationsTotal tracks notification outcomes per channel.
var NotificationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "identree",
	Name:      "notifications_total",
	Help:      "Total push notification attempts.",
}, []string{"status", "channel"}) // status: sent|failed|skipped, channel: channel name

// NotificationDeliveryDuration tracks how long each notification delivery takes.
var NotificationDeliveryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Namespace: "identree",
	Name:      "notification_delivery_duration_seconds",
	Help:      "Time spent delivering a single notification.",
	Buckets:   []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 15, 30},
}, []string{"channel"})

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
	Reason      string `json:"reason,omitempty"`
	Actor       string `json:"actor,omitempty"`
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
	if event == "test" {
		payload := map[string]interface{}{
			"event":     "test",
			"message":   "Test notification from identree",
			"username":  d.Username,
			"hostname":  d.Hostname,
			"timestamp": d.Timestamp,
		}
		if d.Actor != "" {
			payload["actor"] = d.Actor
		}
		return json.Marshal(payload)
	}
	payload := map[string]interface{}{
		"event":        event,
		"username":     d.Username,
		"hostname":     d.Hostname,
		"user_code":    d.UserCode,
		"approval_url": d.ApprovalURL,
		"onetap_url":   d.OneTapURL,
		"expires_in":   d.ExpiresIn,
		"timestamp":    d.Timestamp,
	}
	if d.Reason != "" {
		payload["reason"] = d.Reason
	}
	if d.Actor != "" {
		payload["actor"] = d.Actor
	}
	return json.Marshal(payload)
}

// FormatWebhookApprise returns a payload suitable for an Apprise API endpoint.
func FormatWebhookApprise(d WebhookData) ([]byte, error) {
	if d.Event == "test" {
		return json.Marshal(map[string]interface{}{
			"title":  "Test notification from identree",
			"body":   fmt.Sprintf("Test notification sent by %s at %s", d.Actor, d.Timestamp),
			"format": "markdown",
		})
	}
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
	if d.Event == "test" {
		return json.Marshal(map[string]interface{}{
			"embeds": []map[string]interface{}{{
				"title":       "Test notification from identree",
				"color":       3447003, // blue
				"description": fmt.Sprintf("Test notification sent by %s at %s", d.Actor, d.Timestamp),
			}},
		})
	}
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
	if d.Event == "test" {
		text := fmt.Sprintf("*Test notification from identree*\nSent by %s at %s", d.Actor, d.Timestamp)
		return json.Marshal(map[string]string{"text": text})
	}
	text := fmt.Sprintf("*Sudo approval needed*\nUser: %s | Host: %s | Code: `%s` | Expires: %ds\n<%s|Approve>",
		d.Username, d.Hostname, d.UserCode, d.ExpiresIn, d.BestApprovalURL())
	return json.Marshal(map[string]string{"text": text})
}

// FormatWebhookNtfy returns a payload for an ntfy.sh server.
// The topic is read from the URL path (e.g., https://ntfy.sh/mytopic), not the body.
func FormatWebhookNtfy(d WebhookData) ([]byte, error) {
	if d.Event == "test" {
		return json.Marshal(map[string]interface{}{
			"title":   "Test notification from identree",
			"message": fmt.Sprintf("Sent by %s at %s", d.Actor, d.Timestamp),
		})
	}
	return json.Marshal(map[string]interface{}{
		"title":   "Sudo approval needed",
		"message": fmt.Sprintf("User: %s\nHost: %s\nCode: %s\nExpires: %ds", d.Username, d.Hostname, d.UserCode, d.ExpiresIn),
		"actions": []map[string]string{
			{"action": "view", "label": "Approve", "url": d.BestApprovalURL()},
		},
	})
}

// WebhookClient is a hardened HTTP client for webhook delivery:
// no proxy (prevents SSRF via proxy env vars), no redirect following
// (prevents redirect-based SSRF to internal hosts), and a custom DialContext
// that rejects connections to private/internal IP ranges (prevents DNS-based SSRF).
var WebhookClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		Proxy:       nil,
		DialContext: ssrfSafeDialContext,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}
