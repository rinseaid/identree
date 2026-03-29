package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"syscall"
	"text/template"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rinseaid/identree/internal/config"
)

// notifyUsersMaxSize caps the size of the per-user notification JSON file
// to prevent memory exhaustion from an accidentally large file.
const notifyUsersMaxSize = 1 << 20 // 1 MB

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

// LoadNotifyUsers reads the per-user notification URL mapping from a JSON file.
// Returns nil map (not error) if the file doesn't exist or is empty — this is
// the normal case when per-user routing is not configured.
//
// Security: uses the same hardened file-reading pattern as loadConfigFile:
// O_NOFOLLOW to reject symlinks, fd-based stat for permissions/ownership
// (no TOCTOU gap), and size limit to prevent OOM.
func LoadNotifyUsers(path string) map[string]string {
	if path == "" {
		return nil
	}

	// Open with O_NOFOLLOW to atomically reject symlinks.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("NOTIFY: cannot open users file %s: %v", path, err)
		}
		return nil
	}
	defer f.Close()

	// Use fd-based stat (not path-based) to avoid TOCTOU races.
	info, err := f.Stat()
	if err != nil {
		log.Printf("NOTIFY: cannot stat users file %s: %v", path, err)
		return nil
	}
	if !info.Mode().IsRegular() {
		log.Printf("NOTIFY: ERROR: %s is not a regular file — refusing to load", path)
		return nil
	}

	// Enforce size limit to prevent OOM from large files.
	if info.Size() > notifyUsersMaxSize {
		log.Printf("NOTIFY: ERROR: %s is too large (%d bytes, max %d) — refusing to load", path, info.Size(), notifyUsersMaxSize)
		return nil
	}

	// Enforce permissions: file may contain bot tokens and webhook secrets.
	if mode := info.Mode().Perm(); mode&0077 != 0 {
		log.Printf("NOTIFY: ERROR: %s has group/other permissions (mode %04o) — refusing to load (fix with: chmod 600 %s)", path, mode, path)
		return nil
	}

	// Enforce root ownership to prevent pre-creation attacks.
	if uid, ok := config.FileOwnerUID(info); !ok {
		log.Printf("NOTIFY: ERROR: cannot determine owner of %s — refusing to load", path)
		return nil
	} else if uid != 0 {
		log.Printf("NOTIFY: ERROR: %s is not owned by root (uid=%d) — refusing to load", path, uid)
		return nil
	}

	// Read from the already-opened fd (not the path) to maintain consistency.
	data, err := io.ReadAll(io.LimitReader(f, notifyUsersMaxSize+1))
	if err != nil {
		log.Printf("NOTIFY: cannot read users file %s: %v", path, err)
		return nil
	}

	// Strip UTF-8 BOM (common when edited on Windows).
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))

	// Empty file is valid — means no per-user routing configured.
	if len(data) == 0 {
		return nil
	}

	var users map[string]string
	if err := json.Unmarshal(data, &users); err != nil {
		log.Printf("NOTIFY: cannot parse users file %s: %v", path, err)
		return nil
	}
	return users
}

// LookupUserURLs returns the notification URL(s) for a username from the
// per-user mapping. Falls back to the "*" wildcard entry if the user has
// no explicit mapping. Returns empty string if no mapping exists.
func LookupUserURLs(users map[string]string, username string) string {
	if users == nil {
		return ""
	}
	if urls, ok := users[username]; ok {
		return urls
	}
	if urls, ok := users["*"]; ok {
		return urls
	}
	return ""
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
