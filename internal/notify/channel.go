package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rinseaid/identree/internal/sanitize"
)

// Channel is a named notification destination with resolved delivery parameters.
type Channel struct {
	Name    string `json:"name"`              // unique identifier, e.g. "ops-slack"
	Backend string `json:"backend"`           // ntfy | slack | discord | apprise | webhook | custom
	URL     string `json:"url,omitempty"`     // webhook URL (all backends except custom)
	Token   string `json:"token,omitempty"`   // optional Bearer token (env-only in practice)
	Command string `json:"command,omitempty"` // custom backend only (env-only in practice)
	Timeout int    `json:"timeout,omitempty"` // per-channel timeout in seconds; 0 = use default
}

// Route determines which events are delivered to which channels.
type Route struct {
	Channels []string `json:"channels"` // channel names to deliver to
	Events   []string `json:"events"`   // event type globs ("*" = all)
	Hosts    []string `json:"hosts"`    // hostname globs (empty = all)
	Users    []string `json:"users"`    // requesting-user globs (empty = all)
}

// NotificationConfig holds the full notification configuration loaded from JSON.
type NotificationConfig struct {
	Channels []Channel `json:"channels"`
	Routes   []Route   `json:"routes"`
}

// LoadNotificationConfig reads the notification config from a JSON file.
// Returns an empty config (not an error) if the file does not exist.
// Uses O_NOFOLLOW to prevent symlink-based attacks, consistent with other state files.
func LoadNotificationConfig(path string) (*NotificationConfig, error) {
	cfg := &NotificationConfig{}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("notify: open %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("notify: stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("notify: %s is not a regular file", path)
	}
	if mode := info.Mode().Perm(); mode&0022 != 0 {
		return nil, fmt.Errorf("notify: %s is group/world writable (mode %04o)", path, mode)
	}
	data, err := io.ReadAll(io.LimitReader(f, 4<<20)) // 4 MiB limit
	if err != nil {
		return nil, fmt.Errorf("notify: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("notify: parse %s: %w", path, err)
	}
	return cfg, nil
}

// SaveNotificationConfig writes the notification config atomically to a JSON file.
func SaveNotificationConfig(path string, cfg *NotificationConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("notify: marshal config: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("notify: create config dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".notify-config-*.json")
	if err != nil {
		return fmt.Errorf("notify: create temp file: %w", err)
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

// InjectChannelSecrets populates Token and Command fields from environment
// variables. For a channel named "ops-slack", it checks:
//   - IDENTREE_NOTIFY_CHANNEL_OPS_SLACK_TOKEN
//   - IDENTREE_NOTIFY_CHANNEL_OPS_SLACK_COMMAND
func InjectChannelSecrets(channels []Channel) {
	for i := range channels {
		envName := channelEnvPrefix(channels[i].Name)
		if t := os.Getenv(envName + "_TOKEN"); t != "" {
			channels[i].Token = t
		}
		if c := os.Getenv(envName + "_COMMAND"); c != "" {
			channels[i].Command = c
		}
	}
}

func channelEnvPrefix(name string) string {
	s := strings.ToUpper(name)
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, ".", "_")
	return "IDENTREE_NOTIFY_CHANNEL_" + s
}

// MatchesGlob checks if s matches any of the given glob patterns.
// An empty pattern list matches everything.
func MatchesGlob(s string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if matched, _ := filepath.Match(p, s); matched {
			return true
		}
		if p == "*" {
			return true
		}
	}
	return false
}

// EvaluateRoutes returns the set of channel names that should receive a
// notification for the given event context.
func EvaluateRoutes(routes []Route, event, hostname, username string) map[string]bool {
	channels := make(map[string]bool)
	for _, r := range routes {
		if !MatchesGlob(event, r.Events) {
			continue
		}
		if !MatchesGlob(hostname, r.Hosts) {
			continue
		}
		if !MatchesGlob(username, r.Users) {
			continue
		}
		for _, ch := range r.Channels {
			channels[ch] = true
		}
	}
	return channels
}

// Deliver sends a notification to a single channel. It handles formatting
// and HTTP POST (or command execution) with retry logic.
func Deliver(ch Channel, data WebhookData, defaultTimeout time.Duration) error {
	timeout := defaultTimeout
	if ch.Timeout > 0 {
		timeout = time.Duration(ch.Timeout) * time.Second
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	if ch.Backend == "custom" {
		return runChannelCommand(ch, data, timeout)
	}
	return postChannelWebhook(ch, data, timeout)
}

func postChannelWebhook(ch Channel, data WebhookData, timeout time.Duration) error {
	var (
		body []byte
		err  error
	)
	switch ch.Backend {
	case "ntfy":
		body, err = FormatWebhookNtfy(data)
	case "slack":
		body, err = FormatWebhookSlack(data)
	case "discord":
		body, err = FormatWebhookDiscord(data)
	case "apprise":
		body, err = FormatWebhookApprise(data)
	default:
		body, err = FormatWebhookRaw(data)
	}
	if err != nil {
		return fmt.Errorf("formatting payload for %s: %w", ch.Name, err)
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<uint(attempt-1)) * time.Second)
		}
		lastErr = postWebhookOnce(body, timeout, ch.URL, ch.Token)
		if lastErr == nil {
			return nil
		}
		var se *WebhookStatusError
		if errors.As(lastErr, &se) && se.Status >= 400 && se.Status < 500 {
			return lastErr // permanent error, don't retry
		}
		slog.Warn("notify: webhook attempt failed", "channel", ch.Name, "attempt", attempt+1, "err", lastErr)
	}
	return lastErr
}

func postWebhookOnce(body []byte, timeout time.Duration, url, token string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := WebhookClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return &WebhookStatusError{Status: resp.StatusCode, Body: sanitize.ForTerminal(string(respBody))}
	}
	return nil
}

// WebhookStatusError carries the HTTP status code from a failed webhook delivery.
type WebhookStatusError struct {
	Status int
	Body   string
}

func (e *WebhookStatusError) Error() string {
	return fmt.Sprintf("server returned %d: %s", e.Status, e.Body)
}

// ── Custom command execution ─────────────────────────────────────────────────

const maxCommandOutput = 1 << 20 // 1 MB

func runChannelCommand(ch Channel, data WebhookData, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	effectiveURL := data.ApprovalURL
	if data.OneTapURL != "" {
		effectiveURL = data.OneTapURL
	}

	cmd := exec.CommandContext(ctx, "sh", "-c", ch.Command)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"NOTIFY_CHANNEL=" + sanitizeEnv(ch.Name),
		"NOTIFY_EVENT=" + sanitizeEnv(data.Event),
		"NOTIFY_USERNAME=" + sanitizeEnv(data.Username),
		"NOTIFY_HOSTNAME=" + sanitizeEnv(data.Hostname),
		"NOTIFY_USER_CODE=" + sanitizeEnv(data.UserCode),
		"NOTIFY_APPROVAL_URL=" + sanitizeEnv(effectiveURL),
		"NOTIFY_ONETAP_URL=" + sanitizeEnv(data.OneTapURL),
		"NOTIFY_EXPIRES_IN=" + strconv.Itoa(data.ExpiresIn),
		"NOTIFY_TIMESTAMP=" + sanitizeEnv(data.Timestamp),
		"NOTIFY_REASON=" + sanitizeEnv(data.Reason),
		"NOTIFY_ACTOR=" + sanitizeEnv(data.Actor),
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdoutBuf, n: maxCommandOutput}
	cmd.Stderr = &limitedWriter{w: &stderrBuf, n: maxCommandOutput}

	if err := cmd.Run(); err != nil {
		out := stdoutBuf.String() + stderrBuf.String()
		if len(out) > 500 {
			out = out[:500] + "..."
		}
		return fmt.Errorf("command %q failed: %w (output: %s)", ch.Name, err, out)
	}
	return nil
}

// limitedWriter wraps a writer and silently discards bytes beyond the limit.
type limitedWriter struct {
	w io.Writer
	n int
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.n <= 0 {
		return len(p), nil // silently discard
	}
	if len(p) > lw.n {
		p = p[:lw.n]
	}
	n, err := lw.w.Write(p)
	lw.n -= n
	return n, err
}

// sanitizeEnv strips control characters, keeping only printable ASCII.
func sanitizeEnv(s string) string {
	var b strings.Builder
	for _, ch := range s {
		if ch >= 0x20 && ch <= 0x7E {
			b.WriteRune(ch)
		}
	}
	return b.String()
}
