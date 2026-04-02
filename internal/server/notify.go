package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/sanitize"
)

// notifyTimeout is the fallback timeout if cfg.NotifyTimeout is not set.
const notifyTimeout = 15 * time.Second

// notifyMaxOutput caps stdout/stderr from the custom notify command.
const notifyMaxOutput = 1 << 20 // 1 MB

// notifySemaphore limits concurrent notify executions.
var notifySemaphore = make(chan struct{}, 50)

// NotifyData holds the fields sent to the notification backend.
type NotifyData struct {
	Event       string // challenge_created, challenge_approved, challenge_rejected, auto_approved
	Username    string
	Hostname    string
	UserCode    string
	ApprovalURL string
	OneTapURL   string
	ExpiresIn   int
	Timestamp   string
	Reason      string
	Actor       string
}

// sendNotification fires the configured notification backend asynchronously.
// It is a no-op when no backend is configured.
func (s *Server) sendNotification(ch *challenge.Challenge, approvalURL, oneTapURL string) {
	s.cfgMu.RLock()
	backend := s.cfg.NotifyBackend
	timeout := s.cfg.NotifyTimeout
	command := s.cfg.NotifyCommand
	token := s.cfg.NotifyToken
	notifyURL := s.cfg.NotifyURL
	challengeTTL := s.cfg.ChallengeTTL
	s.cfgMu.RUnlock()

	if backend == "" {
		return
	}

	d := NotifyData{
		Event:       "challenge_created",
		Username:    ch.Username,
		Hostname:    ch.Hostname,
		UserCode:    ch.UserCode,
		ApprovalURL: approvalURL,
		OneTapURL:   oneTapURL,
		ExpiresIn:   int(challengeTTL.Seconds()),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Reason:      ch.Reason,
	}

	s.notifyMu.Lock()
	if s.notifyShutdown.Load() {
		s.notifyMu.Unlock()
		slog.Debug("notify: shutdown in progress, dropping notification", "event", d.Event)
		return
	}
	s.notifyWg.Add(1)
	s.notifyMu.Unlock()
	go func() {
		defer s.notifyWg.Done()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("NOTIFY panic recovered", "panic", r)
			}
		}()

		select {
		case notifySemaphore <- struct{}{}:
			defer func() { <-notifySemaphore }()
		default:
			notify.NotificationsTotal.WithLabelValues("skipped").Inc()
			slog.Warn("NOTIFY skipped", "reason", "too many concurrent notifications", "user", d.Username)
			return
		}

		if timeout <= 0 {
			timeout = notifyTimeout
		}

		var err error
		if backend == "custom" {
			err = s.runNotifyCommand(d, timeout, command)
		} else {
			err = s.postNotifyWebhook(d, timeout, backend, notifyURL, token)
		}

		if err != nil {
			notify.NotificationsTotal.WithLabelValues("failed").Inc()
			slog.Error("NOTIFY failed", "user", d.Username, "host", d.Hostname, "err", err)
			return
		}
		notify.NotificationsTotal.WithLabelValues("sent").Inc()
		slog.Info("NOTIFY sent", "user", d.Username, "host", d.Hostname)
	}()
}

// sendEventNotification fires a notification for non-challenge-creation events
// (approved, rejected, auto_approved, revealed_breakglass). No-op if no backend configured.
func (s *Server) sendEventNotification(d notify.WebhookData) {
	s.cfgMu.RLock()
	backend := s.cfg.NotifyBackend
	timeout := s.cfg.NotifyTimeout
	command := s.cfg.NotifyCommand
	token := s.cfg.NotifyToken
	notifyURL := s.cfg.NotifyURL
	s.cfgMu.RUnlock()

	if backend == "" {
		return
	}
	nd := NotifyData{
		Event:     d.Event,
		Username:  d.Username,
		Hostname:  d.Hostname,
		UserCode:  d.UserCode,
		Timestamp: d.Timestamp,
		Reason:    d.Reason,
		Actor:     d.Actor,
	}
	s.notifyMu.Lock()
	if s.notifyShutdown.Load() {
		s.notifyMu.Unlock()
		slog.Debug("notify: shutdown in progress, dropping notification", "event", nd.Event)
		return
	}
	s.notifyWg.Add(1)
	s.notifyMu.Unlock()
	go func() {
		defer s.notifyWg.Done()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("NOTIFY panic recovered", "panic", r)
			}
		}()

		select {
		case notifySemaphore <- struct{}{}:
			defer func() { <-notifySemaphore }()
		default:
			notify.NotificationsTotal.WithLabelValues("skipped").Inc()
			slog.Warn("NOTIFY skipped", "reason", "too many concurrent notifications", "event", nd.Event, "user", nd.Username)
			return
		}

		if timeout <= 0 {
			timeout = notifyTimeout
		}

		var err error
		if backend == "custom" {
			err = s.runNotifyCommand(nd, timeout, command)
		} else {
			err = s.postNotifyWebhook(nd, timeout, backend, notifyURL, token)
		}
		if err != nil {
			notify.NotificationsTotal.WithLabelValues("failed").Inc()
			slog.Error("NOTIFY event failed", "event", nd.Event, "user", nd.Username, "err", err)
			return
		}
		notify.NotificationsTotal.WithLabelValues("sent").Inc()
		slog.Info("NOTIFY sent", "event", nd.Event, "user", nd.Username, "host", nd.Hostname)
	}()
}

// postNotifyWebhook formats the payload for the configured backend and POSTs it,
// retrying up to 3 times with exponential backoff on transient (non-4xx) failures.
// backend, notifyURL, and token are snapshotted config values passed by the caller.
func (s *Server) postNotifyWebhook(d NotifyData, timeout time.Duration, backend, notifyURL, token string) error {
	wd := notify.WebhookData{
		Event:       d.Event,
		Username:    d.Username,
		Hostname:    d.Hostname,
		UserCode:    d.UserCode,
		ApprovalURL: d.ApprovalURL,
		OneTapURL:   d.OneTapURL,
		ExpiresIn:   d.ExpiresIn,
		Timestamp:   d.Timestamp,
		Reason:      d.Reason,
		Actor:       d.Actor,
	}

	var (
		body []byte
		err  error
	)
	switch backend {
	case "ntfy":
		body, err = notify.FormatWebhookNtfy(wd)
	case "slack":
		body, err = notify.FormatWebhookSlack(wd)
	case "discord":
		body, err = notify.FormatWebhookDiscord(wd)
	case "apprise":
		body, err = notify.FormatWebhookApprise(wd)
	default: // "webhook" or unrecognised
		body, err = notify.FormatWebhookRaw(wd)
	}
	if err != nil {
		return fmt.Errorf("formatting payload: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<uint(attempt-1)) * time.Second) // 1s, 2s
		}
		lastErr = s.sendWebhookOnce(body, timeout, notifyURL, token)
		if lastErr == nil {
			return nil
		}
		// Don't retry on 4xx responses — they indicate a permanent client error
		// (bad URL, bad token, etc.) that retrying won't fix.
		if isPermanentWebhookError(lastErr) {
			return lastErr
		}
		slog.Warn("notify: webhook attempt failed", "attempt", attempt+1, "err", lastErr)
	}
	return lastErr
}

// isPermanentWebhookError reports whether err was caused by a 4xx HTTP response.
func isPermanentWebhookError(err error) bool {
	if err == nil {
		return false
	}
	// webhookStatusError is set by sendWebhookOnce for HTTP-level failures.
	var se *webhookStatusError
	return errors.As(err, &se) && se.status >= 400 && se.status < 500
}

// webhookStatusError carries the HTTP status code from a failed webhook delivery.
type webhookStatusError struct {
	status int
	body   string
}

func (e *webhookStatusError) Error() string {
	return fmt.Sprintf("server returned %d: %s", e.status, e.body)
}

// sendWebhookOnce performs a single HTTP POST of body to notifyURL.
func (s *Server) sendWebhookOnce(body []byte, timeout time.Duration, notifyURL, token string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, notifyURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := s.webhookClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return &webhookStatusError{status: resp.StatusCode, body: sanitize.ForTerminal(string(respBody))}
	}
	return nil
}

// sanitizeEnvVal strips control characters and non-printable bytes from s so
// it is safe to place in a shell environment variable. Only printable ASCII
// (0x20–0x7E) is retained; everything else (including \n, \r, \0) is dropped.
func sanitizeEnvVal(s string) string {
	var b strings.Builder
	for _, ch := range s {
		if ch >= 0x20 && ch <= 0x7E {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

// runNotifyCommand executes the custom notify command with NOTIFY_* env vars.
// command is the snapshotted config value passed by the caller.
func (s *Server) runNotifyCommand(d NotifyData, timeout time.Duration, command string) error {
	// Validate user-controlled values before placing them in the shell environment.
	// Even though env vars aren't interpolated by sh -c directly, a command that
	// echoes $NOTIFY_HOSTNAME or $NOTIFY_USERNAME into a sub-invocation could
	// still be exploited if the values contain shell metacharacters.
	if !validHostname.MatchString(d.Hostname) || !validUsername.MatchString(d.Username) {
		slog.Error("notify: custom backend: refusing to execute with invalid hostname/username",
			"hostname", d.Hostname, "username", d.Username)
		return fmt.Errorf("notify: invalid hostname or username for custom backend")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	effectiveURL := d.ApprovalURL
	if d.OneTapURL != "" {
		effectiveURL = d.OneTapURL
	}

	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"NOTIFY_EVENT=" + sanitizeEnvVal(d.Event),
		"NOTIFY_USERNAME=" + d.Username,
		"NOTIFY_HOSTNAME=" + d.Hostname,
		"NOTIFY_USER_CODE=" + sanitizeEnvVal(d.UserCode),
		"NOTIFY_APPROVAL_URL=" + sanitizeEnvVal(effectiveURL),
		"NOTIFY_ONETAP_URL=" + sanitizeEnvVal(d.OneTapURL),
		"NOTIFY_EXPIRES_IN=" + strconv.Itoa(d.ExpiresIn),
		"NOTIFY_TIMESTAMP=" + sanitizeEnvVal(d.Timestamp),
		"NOTIFY_REASON=" + sanitizeEnvVal(d.Reason),
		"NOTIFY_ACTOR=" + sanitizeEnvVal(d.Actor),
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdoutBuf, n: notifyMaxOutput}
	cmd.Stderr = &limitedWriter{w: &stderrBuf, n: notifyMaxOutput}

	if err := cmd.Run(); err != nil {
		combined := truncateOutput(stdoutBuf.String() + stderrBuf.String())
		return fmt.Errorf("command failed: %w (output: %s)", err, combined)
	}
	return nil
}

// WaitForNotifications blocks until all in-flight notification goroutines
// complete or the timeout expires.
func (s *Server) WaitForNotifications(timeout time.Duration) {
	s.notifyMu.Lock()
	s.notifyShutdown.Store(true)
	s.notifyMu.Unlock()
	done := make(chan struct{})
	go func() {
		s.notifyWg.Wait()
		close(done)
	}()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
		slog.Warn("NOTIFY timed out waiting for notifications", "timeout", timeout)
	}
}
