package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"
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
var notifySemaphore = make(chan struct{}, 10)

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
}

// sendNotification fires the configured notification backend asynchronously.
// It is a no-op when no backend is configured.
func (s *Server) sendNotification(ch *challenge.Challenge, approvalURL, oneTapURL string) {
	if s.cfg.NotifyBackend == "" {
		return
	}

	d := NotifyData{
		Event:       "challenge_created",
		Username:    ch.Username,
		Hostname:    ch.Hostname,
		UserCode:    ch.UserCode,
		ApprovalURL: approvalURL,
		OneTapURL:   oneTapURL,
		ExpiresIn:   int(s.cfg.ChallengeTTL.Seconds()),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}

	s.notifyWg.Add(1)
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

		timeout := s.cfg.NotifyTimeout
		if timeout <= 0 {
			timeout = notifyTimeout
		}

		var err error
		if s.cfg.NotifyBackend == "custom" {
			err = s.runNotifyCommand(d, timeout)
		} else {
			err = s.postNotifyWebhook(d, timeout)
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
	if s.cfg.NotifyBackend == "" {
		return
	}
	nd := NotifyData{
		Event:     d.Event,
		Username:  d.Username,
		Hostname:  d.Hostname,
		UserCode:  d.UserCode,
		Timestamp: d.Timestamp,
	}
	s.notifyWg.Add(1)
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
			return
		}

		timeout := s.cfg.NotifyTimeout
		if timeout <= 0 {
			timeout = notifyTimeout
		}

		var err error
		if s.cfg.NotifyBackend == "custom" {
			err = s.runNotifyCommand(nd, timeout)
		} else {
			err = s.postNotifyWebhook(nd, timeout)
		}
		if err != nil {
			notify.NotificationsTotal.WithLabelValues("failed").Inc()
			slog.Error("NOTIFY event failed", "event", nd.Event, "user", nd.Username, "err", err)
			return
		}
		notify.NotificationsTotal.WithLabelValues("sent").Inc()
	}()
}

// postNotifyWebhook formats the payload for the configured backend and POSTs it.
func (s *Server) postNotifyWebhook(d NotifyData, timeout time.Duration) error {
	wd := notify.WebhookData{
		Event:       d.Event,
		Username:    d.Username,
		Hostname:    d.Hostname,
		UserCode:    d.UserCode,
		ApprovalURL: d.ApprovalURL,
		OneTapURL:   d.OneTapURL,
		ExpiresIn:   d.ExpiresIn,
		Timestamp:   d.Timestamp,
	}

	var (
		body []byte
		err  error
	)
	switch s.cfg.NotifyBackend {
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

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.NotifyURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.NotifyToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.NotifyToken)
	}

	resp, err := s.webhookClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, sanitize.ForTerminal(string(respBody)))
	}
	return nil
}

// runNotifyCommand executes the custom notify command with NOTIFY_* env vars.
func (s *Server) runNotifyCommand(d NotifyData, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	effectiveURL := d.ApprovalURL
	if d.OneTapURL != "" {
		effectiveURL = d.OneTapURL
	}

	cmd := exec.CommandContext(ctx, "sh", "-c", s.cfg.NotifyCommand)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"NOTIFY_EVENT=" + d.Event,
		"NOTIFY_USERNAME=" + d.Username,
		"NOTIFY_HOSTNAME=" + d.Hostname,
		"NOTIFY_USER_CODE=" + d.UserCode,
		"NOTIFY_APPROVAL_URL=" + effectiveURL,
		"NOTIFY_ONETAP_URL=" + d.OneTapURL,
		"NOTIFY_EXPIRES_IN=" + strconv.Itoa(d.ExpiresIn),
		"NOTIFY_TIMESTAMP=" + d.Timestamp,
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
	done := make(chan struct{})
	go func() {
		s.notifyWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		slog.Warn("NOTIFY timed out waiting for notifications", "timeout", timeout)
	}
}
