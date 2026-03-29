package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/notify"
)

// notifyTimeout is the default timeout for the notify command.
// Overridden at runtime by s.cfg.NotifyTimeout (IDENTREE_NOTIFY_TIMEOUT).
const notifyTimeout = 15 * time.Second

// notifyMaxOutput caps the amount of stdout/stderr we read from the notify
// command to prevent a verbose or malicious command from exhausting memory.
const notifyMaxOutput = 1 << 20 // 1 MB

// notifySemaphore limits concurrent notify command executions to prevent
// resource exhaustion if challenges arrive in bursts.
var notifySemaphore = make(chan struct{}, 10)

// sendNotification fires the configured notify command asynchronously when a
// new challenge is created. It is a no-op if no notify command is configured.
// Runs in a goroutine so it never blocks the challenge API response.
// The WaitGroup tracks in-flight goroutines for graceful shutdown.
func (s *Server) sendNotification(ch *challenge.Challenge, approvalURL string, oneTapURL string) {
	if s.cfg.NotifyCommand == "" {
		return
	}

	// Capture values for the goroutine (challenge pointer may be mutated later).
	username := ch.Username
	hostname := ch.Hostname
	userCode := ch.UserCode
	expiresIn := int(s.cfg.ChallengeTTL.Seconds())
	notifyCmd := s.cfg.NotifyCommand
	notifyEnv := s.cfg.NotifyEnvPassthrough
	notifyUsersFile := s.cfg.NotifyUsersFile
	notifyUsersInline := s.cfg.NotifyUsers

	s.notifyWg.Add(1)
	go func() {
		defer s.notifyWg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("NOTIFY: panic (recovered): %v", r)
			}
		}()

		// Limit concurrency to prevent resource exhaustion.
		select {
		case notifySemaphore <- struct{}{}:
			defer func() { <-notifySemaphore }()
		default:
			notify.NotificationsTotal.WithLabelValues("skipped").Inc()
			log.Printf("NOTIFY: skipped for user %q on host %q — too many concurrent notifications", username, hostname)
			return
		}

		timeout := s.cfg.NotifyTimeout
		if timeout <= 0 {
			timeout = notifyTimeout
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Note: exec.CommandContext kills the direct child on timeout but not
		// grandchildren. Avoid notify commands that fork background processes.
		cmd := exec.CommandContext(ctx, "sh", "-c", notifyCmd)

		// Look up per-user notification URLs.
		var userURLs string
		if notifyUsersInline != nil {
			userURLs = notify.LookupUserURLs(notifyUsersInline, username)
		} else {
			userURLs = notify.LookupUserURLs(notify.LoadNotifyUsers(notifyUsersFile), username)
		}

		if (notifyUsersFile != "" || notifyUsersInline != nil) && userURLs == "" {
			log.Printf("NOTIFY: no per-user mapping for %q (NOTIFY_USER_URLS will be empty)", username)
		}

		effectiveApprovalURL := approvalURL
		if oneTapURL != "" {
			effectiveApprovalURL = oneTapURL
		}
		cmdEnv := []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + os.Getenv("HOME"),
			"NOTIFY_USERNAME=" + username,
			"NOTIFY_HOSTNAME=" + hostname,
			"NOTIFY_USER_CODE=" + userCode,
			"NOTIFY_APPROVAL_URL=" + effectiveApprovalURL,
			"NOTIFY_EXPIRES_IN=" + fmt.Sprintf("%d", expiresIn),
			"NOTIFY_USER_URLS=" + userURLs,
			"NOTIFY_ONETAP_URL=" + oneTapURL,
		}

		if len(notifyEnv) > 0 {
			for _, env := range os.Environ() {
				if strings.HasPrefix(env, "PATH=") || strings.HasPrefix(env, "HOME=") || strings.HasPrefix(env, "NOTIFY_") {
					continue
				}
				for _, prefix := range notifyEnv {
					if prefix != "" && strings.HasPrefix(env, prefix) {
						cmdEnv = append(cmdEnv, env)
						break
					}
				}
			}
		}
		cmd.Env = cmdEnv

		var stdoutBuf, stderrBuf bytes.Buffer
		cmd.Stdout = &limitedWriter{w: &stdoutBuf, n: notifyMaxOutput}
		cmd.Stderr = &limitedWriter{w: &stderrBuf, n: notifyMaxOutput}

		err := cmd.Run()
		if err != nil {
			notify.NotificationsTotal.WithLabelValues("failed").Inc()
			combined := truncateOutput(stdoutBuf.String() + stderrBuf.String())
			log.Printf("NOTIFY: command failed for user %q on host %q: %v (output: %s)", username, hostname, err, combined)
			return
		}
		notify.NotificationsTotal.WithLabelValues("sent").Inc()
		log.Printf("NOTIFY: sent for user %q on host %q", username, hostname)
	}()
}

// sendWebhookNotifications fires each configured webhook in its own goroutine.
// It is a no-op when no webhooks are configured.
func (s *Server) sendWebhookNotifications(d notify.WebhookData) {
	for _, wh := range s.cfg.Webhooks {
		s.notifyWg.Add(1)
		go func(wh config.WebhookConfig) {
			defer s.notifyWg.Done()
			s.fireWebhook(wh, d)
		}(wh)
	}
}

// fireWebhook formats and delivers a single webhook. Errors are logged but
// never returned — callers should not depend on delivery success.
func (s *Server) fireWebhook(wh config.WebhookConfig, d notify.WebhookData) {
	var (
		body []byte
		err  error
	)

	switch wh.Format {
	case "apprise":
		body, err = notify.FormatWebhookApprise(d)
	case "discord":
		body, err = notify.FormatWebhookDiscord(d)
	case "slack":
		body, err = notify.FormatWebhookSlack(d)
	case "ntfy":
		body, err = notify.FormatWebhookNtfy(d)
	case "custom":
		body, err = notify.FormatWebhookCustom(d, wh.Template)
	default: // "raw" or unrecognised — fall back to raw
		body, err = notify.FormatWebhookRaw(d)
	}

	if err != nil {
		log.Printf("ERROR: formatting webhook (format=%q): %v", wh.Format, err)
		return
	}

	webhookTimeout := s.cfg.WebhookTimeout
	if webhookTimeout <= 0 {
		webhookTimeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), webhookTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(body))
	if err != nil {
		log.Printf("ERROR: creating webhook request (format=%q): %v", wh.Format, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range wh.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.webhookClient.Do(req)
	if err != nil {
		log.Printf("ERROR: webhook (format=%q) delivery failed: %v", wh.Format, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		log.Printf("ERROR: webhook (format=%q) returned %d: %s", wh.Format, resp.StatusCode, string(respBody))
	}
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
		log.Printf("NOTIFY: timed out waiting for %s — some notifications may not have completed", timeout)
	}
}
