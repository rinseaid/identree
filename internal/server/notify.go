package server

import (
	"log/slog"
	"time"

	"github.com/rinseaid/identree/internal/audit"
	"github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/notify"
)

// notifyTimeout is the fallback timeout if cfg.NotifyTimeout is not set.
const notifyTimeout = 15 * time.Second

// notifySemaphore limits concurrent notify executions.
var notifySemaphore = make(chan struct{}, 50)

// emitAuditEvent sends a structured event to all configured audit sinks.
// It is a no-op when no audit streamer is configured.
func (s *Server) emitAuditEvent(event, username, hostname, code, actor, reason string) {
	if s.audit == nil {
		return
	}
	s.audit.Emit(audit.NewEvent(event, username, hostname, code, actor, reason, version))
}

// dispatchNotification evaluates notification routing rules and admin preferences,
// then delivers the notification to all matching channels asynchronously.
// Audit events are always emitted regardless of notification configuration.
func (s *Server) dispatchNotification(d notify.WebhookData) {
	// Always emit to audit sinks.
	s.emitAuditEvent(d.Event, d.Username, d.Hostname, d.UserCode, d.Actor, d.Reason)

	// Collect matching channels from org-level routes.
	channels := notify.EvaluateRoutes(s.notifyRoutes(), d.Event, d.Hostname, d.Username)

	// Collect matching channels from per-admin preferences.
	if s.adminNotifyStore != nil {
		for ch := range s.adminNotifyStore.MatchingChannels(d.Event, d.Hostname, d.Username) {
			channels[ch] = true
		}
	}

	if len(channels) == 0 {
		return
	}

	// Resolve channel names to channel configs.
	channelMap := s.notifyChannelMap()
	timeout := s.notifyDefaultTimeout()

	for chName := range channels {
		ch, ok := channelMap[chName]
		if !ok {
			slog.Warn("notify: unknown channel in route", "channel", chName)
			continue
		}
		s.deliverToChannel(ch, d, timeout)
	}
}

// sendChallengeNotification is the dispatch entry point for challenge_created events.
// It constructs WebhookData from the challenge and fires dispatchNotification.
func (s *Server) sendChallengeNotification(ch *challenge.Challenge, approvalURL, oneTapURL string) {
	s.cfgMu.RLock()
	challengeTTL := s.cfg.ChallengeTTL
	s.cfgMu.RUnlock()

	s.dispatchNotification(notify.WebhookData{
		Event:       "challenge_created",
		Username:    ch.Username,
		Hostname:    ch.Hostname,
		UserCode:    ch.UserCode,
		ApprovalURL: approvalURL,
		OneTapURL:   oneTapURL,
		ExpiresIn:   int(challengeTTL.Seconds()),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Reason:      ch.Reason,
	})
}

// deliverToChannel sends a notification to a single channel asynchronously.
func (s *Server) deliverToChannel(ch notify.Channel, d notify.WebhookData, defaultTimeout time.Duration) {
	s.notifyMu.Lock()
	if s.notifyShutdown.Load() {
		s.notifyMu.Unlock()
		slog.Debug("notify: shutdown in progress, dropping notification", "channel", ch.Name, "event", d.Event)
		return
	}
	s.notifyWg.Add(1)
	s.notifyMu.Unlock()

	go func() {
		defer s.notifyWg.Done()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("NOTIFY panic recovered", "channel", ch.Name, "panic", r)
			}
		}()

		select {
		case notifySemaphore <- struct{}{}:
			defer func() { <-notifySemaphore }()
		default:
			notify.NotificationsTotal.WithLabelValues("skipped", ch.Name).Inc()
			slog.Warn("NOTIFY skipped", "reason", "too many concurrent", "channel", ch.Name, "event", d.Event)
			return
		}

		if err := notify.Deliver(ch, d, defaultTimeout); err != nil {
			notify.NotificationsTotal.WithLabelValues("failed", ch.Name).Inc()
			slog.Error("NOTIFY failed", "channel", ch.Name, "event", d.Event, "err", err)
			return
		}
		notify.NotificationsTotal.WithLabelValues("sent", ch.Name).Inc()
		slog.Info("NOTIFY sent", "channel", ch.Name, "event", d.Event, "user", d.Username, "host", d.Hostname)
	}()
}

// notifyRoutes returns a copy of the current notification routes (thread-safe).
func (s *Server) notifyRoutes() []notify.Route {
	s.notifyCfgMu.RLock()
	defer s.notifyCfgMu.RUnlock()
	out := make([]notify.Route, len(s.notifyCfg.Routes))
	copy(out, s.notifyCfg.Routes)
	return out
}

// notifyChannelMap returns a name→Channel lookup (thread-safe).
func (s *Server) notifyChannelMap() map[string]notify.Channel {
	s.notifyCfgMu.RLock()
	defer s.notifyCfgMu.RUnlock()
	m := make(map[string]notify.Channel, len(s.notifyCfg.Channels))
	for _, ch := range s.notifyCfg.Channels {
		m[ch.Name] = ch
	}
	return m
}

// notifyDefaultTimeout returns the configured default notification timeout.
func (s *Server) notifyDefaultTimeout() time.Duration {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	if s.cfg.NotifyTimeout > 0 {
		return s.cfg.NotifyTimeout
	}
	return notifyTimeout
}

// reloadNotificationConfig reloads the notification channels and routes from disk.
func (s *Server) reloadNotificationConfig() {
	s.cfgMu.RLock()
	path := s.cfg.NotificationConfigFile
	s.cfgMu.RUnlock()

	cfg, err := notify.LoadNotificationConfig(path)
	if err != nil {
		slog.Error("notify: failed to reload config", "path", path, "err", err)
		return
	}
	notify.InjectChannelSecrets(cfg.Channels)

	s.notifyCfgMu.Lock()
	s.notifyCfg = cfg
	s.notifyCfgMu.Unlock()
	slog.Info("notify: config reloaded", "channels", len(cfg.Channels), "routes", len(cfg.Routes))
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
