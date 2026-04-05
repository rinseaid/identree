package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// clusterMessage is a JSON message exchanged on the Redis cluster control channel.
type clusterMessage struct {
	Type     string `json:"type"`               // "revoke_nonce", "revoke_admin", "reload_notify_config"
	Nonce    string `json:"nonce,omitempty"`     // for revoke_nonce
	Username string `json:"username,omitempty"`  // for revoke_admin
}

// clusterChannelSuffix is appended to the Redis key prefix to form the pub/sub channel name.
const clusterChannelSuffix = "cluster"

// clusterReconnectMin and clusterReconnectMax control the exponential backoff
// used when the Redis subscription is lost.
const (
	clusterReconnectMin = 1 * time.Second
	clusterReconnectMax = 30 * time.Second
)

// startClusterSubscriber subscribes to the cluster control channel and applies
// incoming state-change messages to the local in-memory state. It reconnects
// with exponential backoff if the Redis connection is lost.
//
// The goroutine exits when stopCh is closed.
func (s *Server) startClusterSubscriber(client redis.UniversalClient, prefix string, stopCh <-chan struct{}) {
	channel := prefix + clusterChannelSuffix
	backoff := clusterReconnectMin

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		err := s.clusterSubscribeLoop(client, channel, stopCh)
		if err == nil {
			// Graceful exit (stopCh closed).
			return
		}

		slog.Warn("cluster subscriber disconnected, reconnecting", "err", err, "backoff", backoff)

		select {
		case <-stopCh:
			return
		case <-time.After(backoff):
		}

		// Exponential backoff, capped at clusterReconnectMax.
		backoff *= 2
		if backoff > clusterReconnectMax {
			backoff = clusterReconnectMax
		}
	}
}

// clusterSubscribeLoop runs a single subscription session. It returns nil when
// stopCh is closed, or an error if the subscription fails.
func (s *Server) clusterSubscribeLoop(client redis.UniversalClient, channel string, stopCh <-chan struct{}) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Cancel the context when stopCh is closed so the subscription unblocks.
	go func() {
		select {
		case <-stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	pubsub := client.Subscribe(ctx, channel)
	defer pubsub.Close()

	// Wait for subscription confirmation with a timeout.
	if _, err := pubsub.Receive(ctx); err != nil {
		return err
	}

	slog.Info("cluster subscriber connected", "channel", channel)

	ch := pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return nil
		case msg, ok := <-ch:
			if !ok {
				return errSubscriptionClosed
			}
			s.handleClusterMessage(msg.Payload)
		}
	}
}

// errSubscriptionClosed is a sentinel error indicating the pub/sub channel was closed.
var errSubscriptionClosed = &clusterError{"subscription channel closed"}

type clusterError struct{ msg string }

func (e *clusterError) Error() string { return e.msg }

// handleClusterMessage parses and applies a single cluster control message.
func (s *Server) handleClusterMessage(payload string) {
	var msg clusterMessage
	if err := json.Unmarshal([]byte(payload), &msg); err != nil {
		slog.Warn("cluster: ignoring malformed message", "err", err)
		return
	}

	switch msg.Type {
	case "revoke_nonce":
		if msg.Nonce == "" {
			return
		}
		s.revokedNoncesMu.Lock()
		if _, already := s.revokedNonces[msg.Nonce]; !already {
			s.revokedNonces[msg.Nonce] = time.Now()
			slog.Debug("cluster: applied nonce revocation", "nonce", msg.Nonce[:min(8, len(msg.Nonce))]+"…")
		}
		s.revokedNoncesMu.Unlock()

	case "revoke_admin":
		if msg.Username == "" {
			return
		}
		now := time.Now()
		// Only store if not already revoked at a more recent time.
		if existing, loaded := s.revokedAdminSessions.Load(msg.Username); loaded {
			if t, ok := existing.(time.Time); ok && !t.Before(now) {
				return // already revoked at same or later time
			}
		}
		s.revokedAdminSessions.Store(msg.Username, now)
		slog.Debug("cluster: applied admin session revocation", "username", msg.Username)

	case "reload_notify_config":
		// Deduplicate: skip if we reloaded very recently (within 1s).
		lastReload := s.clusterLastNotifyReload.Load()
		nowUnix := time.Now().UnixMilli()
		if nowUnix-lastReload < 1000 {
			return
		}
		s.clusterLastNotifyReload.Store(nowUnix)
		s.reloadNotificationConfig()
		slog.Debug("cluster: reloaded notification config")

	default:
		slog.Debug("cluster: ignoring unknown message type", "type", msg.Type)
	}
}

// publishClusterMessage publishes a message to the cluster control channel.
// Errors are logged but not returned — cluster sync is best-effort.
func (s *Server) publishClusterMessage(msg clusterMessage) {
	if s.clusterRedis == nil {
		return
	}
	data, err := json.Marshal(msg)
	if err != nil {
		slog.Error("cluster: failed to marshal message", "err", err)
		return
	}
	channel := s.clusterPrefix + clusterChannelSuffix
	if err := s.clusterRedis.Publish(context.Background(), channel, string(data)).Err(); err != nil {
		slog.Warn("cluster: publish failed", "type", msg.Type, "err", err)
	}
}

