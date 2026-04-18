package server

import (
	"encoding/json"
	"log/slog"
	"time"
)

// Cluster control messages coordinate cross-replica state in HA Postgres
// deployments: revoked session nonces, revoked admin sessions, and
// notify-config reloads. Single-node SQLite deployments skip the wire and
// rely on local in-memory state alone.
//
// On Postgres, messages travel over the "identree_cluster" channel via
// pgListenBroadcaster (broadcast_pg.go).

type clusterMessage struct {
	Type     string `json:"type"`               // "revoke_nonce", "revoke_admin", "reload_notify_config"
	Nonce    string `json:"nonce,omitempty"`    // for revoke_nonce
	Username string `json:"username,omitempty"` // for revoke_admin
}

// publishClusterMessage emits a cluster control message to all peer replicas.
// Locally-originated messages have already updated this replica's in-memory
// state; the publish is the cross-replica fan-out.
func (s *Server) publishClusterMessage(msg clusterMessage) {
	if s.sseBroadcaster == nil {
		return
	}
	s.sseBroadcaster.PublishCluster(msg)
}

// applyClusterMessage is invoked by pgListenBroadcaster when a NOTIFY arrives
// from a peer replica. It applies the same state mutation locally that the
// originating handler applied on the publishing replica.
//
// Nothing in this method talks to Postgres — the database is already
// up-to-date because the originating handler wrote first, then notified.
// Our job is to refresh the per-replica in-memory caches.
func (s *Server) applyClusterMessage(payload string) {
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
		}
		s.revokedNoncesMu.Unlock()

	case "revoke_admin":
		if msg.Username == "" {
			return
		}
		now := time.Now()
		if existing, loaded := s.revokedAdminSessions.Load(msg.Username); loaded {
			if t, ok := existing.(time.Time); ok && !t.Before(now) {
				return
			}
		}
		s.revokedAdminSessions.Store(msg.Username, now)

	case "reload_notify_config":
		// Deduplicate: skip if we reloaded very recently (within 1s).
		nowMS := time.Now().UnixMilli()
		if nowMS-s.clusterLastNotifyReload.Load() < 1000 {
			return
		}
		s.clusterLastNotifyReload.Store(nowMS)
		s.reloadNotificationConfig()

	default:
		slog.Debug("cluster: ignoring unknown message type", "type", msg.Type)
	}
}
