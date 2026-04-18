package server

// Cluster control messages coordinate cross-replica state in HA deployments
// (revoked session nonces, revoked admin sessions, notify config reloads).
//
// v1 single-node behaviour: publishClusterMessage is a no-op. SQLite is
// single-node by definition, so there are no peers to inform; the local
// in-memory state is already authoritative for the current process.
//
// Multi-replica behaviour ships in a follow-up commit, where the Postgres
// LISTEN/NOTIFY broadcaster will deliver these messages to peer replicas.

type clusterMessage struct {
	Type     string `json:"type"`               // "revoke_nonce", "revoke_admin", "reload_notify_config"
	Nonce    string `json:"nonce,omitempty"`    // for revoke_nonce
	Username string `json:"username,omitempty"` // for revoke_admin
}

// publishClusterMessage emits a cluster control message to all peer replicas.
// In v1 single-node mode this is a no-op; the LISTEN/NOTIFY broadcaster
// will replace this implementation for HA Postgres deployments.
func (s *Server) publishClusterMessage(msg clusterMessage) {
	_ = msg
}
