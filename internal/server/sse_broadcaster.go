package server

// SSEBroadcaster abstracts cross-replica event delivery. Two implementations:
//
//   - localBroadcaster: in-process delivery only. Used when DatabaseDriver
//     is "sqlite" — there are no peer replicas to inform.
//   - pgListenBroadcaster: delivers locally and via Postgres LISTEN/NOTIFY
//     so every replica behind a load balancer sees the same events.
//
// Two channels: "identree_sse" (per-user dashboard refreshes) and
// "identree_cluster" (admin-session revocations, notify config reloads).
// Payloads above ~7 KB spill into a cluster_messages row and are
// referenced by id in the NOTIFY payload, working around Postgres's
// 8000-byte notification limit.
type SSEBroadcaster interface {
	Broadcast(username, event string)
	PublishCluster(msg clusterMessage)
	Close()
}

// localBroadcaster wraps the Server's existing broadcastSSE logic for
// single-instance deployments. Cluster messages are no-ops because this
// replica is the only one that needs to know.
type localBroadcaster struct {
	server *Server
}

func (b *localBroadcaster) Broadcast(username, event string) {
	b.server.broadcastSSE(username, event)
}

func (b *localBroadcaster) PublishCluster(_ clusterMessage) {
	// Single-node: this replica's in-memory state is already authoritative
	// (handlers updated it before publishing). Nothing to fan out.
}

func (b *localBroadcaster) Close() {
	// No-op for local broadcaster.
}
