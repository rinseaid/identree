package server

// SSEBroadcaster abstracts the mechanism for broadcasting SSE events.
// The local implementation delivers directly to in-process SSE channels.
// A Postgres LISTEN/NOTIFY implementation will fan events out across
// HA replicas in a follow-up commit.
type SSEBroadcaster interface {
	Broadcast(username, event string)
	Close()
}

// localBroadcaster wraps the Server's existing broadcastSSE logic for
// single-instance deployments.
type localBroadcaster struct {
	server *Server
}

func (b *localBroadcaster) Broadcast(username, event string) {
	b.server.broadcastSSE(username, event)
}

func (b *localBroadcaster) Close() {
	// No-op for local broadcaster.
}
