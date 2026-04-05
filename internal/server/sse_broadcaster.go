package server

// SSEBroadcaster abstracts the mechanism for broadcasting SSE events.
// The local implementation delivers directly to in-process SSE channels.
// The Redis implementation publishes to a Redis pub/sub channel so all
// identree instances in a cluster receive the event.
type SSEBroadcaster interface {
	Broadcast(username, event string)
	Close()
}

// localBroadcaster wraps the Server's existing broadcastSSE logic for
// single-instance deployments (state backend = "local").
type localBroadcaster struct {
	server *Server
}

func (b *localBroadcaster) Broadcast(username, event string) {
	b.server.broadcastSSE(username, event)
}

func (b *localBroadcaster) Close() {
	// No-op for local broadcaster.
}
