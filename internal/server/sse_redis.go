package server

import (
	"context"
	"log/slog"
	"strings"

	"github.com/redis/go-redis/v9"
)

// redisBroadcaster publishes SSE events to a Redis pub/sub channel so that
// all identree instances in a cluster deliver the event to their local SSE
// subscribers.
type redisBroadcaster struct {
	server *Server
	client redis.UniversalClient
	prefix string
	cancel context.CancelFunc
}

func newRedisBroadcaster(server *Server, client redis.UniversalClient, prefix string) *redisBroadcaster {
	ctx, cancel := context.WithCancel(context.Background())
	b := &redisBroadcaster{
		server: server,
		client: client,
		prefix: prefix,
		cancel: cancel,
	}
	go b.subscribe(ctx)
	return b
}

// Broadcast publishes an SSE event to the Redis channel. All instances
// (including the local one) receive it via the subscription goroutine.
func (b *redisBroadcaster) Broadcast(username, event string) {
	payload := username + "|" + event
	if err := b.client.Publish(context.Background(), b.prefix+"sse", payload).Err(); err != nil {
		slog.Warn("redis SSE publish failed, falling back to local delivery", "err", err)
		// Fall back to local delivery so the current instance still works.
		b.server.broadcastSSE(username, event)
	}
}

func (b *redisBroadcaster) Close() {
	b.cancel()
}

// subscribe listens for SSE events from Redis pub/sub and delivers them
// to the local SSE channels.
func (b *redisBroadcaster) subscribe(ctx context.Context) {
	pubsub := b.client.Subscribe(ctx, b.prefix+"sse")
	defer pubsub.Close()

	ch := pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			// Parse "username|event" payload.
			parts := strings.SplitN(msg.Payload, "|", 2)
			if len(parts) != 2 {
				continue
			}
			b.server.broadcastSSE(parts[0], parts[1])
		}
	}
}
