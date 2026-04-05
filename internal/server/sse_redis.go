package server

import (
	"context"
	"log/slog"
	"strings"
	"time"

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
	done   chan struct{} // closed when subscribe goroutine exits
}

func newRedisBroadcaster(server *Server, client redis.UniversalClient, prefix string) *redisBroadcaster {
	ctx, cancel := context.WithCancel(context.Background())
	b := &redisBroadcaster{
		server: server,
		client: client,
		prefix: prefix,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go func() {
		defer close(b.done)
		b.subscribe(ctx)
	}()
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
	// Wait for the subscriber goroutine to exit before closing the client,
	// preventing it from accessing a closed Redis connection.
	<-b.done
	if b.client != nil {
		b.client.Close()
	}
}

// subscribe listens for SSE events from Redis pub/sub and delivers them
// to the local SSE channels. Reconnects with exponential backoff on failure.
func (b *redisBroadcaster) subscribe(ctx context.Context) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		b.subscribeOnce(ctx)

		// If context was cancelled, exit cleanly.
		if ctx.Err() != nil {
			return
		}

		slog.Warn("redis SSE subscriber disconnected, reconnecting", "backoff", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

// subscribeOnce runs a single subscription session until the channel closes
// or the context is cancelled.
func (b *redisBroadcaster) subscribeOnce(ctx context.Context) {
	pubsub := b.client.Subscribe(ctx, b.prefix+"sse")
	defer pubsub.Close()

	ch := pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return // channel closed — trigger reconnect
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
