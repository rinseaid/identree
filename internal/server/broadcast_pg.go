package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// pgListenBroadcaster fans events out across HA Postgres replicas using
// LISTEN/NOTIFY. The same instance:
//
//   - delivers events to local SSE subscribers (so a single-replica
//     deployment behaves identically),
//   - publishes a NOTIFY on either the SSE or cluster channel so peer
//     replicas receive the event,
//   - holds a dedicated pgx.Conn (separate from the database/sql pool)
//     in a background goroutine that LISTENs for incoming notifications.
//
// Postgres caps NOTIFY payloads at 8000 bytes. Anything larger is written
// to the cluster_messages table and the row id is published instead;
// the receiver looks the row up by id, applies the message, and lets the
// reaper trim old rows on its next sweep.
type pgListenBroadcaster struct {
	server *Server
	dsn    string
	db     *sql.DB

	stopCh chan struct{}
	stopWg sync.WaitGroup

	// publishMu serialises NOTIFY-issuing calls so we don't hold two
	// connections in flight when bursts of events fire from concurrent
	// handlers. NOTIFY itself is fast; this just bounds connection churn.
	publishMu sync.Mutex
}

const (
	pgChannelSSE     = "identree_sse"
	pgChannelCluster = "identree_cluster"

	// pgInlineMax is the body size we'll inline in a NOTIFY payload.
	// Postgres's hard cap is 8000 bytes; we leave slack for JSON wrapping
	// and the {"row":N} overflow envelope.
	pgInlineMax = 6000
)

// newPgListenBroadcaster constructs and starts the listener goroutine.
// The caller is responsible for calling Close() at shutdown.
func newPgListenBroadcaster(s *Server, dsn string, db *sql.DB) *pgListenBroadcaster {
	b := &pgListenBroadcaster{
		server: s,
		dsn:    dsn,
		db:     db,
		stopCh: make(chan struct{}),
	}
	b.stopWg.Add(1)
	go b.listenLoop()
	return b
}

// ── Outbound ────────────────────────────────────────────────────────────────

type ssePayload struct {
	User  string `json:"user"`
	Event string `json:"event"`
}

func (b *pgListenBroadcaster) Broadcast(username, event string) {
	// Local delivery first so this replica's subscribers don't pay the
	// LISTEN/NOTIFY round-trip.
	b.server.broadcastSSE(username, event)

	payload, err := json.Marshal(ssePayload{User: username, Event: event})
	if err != nil {
		slog.Error("pg broadcast: marshal", "err", err)
		return
	}
	b.publish(pgChannelSSE, string(payload))
}

func (b *pgListenBroadcaster) PublishCluster(msg clusterMessage) {
	payload, err := json.Marshal(msg)
	if err != nil {
		slog.Error("pg cluster: marshal", "err", err)
		return
	}
	b.publish(pgChannelCluster, string(payload))
}

// publish issues a NOTIFY. Payloads above pgInlineMax are spooled to the
// cluster_messages table and the NOTIFY carries a {"row":N} envelope.
func (b *pgListenBroadcaster) publish(channel, payload string) {
	b.publishMu.Lock()
	defer b.publishMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if len(payload) > pgInlineMax {
		var rowID int64
		err := b.db.QueryRowContext(ctx,
			`INSERT INTO cluster_messages (topic, payload, created_at) VALUES ($1, $2, $3) RETURNING id`,
			channel, payload, time.Now().Unix()).Scan(&rowID)
		if err != nil {
			slog.Error("pg publish: spool to cluster_messages", "err", err)
			return
		}
		payload = `{"row":` + strconv.FormatInt(rowID, 10) + `}`
	}

	// pq_notify is parameterless; payload must be inlined as a quoted
	// literal. We control the channel name (constant) and the payload is
	// JSON, but quote it defensively anyway.
	if _, err := b.db.ExecContext(ctx, "SELECT pg_notify($1, $2)", channel, payload); err != nil {
		slog.Warn("pg publish: NOTIFY", "channel", channel, "err", err)
	}
}

// ── Inbound ─────────────────────────────────────────────────────────────────

func (b *pgListenBroadcaster) listenLoop() {
	defer b.stopWg.Done()
	backoff := time.Second
	for {
		select {
		case <-b.stopCh:
			return
		default:
		}

		err := b.listenOnce()
		if err == nil {
			return // graceful shutdown
		}
		slog.Warn("pg listen: disconnected", "err", err, "backoff", backoff)

		select {
		case <-b.stopCh:
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// listenOnce holds a dedicated pgx.Conn for the lifetime of a single
// LISTEN session. Returns nil on graceful shutdown, error on failure
// (caller will reconnect with backoff).
func (b *pgListenBroadcaster) listenOnce() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Cancel the listener context when stopCh closes so WaitForNotification
	// unblocks.
	go func() {
		select {
		case <-b.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	conn, err := pgx.Connect(ctx, b.dsn)
	if err != nil {
		return fmt.Errorf("pgx connect: %w", err)
	}
	defer conn.Close(context.Background())

	if _, err := conn.Exec(ctx, "LISTEN "+pgChannelSSE); err != nil {
		return fmt.Errorf("LISTEN sse: %w", err)
	}
	if _, err := conn.Exec(ctx, "LISTEN "+pgChannelCluster); err != nil {
		return fmt.Errorf("LISTEN cluster: %w", err)
	}
	slog.Info("pg listen: subscribed", "channels", []string{pgChannelSSE, pgChannelCluster})

	for {
		notification, err := conn.WaitForNotification(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil // graceful shutdown
			}
			return fmt.Errorf("wait: %w", err)
		}
		b.dispatch(notification.Channel, notification.Payload)
	}
}

// dispatch applies an incoming notification to local state. Overflow
// envelopes ({"row":N}) trigger a cluster_messages lookup before the
// payload is processed.
func (b *pgListenBroadcaster) dispatch(channel, payload string) {
	// Resolve overflow envelope.
	if len(payload) > 0 && payload[0] == '{' && payload[len(payload)-1] == '}' {
		var env struct {
			Row int64 `json:"row"`
		}
		if err := json.Unmarshal([]byte(payload), &env); err == nil && env.Row > 0 {
			full, err := b.fetchSpooledPayload(env.Row)
			if err != nil {
				slog.Warn("pg listen: spool fetch failed", "row", env.Row, "err", err)
				return
			}
			payload = full
		}
	}

	switch channel {
	case pgChannelSSE:
		var msg ssePayload
		if err := json.Unmarshal([]byte(payload), &msg); err != nil {
			slog.Warn("pg listen: bad sse payload", "err", err)
			return
		}
		// Deliver to local subscribers ONLY — the originating replica has
		// already done so itself.
		b.server.broadcastSSE(msg.User, msg.Event)

	case pgChannelCluster:
		b.server.applyClusterMessage(payload)
	}
}

func (b *pgListenBroadcaster) fetchSpooledPayload(rowID int64) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var payload string
	if err := b.db.QueryRowContext(ctx,
		`SELECT payload FROM cluster_messages WHERE id = $1`, rowID).Scan(&payload); err != nil {
		return "", err
	}
	return payload, nil
}

func (b *pgListenBroadcaster) Close() {
	close(b.stopCh)
	b.stopWg.Wait()
}
