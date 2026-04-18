package server

import (
	"database/sql"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	challpkg "github.com/rinseaid/identree/internal/challenge"
)

// TestPgListenBroadcaster_RoundTrip exercises the full publish → NOTIFY →
// dispatch → local-broadcast path against a real Postgres. Skipped unless
// IDENTREE_TEST_BACKEND=postgres + IDENTREE_TEST_POSTGRES_DSN are set;
// CI's sqlstore-postgres job sets both.
//
// Two scenarios:
//   - small payload: inlined directly in the NOTIFY message
//   - large payload (>pgInlineMax): spooled to cluster_messages and
//     received as {"row":N}, then expanded via fetchSpooledPayload
func TestPgListenBroadcaster_RoundTrip(t *testing.T) {
	dsn, db := openTestPg(t)

	srv := &Server{
		sseClients: make(map[string][]chan string),
	}

	b := newPgListenBroadcaster(srv, dsn, db)
	t.Cleanup(b.Close)

	// Subscribe to the SSE channel as an admin so we can observe broadcasts
	// re-delivered locally when the LISTEN socket fires.
	recv := make(chan string, 32)
	srv.sseMu.Lock()
	srv.sseClients[sseAdminKey] = append(srv.sseClients[sseAdminKey], recv)
	srv.sseMu.Unlock()

	// Give the listener goroutine a moment to LISTEN before we publish.
	waitForListener(t, db)

	t.Run("inline payload", func(t *testing.T) {
		drain(recv)
		b.Broadcast("alice", "challenge_created")
		// First arrival is the local synchronous delivery.
		if got := waitFor(t, recv); got != "challenge_created" {
			t.Fatalf("local delivery: got %q", got)
		}
		// Second arrival is the round-trip from Postgres LISTEN.
		if got := waitFor(t, recv); got != "challenge_created" {
			t.Fatalf("notify roundtrip: got %q", got)
		}
	})

	t.Run("large payload spools through cluster_messages", func(t *testing.T) {
		drain(recv)
		large := strings.Repeat("X", pgInlineMax+500)

		// PublishCluster with a fabricated message that has an oversized
		// Username — pgInlineMax is well above any real message but the
		// envelope path is what we want to test.
		b.PublishCluster(clusterMessage{Type: "revoke_admin", Username: large})

		// Verify the row landed in cluster_messages with the full payload.
		// (The dispatch handler reads it back via fetchSpooledPayload.)
		var rowCount int
		if err := db.QueryRow(`SELECT COUNT(*) FROM cluster_messages WHERE topic=$1`, pgChannelCluster).Scan(&rowCount); err != nil {
			t.Fatalf("query cluster_messages: %v", err)
		}
		if rowCount != 1 {
			t.Fatalf("cluster_messages row count: got %d, want 1", rowCount)
		}

		// Wait for the listener to apply the message via applyClusterMessage.
		// Verify by checking revokedAdminSessions in-memory state.
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, ok := srv.revokedAdminSessions.Load(large); ok {
				return // success
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for spooled cluster message to apply (revokedAdminSessions did not gain entry)")
	})
}

// waitForListener polls pg_stat_activity until our pgListenBroadcaster
// has issued its LISTEN. Without this, NOTIFY can fire before the
// listener subscribed and the message is dropped.
func waitForListener(t *testing.T, db *sql.DB) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		// pg_listening_channels is a per-session view; pg_stat_activity
		// joined to wait events would also work. Easier: count sessions
		// in 'idle' state with our query in their last query buffer.
		err := db.QueryRow(`
			SELECT COUNT(*) FROM pg_stat_activity
			WHERE query ILIKE 'LISTEN identree_%' OR backend_type='client backend' AND state='idle' AND wait_event_type='Client'
		`).Scan(&n)
		if err == nil && n >= 1 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("warning: could not confirm listener was subscribed; test may flake")
}

func waitFor(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for SSE event")
		return ""
	}
}

func drain(ch chan string) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// openTestPg connects to the Postgres pointed to by IDENTREE_TEST_POSTGRES_DSN
// and applies the schema (so cluster_messages exists). Skips if no DSN set.
// Returns both the raw DSN (for the broadcaster) and the *sql.DB (for assertions).
func openTestPg(t *testing.T) (string, *sql.DB) {
	t.Helper()
	if os.Getenv("IDENTREE_TEST_BACKEND") != "postgres" {
		t.Skip("IDENTREE_TEST_BACKEND != postgres")
	}
	dsn := os.Getenv("IDENTREE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("IDENTREE_TEST_POSTGRES_DSN unset")
	}

	db, dialect, err := challpkg.Open(challpkg.SQLConfig{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store, err := challpkg.NewSQLStore(db, dialect, time.Minute, time.Minute)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	t.Cleanup(store.Stop)

	// Truncate cluster_messages so this test doesn't see stale rows.
	if _, err := db.Exec(`TRUNCATE TABLE cluster_messages RESTART IDENTITY`); err != nil {
		t.Fatalf("truncate cluster_messages: %v", err)
	}
	return dsn, db
}

// Compile-time guards.
var (
	_ = sync.Mutex{}
)
