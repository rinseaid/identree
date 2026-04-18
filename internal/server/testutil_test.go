package server

import (
	"testing"
	"time"

	challpkg "github.com/rinseaid/identree/internal/challenge"
)

// newTestStore returns a fresh SQL-backed challenge.Store backed by an
// in-memory SQLite for a single test. Replaces the JSON ChallengeStore
// constructor used pervasively across handler tests in the legacy code.
func newTestStore(t *testing.T, ttl, gracePeriod time.Duration) challpkg.Store {
	t.Helper()
	return openMemoryStore(t, ttl, gracePeriod)
}

// newBenchStore mirrors newTestStore for benchmarks.
func newBenchStore(b *testing.B, ttl, gracePeriod time.Duration) challpkg.Store {
	b.Helper()
	return openMemoryStore(b, ttl, gracePeriod)
}

type tbCleanup interface {
	Helper()
	Fatalf(format string, args ...any)
	Cleanup(func())
}

func openMemoryStore(tb tbCleanup, ttl, gracePeriod time.Duration) challpkg.Store {
	tb.Helper()
	db, dialect, err := challpkg.Open(challpkg.SQLConfig{
		Driver: "sqlite",
		DSN:    "file::memory:?cache=shared",
	})
	if err != nil {
		tb.Fatalf("Open: %v", err)
	}
	tb.Cleanup(func() { _ = db.Close() })
	store, err := challpkg.NewSQLStore(db, dialect, ttl, gracePeriod)
	if err != nil {
		tb.Fatalf("NewSQLStore: %v", err)
	}
	tb.Cleanup(store.Stop)
	return store
}
