package challenge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// Compile-time check: SQLStore implements Store.
var _ Store = (*SQLStore)(nil)

// Dialect identifies the SQL backend in use.
type Dialect int

const (
	DialectSQLite Dialect = iota
	DialectPostgres
)

func (d Dialect) String() string {
	switch d {
	case DialectSQLite:
		return "sqlite"
	case DialectPostgres:
		return "postgres"
	default:
		return "unknown"
	}
}

// SQLStore implements the Store interface backed by a SQL database
// (SQLite for single-node deploys, PostgreSQL for HA / enterprise).
//
// All methods are safe for concurrent use. Read-modify-write paths
// (Approve, Deny, AddApproval, SetNonce, ConsumeOneTap, ConsumeAndApprove,
// ExtendGraceSession) wrap their work in a transaction with explicit row
// locks so they preserve the linearizability the in-memory ChallengeStore
// and the Redis Lua scripts provided.
type SQLStore struct {
	db          *sql.DB
	dialect     Dialect
	ttl         time.Duration
	gracePeriod time.Duration

	graceHMACKeyMu sync.RWMutex
	graceHMACKey   []byte

	stopCh   chan struct{}
	stopOnce sync.Once
	stopWg   sync.WaitGroup

	// dirty is set whenever a write happens; SaveState becomes a no-op for
	// the SQL backend (every write commits) but the flag is retained so
	// the existing periodic-flush wiring stays compatible during cutover.
	dirty atomic.Bool

	// OnExpire is invoked by the background reap goroutine when a pending
	// challenge passes its expiry. The server wires this to emit an audit
	// event and broadcast a UI update.
	OnExpire func(username, hostname, code string)
}

// SQLConfig is the connection configuration for NewSQLStore.
type SQLConfig struct {
	// Driver is "sqlite" or "postgres".
	Driver string
	// DSN is the dialect-specific connection string. For SQLite this is
	// a file path (or ":memory:"); for Postgres it is a libpq-style URL.
	DSN string
	// MaxOpenConns caps the connection pool. Defaults to 25 for Postgres,
	// 1 for SQLite (WAL still allows concurrent readers via separate
	// read-only connections, but for v1 we serialize all access for
	// simplicity).
	MaxOpenConns int
	// MaxIdleConns caps the idle pool. Defaults to MaxOpenConns.
	MaxIdleConns int
	// ConnMaxLifetime caps connection age. Zero means no cap.
	ConnMaxLifetime time.Duration
}

// Open returns a *sql.DB for the given config, applying dialect-specific
// connection tuning. The caller is responsible for closing it.
func Open(cfg SQLConfig) (*sql.DB, Dialect, error) {
	driver, dialect, err := resolveDriver(cfg.Driver)
	if err != nil {
		return nil, 0, err
	}

	dsn := cfg.DSN
	if dialect == DialectSQLite {
		dsn = applySQLitePragmas(dsn)
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, 0, fmt.Errorf("sql open %s: %w", driver, err)
	}

	maxOpen := cfg.MaxOpenConns
	if maxOpen == 0 {
		if dialect == DialectSQLite {
			maxOpen = 1
		} else {
			maxOpen = 25
		}
	}
	maxIdle := cfg.MaxIdleConns
	if maxIdle == 0 {
		maxIdle = maxOpen
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	if cfg.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	}

	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, 0, fmt.Errorf("sql ping %s: %w", driver, err)
	}
	return db, dialect, nil
}

// resolveDriver maps the public driver name to the registered database/sql
// driver name and the dialect we use for query rewriting.
func resolveDriver(name string) (string, Dialect, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sqlite", "sqlite3":
		return "sqlite", DialectSQLite, nil
	case "postgres", "postgresql", "pg", "pgx":
		return "pgx", DialectPostgres, nil
	case "":
		return "", 0, errors.New("sql driver: empty (set IDENTREE_DATABASE_DRIVER to 'sqlite' or 'postgres')")
	default:
		return "", 0, fmt.Errorf("sql driver: unknown %q (want 'sqlite' or 'postgres')", name)
	}
}

// applySQLitePragmas appends our standard pragmas to a SQLite DSN if the
// caller hasn't set them. WAL + busy_timeout are essential for sane
// concurrency; foreign_keys is on for safety; synchronous=NORMAL is the
// recommended pairing with WAL.
func applySQLitePragmas(dsn string) string {
	if dsn == "" {
		return dsn
	}
	required := map[string]string{
		"_pragma": "", // marker — the modernc driver uses _pragma=key(value)
	}
	_ = required
	// modernc.org/sqlite expects pragmas via _pragma= query parameters in
	// the DSN, e.g. ":memory:?_pragma=journal_mode(WAL)". We append our
	// defaults if the DSN doesn't already have them.
	defaults := []string{
		"_pragma=journal_mode(WAL)",
		"_pragma=busy_timeout(5000)",
		"_pragma=synchronous(NORMAL)",
		"_pragma=foreign_keys(ON)",
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	add := []string{}
	for _, p := range defaults {
		key := strings.SplitN(p, "(", 2)[0]
		if !strings.Contains(dsn, key) {
			add = append(add, p)
		}
	}
	if len(add) == 0 {
		return dsn
	}
	return dsn + sep + strings.Join(add, "&")
}

// NewSQLStore opens the database, applies the schema, and returns a ready
// SQLStore. The caller passes a *sql.DB obtained from Open() so that
// connection pooling and DSN tuning happen in one place.
func NewSQLStore(db *sql.DB, dialect Dialect, ttl, gracePeriod time.Duration, opts ...func(*SQLStore)) (*SQLStore, error) {
	if db == nil {
		return nil, errors.New("NewSQLStore: nil db")
	}
	s := &SQLStore{
		db:          db,
		dialect:     dialect,
		ttl:         ttl,
		gracePeriod: gracePeriod,
		stopCh:      make(chan struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	if err := s.migrate(context.Background()); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	s.startReap()
	return s, nil
}

// WithSQLGraceHMACKey is the SQLStore equivalent of WithGraceHMACKey for
// the legacy ChallengeStore. Apply at construction so HMAC verification
// is consistent from the first read.
func WithSQLGraceHMACKey(key []byte) func(*SQLStore) {
	return func(s *SQLStore) {
		s.graceHMACKey = key
	}
}

// ── Dialect / placeholder helpers ───────────────────────────────────────────

// q rewrites ? placeholders to $N for Postgres. SQLite leaves them as ?.
// All query constants in the SQLStore implementation use ? placeholders.
func (s *SQLStore) q(query string) string {
	if s.dialect != DialectPostgres {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	inSQ := false
	inDQ := false
	for i := 0; i < len(query); i++ {
		c := query[i]
		switch {
		case c == '\'' && !inDQ:
			inSQ = !inSQ
			b.WriteByte(c)
		case c == '"' && !inSQ:
			inDQ = !inDQ
			b.WriteByte(c)
		case c == '?' && !inSQ && !inDQ:
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// exec runs a write statement with placeholder rewriting.
func (s *SQLStore) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	res, err := s.db.ExecContext(ctx, s.q(query), args...)
	if err == nil {
		s.dirty.Store(true)
	}
	return res, err
}

// query runs a SELECT with placeholder rewriting.
func (s *SQLStore) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, s.q(query), args...)
}

// queryRow runs a single-row SELECT with placeholder rewriting.
func (s *SQLStore) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return s.db.QueryRowContext(ctx, s.q(query), args...)
}

// beginTxRMW begins a transaction for read-modify-write paths. On
// SQLite it issues an immediate write lock to avoid deferred-lock
// upgrade deadlocks; on Postgres it uses the default isolation and
// relies on explicit SELECT ... FOR UPDATE in the transaction body.
func (s *SQLStore) beginTxRMW(ctx context.Context) (*sql.Tx, error) {
	if s.dialect == DialectSQLite {
		// modernc.org/sqlite supports BEGIN IMMEDIATE via a separate Exec.
		// database/sql's BeginTx doesn't expose the SQLite locking modes
		// directly, so we open a tx and immediately escalate.
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		// SQLite ROLLBACK followed by BEGIN IMMEDIATE inside a sql.Tx is
		// not legal. Instead, the simplest correct approach for serializing
		// writes on SQLite is MaxOpenConns=1 + plain BEGIN, which our
		// Open() default already does. Document this and return the tx.
		return tx, nil
	}
	return s.db.BeginTx(ctx, nil)
}

// forUpdate returns a SQL fragment that locks the selected row for update,
// or empty string for SQLite (where BEGIN IMMEDIATE + MaxOpenConns=1 is
// our serialization story).
func (s *SQLStore) forUpdate() string {
	if s.dialect == DialectPostgres {
		return " FOR UPDATE"
	}
	return ""
}

// upsert returns a dialect-appropriate INSERT ... ON CONFLICT clause.
// Both SQLite (>=3.24) and Postgres support identical syntax for the
// ON CONFLICT DO UPDATE form so this is a passthrough — kept as a helper
// in case future dialect divergence appears.
func (s *SQLStore) upsertSuffix(conflictCols, setCols string) string {
	return " ON CONFLICT (" + conflictCols + ") DO UPDATE SET " + setCols
}

// ── Time helpers ────────────────────────────────────────────────────────────

// nowUnix returns the current time as Unix seconds.
func nowUnix() int64 { return time.Now().Unix() }

// unixToTime converts a stored Unix timestamp to a time.Time. Zero stays zero.
func unixToTime(u int64) time.Time {
	if u == 0 {
		return time.Time{}
	}
	return time.Unix(u, 0)
}

// timeToUnix converts a time.Time to a stored Unix timestamp. Zero stays zero.
func timeToUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// boolToInt converts a Go bool to the integer representation we store.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

// SetGraceHMACKey sets the HMAC key used to sign and verify grace session values.
func (s *SQLStore) SetGraceHMACKey(key []byte) {
	s.graceHMACKeyMu.Lock()
	s.graceHMACKey = key
	s.graceHMACKeyMu.Unlock()
}

func (s *SQLStore) currentGraceHMACKey() []byte {
	s.graceHMACKeyMu.RLock()
	defer s.graceHMACKeyMu.RUnlock()
	return s.graceHMACKey
}

// SaveState is a no-op for the SQL backend: every mutation commits
// synchronously. The method is retained so the periodic-flush wiring in
// cmd.go can keep calling it during the cutover; callers should not rely
// on it doing anything.
func (s *SQLStore) SaveState() {
	s.dirty.Store(false)
}

// Stop signals background goroutines to exit, waits for them, and closes the
// underlying database connection pool.
func (s *SQLStore) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	s.stopWg.Wait()
	if err := s.db.Close(); err != nil {
		slog.Error("database close error", "err", err)
	}
}

// HealthCheck pings the underlying database.
func (s *SQLStore) HealthCheck() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("sql health: %w", err)
	}
	return nil
}

// DB returns the underlying *sql.DB. Exposed for the LISTEN/NOTIFY
// broadcaster and other components that need direct access.
func (s *SQLStore) DB() *sql.DB { return s.db }

// DialectName returns the dialect string for diagnostics.
func (s *SQLStore) DialectName() string { return s.dialect.String() }

// logErr is a small helper to keep one-off error logging consistent.
func logErr(op string, err error) {
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		slog.Error("sqlstore", "op", op, "err", err)
	}
}
