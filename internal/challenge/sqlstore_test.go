package challenge

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"
)

// newTestSQLStore returns a fresh SQLStore backed by either:
//   - an in-memory SQLite (default), or
//   - a Postgres instance pointed to by IDENTREE_TEST_POSTGRES_DSN when
//     IDENTREE_TEST_BACKEND=postgres.
//
// CI runs the suite twice — once per backend — so every Store method is
// exercised against both dialects, including the Postgres-specific row
// locking on read-modify-write paths.
func newTestSQLStore(t *testing.T) *SQLStore {
	t.Helper()
	return openTestStore(t, 5*time.Minute, 30*time.Minute)
}

// openTestStore is the parameterised constructor used by tests that need a
// custom challenge TTL or grace period (e.g. the reap-loop test).
func openTestStore(t testing.TB, ttl, gracePeriod time.Duration) *SQLStore {
	t.Helper()
	driver, dsn := backendForTest(t)
	db, dialect, err := Open(SQLConfig{Driver: driver, DSN: dsn})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewSQLStore(db, dialect, ttl, gracePeriod)
	if err != nil {
		t.Fatalf("NewSQLStore: %v", err)
	}
	if dialect == DialectPostgres {
		// SQLite tests get a fresh in-memory db per Open(); Postgres tests
		// share a single physical database across the run so we wipe state
		// up-front for isolation.
		truncateAllTables(t, db)
	}
	t.Cleanup(store.Stop)
	return store
}

// backendForTest picks the test backend based on environment. Defaults to
// SQLite. When IDENTREE_TEST_BACKEND=postgres the caller is responsible
// for setting IDENTREE_TEST_POSTGRES_DSN; missing DSN skips the test
// instead of failing so the Postgres job is opt-in.
func backendForTest(t testing.TB) (driver, dsn string) {
	t.Helper()
	switch os.Getenv("IDENTREE_TEST_BACKEND") {
	case "postgres":
		dsn := os.Getenv("IDENTREE_TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("IDENTREE_TEST_BACKEND=postgres but IDENTREE_TEST_POSTGRES_DSN is empty")
		}
		return "postgres", dsn
	case "", "sqlite":
		return "sqlite", "file::memory:?cache=shared"
	default:
		t.Fatalf("unknown IDENTREE_TEST_BACKEND %q", os.Getenv("IDENTREE_TEST_BACKEND"))
		return "", ""
	}
}

// allTestTables enumerates every table the schema creates. Used for
// per-test cleanup on the shared Postgres database.
var allTestTables = []string{
	"schema_migrations",
	"challenges", "action_log", "grace_sessions",
	"revoked_nonces", "revoked_admin_sessions", "revoke_tokens_before",
	"rotate_breakglass_before", "last_oidc_auth",
	"escrowed_hosts", "escrow_ciphertexts", "used_escrow_tokens",
	"session_nonces", "agents", "cluster_messages",
	"notify_admin_prefs", "notify_config",
}

func truncateAllTables(t testing.TB, db *sql.DB) {
	t.Helper()
	// CASCADE handles any future FK additions; RESTART IDENTITY resets
	// the BIGSERIAL counters on action_log + cluster_messages.
	for _, table := range allTestTables {
		if _, err := db.Exec("TRUNCATE TABLE " + table + " RESTART IDENTITY CASCADE"); err != nil {
			t.Fatalf("truncate %s: %v", table, err)
		}
	}
}

func TestSQLStore_HealthCheck(t *testing.T) {
	s := newTestSQLStore(t)
	if err := s.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
	want := "sqlite"
	if os.Getenv("IDENTREE_TEST_BACKEND") == "postgres" {
		want = "postgres"
	}
	if got := s.DialectName(); got != want {
		t.Errorf("DialectName: got %q, want %q", got, want)
	}
}

func TestSQLStore_ActionLog(t *testing.T) {
	s := newTestSQLStore(t)

	s.LogAction(context.Background(), "alice", ActionApproved, "host1", "ABC123", "")
	s.LogActionWithReason(context.Background(), "alice", ActionRevoked, "host1", "ABC123", "admin", "no longer needed")
	s.LogActionAt(context.Background(), "bob", ActionApproved, "host2", "DEF456", "alice", time.Now().Add(-time.Hour))

	hist := s.ActionHistory(context.Background(), "alice", 10)
	if len(hist) != 2 {
		t.Fatalf("ActionHistory(alice): got %d entries, want 2", len(hist))
	}
	// Newest first.
	if hist[0].Action != ActionRevoked {
		t.Errorf("hist[0].Action: got %q, want %q", hist[0].Action, ActionRevoked)
	}
	if hist[0].Reason != "no longer needed" {
		t.Errorf("hist[0].Reason: got %q, want %q", hist[0].Reason, "no longer needed")
	}
	if hist[0].Actor != "admin" {
		t.Errorf("hist[0].Actor: got %q, want %q", hist[0].Actor, "admin")
	}

	all := s.AllActionHistory(context.Background(), 10000)
	if len(all) != 3 {
		t.Errorf("AllActionHistory: got %d entries, want 3", len(all))
	}

	withUsers := s.AllActionHistoryWithUsers(context.Background(), 10000, 0)
	if len(withUsers) != 3 {
		t.Errorf("AllActionHistoryWithUsers: got %d entries, want 3", len(withUsers))
	}
	usernames := make(map[string]int)
	for _, e := range withUsers {
		usernames[e.Username]++
	}
	if usernames["alice"] != 2 || usernames["bob"] != 1 {
		t.Errorf("usernames: got %v, want alice=2 bob=1", usernames)
	}
}

func TestSQLStore_OIDCAuth(t *testing.T) {
	s := newTestSQLStore(t)

	if got := s.LastOIDCAuth(context.Background(), "alice"); !got.IsZero() {
		t.Errorf("LastOIDCAuth(alice) before record: got %v, want zero", got)
	}

	before := time.Now().Add(-time.Second)
	s.RecordOIDCAuth(context.Background(), "alice")
	after := time.Now().Add(time.Second)

	got := s.LastOIDCAuth(context.Background(), "alice")
	if got.Before(before) || got.After(after) {
		t.Errorf("LastOIDCAuth(alice): got %v, want between %v and %v", got, before, after)
	}

	// Updating should overwrite.
	time.Sleep(1100 * time.Millisecond)
	s.RecordOIDCAuth(context.Background(), "alice")
	got2 := s.LastOIDCAuth(context.Background(), "alice")
	if !got2.After(got) {
		t.Errorf("LastOIDCAuth(alice) after re-record: got %v, want > %v", got2, got)
	}
}

func TestSQLStore_RevokedNonces(t *testing.T) {
	s := newTestSQLStore(t)

	now := time.Now().Truncate(time.Second)
	s.PersistRevokedNonce(context.Background(), "nonce-a", now)
	s.PersistRevokedNonce(context.Background(), "nonce-b", now.Add(-time.Hour))

	loaded := s.LoadRevokedNonces(context.Background())
	if len(loaded) != 2 {
		t.Fatalf("LoadRevokedNonces: got %d, want 2", len(loaded))
	}
	if !loaded["nonce-a"].Equal(now) {
		t.Errorf("nonce-a timestamp: got %v, want %v", loaded["nonce-a"], now)
	}
}

func TestSQLStore_RevokedAdminSessions(t *testing.T) {
	s := newTestSQLStore(t)

	now := time.Now().Truncate(time.Second)
	s.PersistRevokedAdminSession(context.Background(), "alice", now)

	loaded := s.LoadRevokedAdminSessions(context.Background())
	if len(loaded) != 1 {
		t.Fatalf("LoadRevokedAdminSessions: got %d, want 1", len(loaded))
	}
	if !loaded["alice"].Equal(now) {
		t.Errorf("alice timestamp: got %v, want %v", loaded["alice"], now)
	}
}

func TestSQLStore_Escrow(t *testing.T) {
	s := newTestSQLStore(t)

	s.RecordEscrow(context.Background(), "host1", "item-id-1", "vault-id-1")
	s.RecordEscrow(context.Background(), "host2", "", "")

	hosts := s.EscrowedHosts(context.Background())
	if len(hosts) != 2 {
		t.Fatalf("EscrowedHosts: got %d, want 2", len(hosts))
	}
	if hosts["host1"].ItemID != "item-id-1" {
		t.Errorf("host1.ItemID: got %q, want %q", hosts["host1"].ItemID, "item-id-1")
	}
	if hosts["host1"].Timestamp.IsZero() {
		t.Error("host1.Timestamp: got zero, want non-zero")
	}

	s.StoreEscrowCiphertext(context.Background(), "host1", "ciphertext-blob")
	ct, ok := s.GetEscrowCiphertext(context.Background(), "host1")
	if !ok || ct != "ciphertext-blob" {
		t.Errorf("GetEscrowCiphertext(host1): got (%q, %v), want (ciphertext-blob, true)", ct, ok)
	}
	if _, ok := s.GetEscrowCiphertext(context.Background(), "nope"); ok {
		t.Error("GetEscrowCiphertext(nope): got true, want false")
	}
}

func TestSQLStore_HostRotateBefore(t *testing.T) {
	s := newTestSQLStore(t)

	if got := s.HostRotateBefore(context.Background(), "host1"); !got.IsZero() {
		t.Errorf("HostRotateBefore before set: got %v, want zero", got)
	}

	s.SetHostRotateBefore(context.Background(), "host1")
	if got := s.HostRotateBefore(context.Background(), "host1"); got.IsZero() {
		t.Error("HostRotateBefore after set: got zero, want non-zero")
	}

	s.SetAllHostsRotateBefore(context.Background(), []string{"hostA", "hostB", "hostC"})
	if got := s.HostRotateBefore(context.Background(), "hostA"); got.IsZero() {
		t.Error("hostA rotate-before after SetAll: got zero")
	}
	if got := s.HostRotateBefore(context.Background(), "hostC"); got.IsZero() {
		t.Error("hostC rotate-before after SetAll: got zero")
	}
}

func TestSQLStore_EscrowTokenReplay(t *testing.T) {
	s := newTestSQLStore(t)

	if seen := s.CheckAndRecordEscrowToken(context.Background(), "token1"); seen {
		t.Error("CheckAndRecordEscrowToken first call: got true, want false")
	}
	if seen := s.CheckAndRecordEscrowToken(context.Background(), "token1"); !seen {
		t.Error("CheckAndRecordEscrowToken second call: got false, want true")
	}
	if seen := s.CheckAndRecordEscrowToken(context.Background(), "token2"); seen {
		t.Error("CheckAndRecordEscrowToken token2: got true, want false")
	}
	if got := s.UsedEscrowTokenCount(context.Background()); got != 2 {
		t.Errorf("UsedEscrowTokenCount: got %d, want 2", got)
	}
}

func TestSQLStore_SessionNonces(t *testing.T) {
	s := newTestSQLStore(t)

	if _, ok := s.GetSessionNonce(context.Background(), "missing"); ok {
		t.Error("GetSessionNonce(missing): got true, want false")
	}

	data := SessionNonceData{
		IssuedAt:     time.Now().Truncate(time.Second),
		CodeVerifier: "verifier-xyz",
		ClientIP:     "1.2.3.4",
	}
	if err := s.StoreSessionNonce(context.Background(), "nonce-1", data, 5*time.Minute); err != nil {
		t.Fatalf("StoreSessionNonce: %v", err)
	}

	got, ok := s.GetSessionNonce(context.Background(), "nonce-1")
	if !ok {
		t.Fatal("GetSessionNonce after store: got false, want true")
	}
	if got.CodeVerifier != "verifier-xyz" || got.ClientIP != "1.2.3.4" {
		t.Errorf("GetSessionNonce: got %+v", got)
	}

	s.DeleteSessionNonce(context.Background(), "nonce-1")
	if _, ok := s.GetSessionNonce(context.Background(), "nonce-1"); ok {
		t.Error("GetSessionNonce after delete: got true, want false")
	}

	// TTL expiry.
	if err := s.StoreSessionNonce(context.Background(), "nonce-2", data, 1*time.Millisecond); err != nil {
		t.Fatalf("StoreSessionNonce: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, ok := s.GetSessionNonce(context.Background(), "nonce-2"); ok {
		t.Error("GetSessionNonce after expiry: got true, want false")
	}
}

func TestSQLStore_KnownHostsAndUsers(t *testing.T) {
	s := newTestSQLStore(t)

	s.LogAction(context.Background(), "alice", ActionApproved, "host1", "C1", "")
	s.LogAction(context.Background(), "alice", ActionApproved, "host2", "C2", "")
	s.LogAction(context.Background(), "bob", ActionApproved, "host1", "C3", "")

	hosts := s.KnownHosts(context.Background(), "alice")
	if len(hosts) != 2 {
		t.Errorf("KnownHosts(alice): got %v, want 2 entries", hosts)
	}

	all := s.AllKnownHosts(context.Background())
	if len(all) != 2 {
		t.Errorf("AllKnownHosts: got %v, want 2 entries", all)
	}

	users := s.UsersWithHostActivity(context.Background(), "host1")
	if len(users) != 2 {
		t.Errorf("UsersWithHostActivity(host1): got %v, want 2 entries", users)
	}

	allUsers := s.AllUsers(context.Background())
	if len(allUsers) != 2 {
		t.Errorf("AllUsers: got %v, want 2 entries", allUsers)
	}
}

func TestSQLStore_SaveStateClearsDirty(t *testing.T) {
	s := newTestSQLStore(t)

	// A write marks the store dirty.
	s.LogAction(context.Background(), "alice", ActionApproved, "h", "C1", "")
	if !s.dirty.Load() {
		t.Fatal("expected dirty=true after write")
	}
	s.SaveState()
	if s.dirty.Load() {
		t.Error("SaveState did not clear dirty flag")
	}
}

func TestSQLStore_DB(t *testing.T) {
	s := newTestSQLStore(t)
	db := s.DB()
	if db == nil {
		t.Fatal("DB(): got nil")
	}
	// Proves the handle is live by pinging through it directly.
	if err := db.Ping(); err != nil {
		t.Errorf("DB().Ping: %v", err)
	}
}

// TestSQLStore_UpsertSuffix verifies the ON CONFLICT fragment is what the
// callers concatenate into INSERT statements. A regression here would break
// upsertGrace + every upsert path silently until a runtime SQL error fires.
func TestSQLStore_UpsertSuffix(t *testing.T) {
	cases := []struct {
		name    string
		dialect Dialect
	}{
		{"sqlite", DialectSQLite},
		{"postgres", DialectPostgres},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &SQLStore{dialect: tc.dialect}
			got := s.upsertSuffix("username, hostname", "expiry_unix = excluded.expiry_unix")
			want := " ON CONFLICT (username, hostname) DO UPDATE SET expiry_unix = excluded.expiry_unix"
			if got != want {
				t.Errorf("upsertSuffix:\n got=%q\nwant=%q", got, want)
			}
		})
	}
}

// TestSQLStore_WithSQLGraceHMACKey verifies the functional option is applied
// at construction time so grace HMACs are written/verified from the first
// write. Without this, the first CreateGraceSession would land with an empty
// MAC and subsequent reads (with the key now set) would drop it as invalid.
func TestSQLStore_WithSQLGraceHMACKey(t *testing.T) {
	driver, dsn := backendForTest(t)
	db, dialect, err := Open(SQLConfig{Driver: driver, DSN: dsn})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	key := []byte("construction-time-key")
	s, err := NewSQLStore(db, dialect, 5*time.Minute, 30*time.Minute, WithSQLGraceHMACKey(key))
	if err != nil {
		t.Fatalf("NewSQLStore: %v", err)
	}
	t.Cleanup(s.Stop)
	if dialect == DialectPostgres {
		truncateAllTables(t, db)
	}

	if got := s.currentGraceHMACKey(); string(got) != string(key) {
		t.Errorf("graceHMACKey after option: got %q, want %q", got, key)
	}

	// End-to-end: write with the key present, then read back successfully.
	s.CreateGraceSession(context.Background(), "alice", "h", 10*time.Minute)
	if !s.WithinGracePeriod(context.Background(), "alice", "h") {
		t.Error("WithinGracePeriod after Create with keyed store: want true")
	}

	// The stored row must have a non-empty HMAC — proving the key was active
	// on the write path (not only on the verify path).
	var mac string
	if err := s.queryRow(t.Context(),
		`SELECT hmac_hex FROM grace_sessions WHERE username = ? AND hostname = ?`,
		"alice", "h").Scan(&mac); err != nil {
		t.Fatalf("scan hmac: %v", err)
	}
	if mac == "" {
		t.Error("stored hmac_hex is empty; WithSQLGraceHMACKey did not take effect at construction")
	}
}

func TestSQLStore_RevokeTokensBefore(t *testing.T) {
	s := newTestSQLStore(t)

	if got := s.RevokeTokensBefore(context.Background(), "alice"); !got.IsZero() {
		t.Errorf("RevokeTokensBefore before set: got %v, want zero", got)
	}
	// Direct insert (RevokeTokensBefore setter lives on the read-modify-write
	// path and is part of the next session's work). Use a raw exec to
	// validate the read side independently.
	now := time.Now().Truncate(time.Second).Unix()
	// Use s.exec() so the placeholder is rewritten for whichever dialect is active.
	if _, err := s.exec(t.Context(), `INSERT INTO revoke_tokens_before (username, revoked_at) VALUES (?, ?)`, "alice", now); err != nil {
		t.Fatalf("manual insert: %v", err)
	}
	got := s.RevokeTokensBefore(context.Background(), "alice")
	if got.Unix() != now {
		t.Errorf("RevokeTokensBefore: got %v, want %v", got.Unix(), now)
	}
}
