package challenge

import (
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
	if err := s.HealthCheck(); err != nil {
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

	s.LogAction("alice", ActionApproved, "host1", "ABC123", "")
	s.LogActionWithReason("alice", ActionRevoked, "host1", "ABC123", "admin", "no longer needed")
	s.LogActionAt("bob", ActionApproved, "host2", "DEF456", "alice", time.Now().Add(-time.Hour))

	hist := s.ActionHistory("alice", 10)
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

	all := s.AllActionHistory()
	if len(all) != 3 {
		t.Errorf("AllActionHistory: got %d entries, want 3", len(all))
	}

	withUsers := s.AllActionHistoryWithUsers()
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

	if got := s.LastOIDCAuth("alice"); !got.IsZero() {
		t.Errorf("LastOIDCAuth(alice) before record: got %v, want zero", got)
	}

	before := time.Now().Add(-time.Second)
	s.RecordOIDCAuth("alice")
	after := time.Now().Add(time.Second)

	got := s.LastOIDCAuth("alice")
	if got.Before(before) || got.After(after) {
		t.Errorf("LastOIDCAuth(alice): got %v, want between %v and %v", got, before, after)
	}

	// Updating should overwrite.
	time.Sleep(1100 * time.Millisecond)
	s.RecordOIDCAuth("alice")
	got2 := s.LastOIDCAuth("alice")
	if !got2.After(got) {
		t.Errorf("LastOIDCAuth(alice) after re-record: got %v, want > %v", got2, got)
	}
}

func TestSQLStore_RevokedNonces(t *testing.T) {
	s := newTestSQLStore(t)

	now := time.Now().Truncate(time.Second)
	s.PersistRevokedNonce("nonce-a", now)
	s.PersistRevokedNonce("nonce-b", now.Add(-time.Hour))

	loaded := s.LoadRevokedNonces()
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
	s.PersistRevokedAdminSession("alice", now)

	loaded := s.LoadRevokedAdminSessions()
	if len(loaded) != 1 {
		t.Fatalf("LoadRevokedAdminSessions: got %d, want 1", len(loaded))
	}
	if !loaded["alice"].Equal(now) {
		t.Errorf("alice timestamp: got %v, want %v", loaded["alice"], now)
	}
}

func TestSQLStore_Escrow(t *testing.T) {
	s := newTestSQLStore(t)

	s.RecordEscrow("host1", "item-id-1", "vault-id-1")
	s.RecordEscrow("host2", "", "")

	hosts := s.EscrowedHosts()
	if len(hosts) != 2 {
		t.Fatalf("EscrowedHosts: got %d, want 2", len(hosts))
	}
	if hosts["host1"].ItemID != "item-id-1" {
		t.Errorf("host1.ItemID: got %q, want %q", hosts["host1"].ItemID, "item-id-1")
	}
	if hosts["host1"].Timestamp.IsZero() {
		t.Error("host1.Timestamp: got zero, want non-zero")
	}

	s.StoreEscrowCiphertext("host1", "ciphertext-blob")
	ct, ok := s.GetEscrowCiphertext("host1")
	if !ok || ct != "ciphertext-blob" {
		t.Errorf("GetEscrowCiphertext(host1): got (%q, %v), want (ciphertext-blob, true)", ct, ok)
	}
	if _, ok := s.GetEscrowCiphertext("nope"); ok {
		t.Error("GetEscrowCiphertext(nope): got true, want false")
	}
}

func TestSQLStore_HostRotateBefore(t *testing.T) {
	s := newTestSQLStore(t)

	if got := s.HostRotateBefore("host1"); !got.IsZero() {
		t.Errorf("HostRotateBefore before set: got %v, want zero", got)
	}

	s.SetHostRotateBefore("host1")
	if got := s.HostRotateBefore("host1"); got.IsZero() {
		t.Error("HostRotateBefore after set: got zero, want non-zero")
	}

	s.SetAllHostsRotateBefore([]string{"hostA", "hostB", "hostC"})
	if got := s.HostRotateBefore("hostA"); got.IsZero() {
		t.Error("hostA rotate-before after SetAll: got zero")
	}
	if got := s.HostRotateBefore("hostC"); got.IsZero() {
		t.Error("hostC rotate-before after SetAll: got zero")
	}
}

func TestSQLStore_EscrowTokenReplay(t *testing.T) {
	s := newTestSQLStore(t)

	if seen := s.CheckAndRecordEscrowToken("token1"); seen {
		t.Error("CheckAndRecordEscrowToken first call: got true, want false")
	}
	if seen := s.CheckAndRecordEscrowToken("token1"); !seen {
		t.Error("CheckAndRecordEscrowToken second call: got false, want true")
	}
	if seen := s.CheckAndRecordEscrowToken("token2"); seen {
		t.Error("CheckAndRecordEscrowToken token2: got true, want false")
	}
	if got := s.UsedEscrowTokenCount(); got != 2 {
		t.Errorf("UsedEscrowTokenCount: got %d, want 2", got)
	}
}

func TestSQLStore_SessionNonces(t *testing.T) {
	s := newTestSQLStore(t)

	if _, ok := s.GetSessionNonce("missing"); ok {
		t.Error("GetSessionNonce(missing): got true, want false")
	}

	data := SessionNonceData{
		IssuedAt:     time.Now().Truncate(time.Second),
		CodeVerifier: "verifier-xyz",
		ClientIP:     "1.2.3.4",
	}
	if err := s.StoreSessionNonce("nonce-1", data, 5*time.Minute); err != nil {
		t.Fatalf("StoreSessionNonce: %v", err)
	}

	got, ok := s.GetSessionNonce("nonce-1")
	if !ok {
		t.Fatal("GetSessionNonce after store: got false, want true")
	}
	if got.CodeVerifier != "verifier-xyz" || got.ClientIP != "1.2.3.4" {
		t.Errorf("GetSessionNonce: got %+v", got)
	}

	s.DeleteSessionNonce("nonce-1")
	if _, ok := s.GetSessionNonce("nonce-1"); ok {
		t.Error("GetSessionNonce after delete: got true, want false")
	}

	// TTL expiry.
	if err := s.StoreSessionNonce("nonce-2", data, 1*time.Millisecond); err != nil {
		t.Fatalf("StoreSessionNonce: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, ok := s.GetSessionNonce("nonce-2"); ok {
		t.Error("GetSessionNonce after expiry: got true, want false")
	}
}

func TestSQLStore_KnownHostsAndUsers(t *testing.T) {
	s := newTestSQLStore(t)

	s.LogAction("alice", ActionApproved, "host1", "C1", "")
	s.LogAction("alice", ActionApproved, "host2", "C2", "")
	s.LogAction("bob", ActionApproved, "host1", "C3", "")

	hosts := s.KnownHosts("alice")
	if len(hosts) != 2 {
		t.Errorf("KnownHosts(alice): got %v, want 2 entries", hosts)
	}

	all := s.AllKnownHosts()
	if len(all) != 2 {
		t.Errorf("AllKnownHosts: got %v, want 2 entries", all)
	}

	users := s.UsersWithHostActivity("host1")
	if len(users) != 2 {
		t.Errorf("UsersWithHostActivity(host1): got %v, want 2 entries", users)
	}

	allUsers := s.AllUsers()
	if len(allUsers) != 2 {
		t.Errorf("AllUsers: got %v, want 2 entries", allUsers)
	}
}

func TestSQLStore_RevokeTokensBefore(t *testing.T) {
	s := newTestSQLStore(t)

	if got := s.RevokeTokensBefore("alice"); !got.IsZero() {
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
	got := s.RevokeTokensBefore("alice")
	if got.Unix() != now {
		t.Errorf("RevokeTokensBefore: got %v, want %v", got.Unix(), now)
	}
}
