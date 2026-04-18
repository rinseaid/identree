package challenge

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestSQLStore_CreateAndGet(t *testing.T) {
	s := newTestSQLStore(t)

	c, err := s.Create("alice", "host1", "", "needs root")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if c.ID == "" || c.UserCode == "" {
		t.Errorf("Create: empty ID or UserCode (%+v)", c)
	}
	if c.Status != StatusPending {
		t.Errorf("Status: got %q, want %q", c.Status, StatusPending)
	}
	if c.Username != "alice" || c.Hostname != "host1" || c.Reason != "needs root" {
		t.Errorf("Create roundtrip: %+v", c)
	}

	got, ok := s.Get(c.ID)
	if !ok {
		t.Fatal("Get: not found")
	}
	if got.ID != c.ID || got.Status != StatusPending {
		t.Errorf("Get: got %+v", got)
	}

	gotByCode, ok := s.GetByCode(c.UserCode)
	if !ok || gotByCode.ID != c.ID {
		t.Errorf("GetByCode: got (%+v, %v)", gotByCode, ok)
	}

	if _, ok := s.Get("missing"); ok {
		t.Error("Get(missing): want false")
	}
	if _, ok := s.GetByCode("MISSING"); ok {
		t.Error("GetByCode(missing): want false")
	}
}

func TestSQLStore_CreatePerUserCap(t *testing.T) {
	s := newTestSQLStore(t)

	for i := 0; i < maxChallengesPerUser; i++ {
		if _, err := s.Create("alice", "h", "", ""); err != nil {
			t.Fatalf("Create #%d: %v", i, err)
		}
	}
	_, err := s.Create("alice", "h", "", "")
	if !errors.Is(err, ErrTooManyPerUser) {
		t.Errorf("Create over per-user cap: got %v, want ErrTooManyPerUser", err)
	}
	// A different user is unaffected.
	if _, err := s.Create("bob", "h", "", ""); err != nil {
		t.Errorf("Create bob: %v", err)
	}
}

func TestSQLStore_SetNonce(t *testing.T) {
	s := newTestSQLStore(t)
	c, _ := s.Create("alice", "h", "", "")

	if err := s.SetNonce(c.ID, "nonce-1"); err != nil {
		t.Fatalf("SetNonce first: %v", err)
	}
	if err := s.SetNonce(c.ID, "nonce-2"); err == nil {
		t.Error("SetNonce twice: want error")
	}
	if err := s.SetNonce("missing", "n"); err == nil {
		t.Error("SetNonce(missing): want error")
	}

	// Verify the nonce landed.
	got, _ := s.Get(c.ID)
	if got.Nonce != "nonce-1" {
		t.Errorf("Nonce: got %q, want nonce-1", got.Nonce)
	}
}

func TestSQLStore_Approve(t *testing.T) {
	s := newTestSQLStore(t)
	c, _ := s.Create("alice", "h1", "", "")

	if err := s.Approve(c.ID, "admin"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	got, ok := s.Get(c.ID)
	if !ok {
		t.Fatal("Get after Approve: not found")
	}
	if got.Status != StatusApproved {
		t.Errorf("Status: got %q, want %q", got.Status, StatusApproved)
	}
	if got.ApprovedBy != "admin" {
		t.Errorf("ApprovedBy: got %q", got.ApprovedBy)
	}
	if got.ApprovedAt.IsZero() {
		t.Error("ApprovedAt: want non-zero")
	}
	// Grace session should now exist.
	if !s.WithinGracePeriod("alice", "h1") {
		t.Error("WithinGracePeriod after Approve: want true")
	}

	// Second approval rejected.
	if err := s.Approve(c.ID, "admin"); !errors.Is(err, ErrAlreadyResolved) {
		t.Errorf("Approve twice: got %v, want ErrAlreadyResolved", err)
	}
}

func TestSQLStore_ApproveBlockedByRevocation(t *testing.T) {
	s := newTestSQLStore(t)
	c, _ := s.Create("alice", "h", "", "")

	// Revoke tokens AFTER the challenge was created.
	time.Sleep(1100 * time.Millisecond) // ensure revoked_at > created_at given Unix-second resolution
	s.RevokeSession("alice", "h")

	if err := s.Approve(c.ID, "admin"); err == nil {
		t.Error("Approve after revocation: want error")
	}
}

func TestSQLStore_Deny(t *testing.T) {
	s := newTestSQLStore(t)
	c, _ := s.Create("alice", "h", "", "")

	if err := s.Deny(c.ID, "no thanks"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	got, _ := s.Get(c.ID)
	if got.Status != StatusDenied {
		t.Errorf("Status: got %q, want %q", got.Status, StatusDenied)
	}
	if got.DenyReason != "no thanks" {
		t.Errorf("DenyReason: got %q", got.DenyReason)
	}
	if err := s.Deny(c.ID, "again"); !errors.Is(err, ErrAlreadyResolved) {
		t.Errorf("Deny twice: got %v, want ErrAlreadyResolved", err)
	}
}

func TestSQLStore_AutoApproveDoesNotExtendGrace(t *testing.T) {
	s := newTestSQLStore(t)
	// First, create a grace session for alice on h via Approve.
	c1, _ := s.Create("alice", "h", "", "")
	if err := s.Approve(c1.ID, "admin"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	originalRem := s.GraceRemaining("alice", "h")

	time.Sleep(1100 * time.Millisecond)

	c2, _ := s.Create("alice", "h", "", "")
	if err := s.AutoApprove(c2.ID); err != nil {
		t.Fatalf("AutoApprove: %v", err)
	}
	// AutoApprove should NOT push the grace expiry forward.
	newRem := s.GraceRemaining("alice", "h")
	// New remaining should be strictly less than the originally captured value
	// (because time has passed).
	if newRem >= originalRem {
		t.Errorf("AutoApprove extended grace: original=%v new=%v", originalRem, newRem)
	}

	got, _ := s.Get(c2.ID)
	if got.Status != StatusApproved {
		t.Errorf("Status: got %q, want %q", got.Status, StatusApproved)
	}
	if got.ApprovedBy != "alice" {
		t.Errorf("AutoApprove ApprovedBy: got %q, want alice", got.ApprovedBy)
	}
}

func TestSQLStore_AutoApproveIfWithinGracePeriod(t *testing.T) {
	s := newTestSQLStore(t)
	// No grace session yet.
	c, _ := s.Create("alice", "h", "", "")
	if ok := s.AutoApproveIfWithinGracePeriod("alice", "h", c.ID); ok {
		t.Error("AutoApproveIfWithinGracePeriod with no grace: want false")
	}

	// Create grace session, then try again with a fresh challenge.
	s.CreateGraceSession("alice", "h", time.Hour)
	c2, _ := s.Create("alice", "h", "", "")
	if !s.AutoApproveIfWithinGracePeriod("alice", "h", c2.ID) {
		t.Error("AutoApproveIfWithinGracePeriod with active grace: want true")
	}
	got, _ := s.Get(c2.ID)
	if got.Status != StatusApproved {
		t.Errorf("Status: got %q", got.Status)
	}
}

func TestSQLStore_AddApproval(t *testing.T) {
	s := newTestSQLStore(t)
	c, _ := s.Create("alice", "h", "", "")

	full, err := s.AddApproval(c.ID, "approver1", 2)
	if err != nil {
		t.Fatalf("AddApproval #1: %v", err)
	}
	if full {
		t.Error("AddApproval #1: should not be fully approved yet")
	}
	got, _ := s.Get(c.ID)
	if got.Status != StatusPending {
		t.Errorf("Status after partial: got %q, want pending", got.Status)
	}
	if len(got.Approvals) != 1 {
		t.Errorf("Approvals: got %d, want 1", len(got.Approvals))
	}

	// Duplicate from same approver rejected.
	if _, err := s.AddApproval(c.ID, "approver1", 2); !errors.Is(err, ErrDuplicateApprover) {
		t.Errorf("AddApproval duplicate: got %v, want ErrDuplicateApprover", err)
	}

	full, err = s.AddApproval(c.ID, "approver2", 2)
	if err != nil {
		t.Fatalf("AddApproval #2: %v", err)
	}
	if !full {
		t.Error("AddApproval #2: should be fully approved")
	}
	got, _ = s.Get(c.ID)
	if got.Status != StatusApproved {
		t.Errorf("Status after full: got %q, want approved", got.Status)
	}
	if got.ApprovedBy != "approver2" {
		t.Errorf("ApprovedBy: got %q, want approver2", got.ApprovedBy)
	}
}

func TestSQLStore_OneTap(t *testing.T) {
	s := newTestSQLStore(t)
	c, _ := s.Create("alice", "h", "", "")

	if err := s.ConsumeOneTap(c.ID); err != nil {
		t.Fatalf("ConsumeOneTap: %v", err)
	}
	if err := s.ConsumeOneTap(c.ID); err == nil {
		t.Error("ConsumeOneTap twice: want error")
	}
	if err := s.ConsumeOneTap("missing"); err == nil {
		t.Error("ConsumeOneTap(missing): want error")
	}
}

func TestSQLStore_ConsumeAndApprove(t *testing.T) {
	s := newTestSQLStore(t)
	c, _ := s.Create("alice", "h", "", "")

	if err := s.ConsumeAndApprove(c.ID, "admin"); err != nil {
		t.Fatalf("ConsumeAndApprove: %v", err)
	}
	got, _ := s.Get(c.ID)
	if got.Status != StatusApproved {
		t.Errorf("Status: got %q", got.Status)
	}
	if got.ApprovedBy != "admin" {
		t.Errorf("ApprovedBy: got %q", got.ApprovedBy)
	}
	// One-tap can't be reused.
	if err := s.ConsumeAndApprove(c.ID, "admin"); err == nil {
		t.Error("ConsumeAndApprove twice: want error")
	}
	// And the standard ConsumeOneTap rejects the consumed flag too.
	c2, _ := s.Create("bob", "h", "", "")
	if err := s.ConsumeOneTap(c2.ID); err != nil {
		t.Fatalf("ConsumeOneTap bob: %v", err)
	}
	if err := s.ConsumeAndApprove(c2.ID, "admin"); err == nil {
		t.Error("ConsumeAndApprove after ConsumeOneTap: want error")
	}
}

func TestSQLStore_PendingChallenges(t *testing.T) {
	s := newTestSQLStore(t)

	c1, _ := s.Create("alice", "h", "", "")
	_, _ = s.Create("alice", "h2", "", "")
	c3, _ := s.Create("bob", "h", "", "")

	// Approve one to remove it from pending.
	_ = s.Approve(c1.ID, "admin")

	pending := s.PendingChallenges("alice")
	if len(pending) != 1 {
		t.Errorf("PendingChallenges(alice): got %d, want 1", len(pending))
	}

	all := s.AllPendingChallenges()
	if len(all) != 2 {
		t.Errorf("AllPendingChallenges: got %d, want 2", len(all))
	}

	// Touch c3 to silence linter.
	_ = c3
}

func TestSQLStore_GraceSessionLifecycle(t *testing.T) {
	s := newTestSQLStore(t)

	if s.WithinGracePeriod("alice", "h") {
		t.Error("WithinGracePeriod with no session: want false")
	}
	if rem := s.GraceRemaining("alice", "h"); rem != 0 {
		t.Errorf("GraceRemaining with no session: got %v, want 0", rem)
	}

	s.CreateGraceSession("alice", "h", 10*time.Minute)
	if !s.WithinGracePeriod("alice", "h") {
		t.Error("WithinGracePeriod after Create: want true")
	}
	if rem := s.GraceRemaining("alice", "h"); rem <= 0 || rem > 10*time.Minute {
		t.Errorf("GraceRemaining: got %v", rem)
	}

	sessions := s.ActiveSessions("alice")
	if len(sessions) != 1 || sessions[0].Hostname != "h" {
		t.Errorf("ActiveSessions: got %+v", sessions)
	}

	all := s.AllActiveSessions()
	if len(all) != 1 {
		t.Errorf("AllActiveSessions: got %d, want 1", len(all))
	}

	forHost := s.ActiveSessionsForHost("h")
	if len(forHost) != 1 {
		t.Errorf("ActiveSessionsForHost(h): got %d, want 1", len(forHost))
	}

	// Revoke removes the session and bumps revoke_tokens_before.
	beforeRev := s.RevokeTokensBefore("alice")
	s.RevokeSession("alice", "h")
	if s.WithinGracePeriod("alice", "h") {
		t.Error("WithinGracePeriod after Revoke: want false")
	}
	afterRev := s.RevokeTokensBefore("alice")
	if !afterRev.After(beforeRev) {
		t.Errorf("RevokeTokensBefore: not bumped (before=%v after=%v)", beforeRev, afterRev)
	}
}

func TestSQLStore_ExtendGraceSession(t *testing.T) {
	s := newTestSQLStore(t)
	// Grace period is 30 minutes per newTestSQLStore.

	s.CreateGraceSession("alice", "h", 5*time.Minute) // less than 75% of 30m
	dur, err := s.ExtendGraceSession("alice", "h")
	if err != nil {
		t.Fatalf("ExtendGraceSession: %v", err)
	}
	if dur != 30*time.Minute {
		t.Errorf("Extend duration: got %v, want 30m", dur)
	}

	// Now there is plenty of time left, so a second extend hits the 75% guard.
	_, err = s.ExtendGraceSession("alice", "h")
	if !errors.Is(err, ErrSessionSufficientlyExtended) {
		t.Errorf("Extend with plenty remaining: got %v, want ErrSessionSufficientlyExtended", err)
	}

	// ForceExtend ignores the guard.
	dur = s.ForceExtendGraceSession("alice", "h")
	if dur != 30*time.Minute {
		t.Errorf("ForceExtend duration: got %v, want 30m", dur)
	}

	// ExtendFor caps at gracePeriod.
	dur = s.ExtendGraceSessionFor("alice", "h", 2*time.Hour)
	if dur != 30*time.Minute {
		t.Errorf("ExtendFor cap: got %v, want 30m", dur)
	}

	// Operations on non-existent sessions return zero.
	if dur := s.ForceExtendGraceSession("nobody", "h"); dur != 0 {
		t.Errorf("ForceExtend on missing: got %v, want 0", dur)
	}
}

func TestSQLStore_RemoveHost(t *testing.T) {
	s := newTestSQLStore(t)

	c, _ := s.Create("alice", "victim", "", "")
	_ = s.Approve(c.ID, "admin")
	s.RecordEscrow("victim", "i", "v")
	s.StoreEscrowCiphertext("victim", "ct")
	s.SetHostRotateBefore("victim")

	if !s.WithinGracePeriod("alice", "victim") {
		t.Fatal("precondition: WithinGracePeriod want true")
	}
	if _, ok := s.GetEscrowCiphertext("victim"); !ok {
		t.Fatal("precondition: GetEscrowCiphertext want ok")
	}
	if hosts := s.EscrowedHosts(); len(hosts) != 1 {
		t.Fatalf("precondition: EscrowedHosts want 1, got %d", len(hosts))
	}

	s.RemoveHost("victim")

	if s.WithinGracePeriod("alice", "victim") {
		t.Error("WithinGracePeriod after RemoveHost: want false")
	}
	if _, ok := s.GetEscrowCiphertext("victim"); ok {
		t.Error("GetEscrowCiphertext after RemoveHost: want false")
	}
	if hosts := s.EscrowedHosts(); len(hosts) != 0 {
		t.Errorf("EscrowedHosts after RemoveHost: got %d, want 0", len(hosts))
	}
	if !s.HostRotateBefore("victim").IsZero() {
		t.Error("HostRotateBefore after RemoveHost: want zero")
	}
}

func TestSQLStore_RemoveUser(t *testing.T) {
	s := newTestSQLStore(t)

	c, _ := s.Create("alice", "h", "", "")
	_ = s.Approve(c.ID, "admin")
	s.LogAction("alice", ActionApproved, "h", c.UserCode, "")
	s.RecordOIDCAuth("alice")

	beforeRev := s.RevokeTokensBefore("alice")
	s.RemoveUser("alice")
	afterRev := s.RevokeTokensBefore("alice")
	if !afterRev.After(beforeRev) {
		t.Errorf("RevokeTokensBefore: not bumped (before=%v after=%v)", beforeRev, afterRev)
	}

	if got := s.LastOIDCAuth("alice"); !got.IsZero() {
		t.Errorf("LastOIDCAuth after RemoveUser: got %v, want zero", got)
	}
	if hist := s.ActionHistory("alice", 100); len(hist) != 0 {
		t.Errorf("ActionHistory after RemoveUser: got %d, want 0", len(hist))
	}
	if pend := s.PendingChallenges("alice"); len(pend) != 0 {
		t.Errorf("PendingChallenges after RemoveUser: got %d, want 0", len(pend))
	}
	if s.WithinGracePeriod("alice", "h") {
		t.Error("WithinGracePeriod after RemoveUser: want false")
	}
}

func TestSQLStore_GraceHMAC(t *testing.T) {
	s := newTestSQLStore(t)
	s.SetGraceHMACKey([]byte("secret-test-key"))

	s.CreateGraceSession("alice", "h", 10*time.Minute)
	if !s.WithinGracePeriod("alice", "h") {
		t.Error("WithinGracePeriod after Create with HMAC: want true")
	}
	// Tamper with the HMAC: the row should be dropped on next read.
	if _, err := s.db.Exec(`UPDATE grace_sessions SET hmac_hex = 'deadbeef' WHERE username = 'alice' AND hostname = 'h'`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if s.WithinGracePeriod("alice", "h") {
		t.Error("WithinGracePeriod after tamper: want false")
	}
}

func TestSQLStore_ReapExpiredChallenges(t *testing.T) {
	// Use an artificially short TTL so the reap goroutine has work.
	db, dialect, err := Open(SQLConfig{Driver: "sqlite", DSN: "file::memory:?cache=shared"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := NewSQLStore(db, dialect, 100*time.Millisecond, time.Hour)
	if err != nil {
		t.Fatalf("NewSQLStore: %v", err)
	}
	t.Cleanup(s.Stop)

	var (
		mu   sync.Mutex
		seen []string
	)
	s.OnExpire = func(username, hostname, code string) {
		mu.Lock()
		seen = append(seen, username+":"+hostname+":"+code)
		mu.Unlock()
	}

	c, err := s.Create("alice", "h", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Fast-forward the row's expiry instead of waiting on the reap ticker.
	if _, err := s.db.Exec(`UPDATE challenges SET expires_at = ? WHERE id = ?`, time.Now().Add(-time.Second).Unix(), c.ID); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	s.reapOnce(t.Context())

	mu.Lock()
	gotSeen := append([]string{}, seen...)
	mu.Unlock()
	if len(gotSeen) != 1 || gotSeen[0] != "alice:h:"+c.UserCode {
		t.Errorf("OnExpire: got %v, want one alice:h:%s", gotSeen, c.UserCode)
	}
	// And the row is now StatusExpired.
	row := s.queryRow(t.Context(), `SELECT status FROM challenges WHERE id = ?`, c.ID)
	var status string
	if err := row.Scan(&status); err != nil {
		t.Fatalf("scan status: %v", err)
	}
	if ChallengeStatus(status) != StatusExpired {
		t.Errorf("Status after reap: got %q, want %q", status, StatusExpired)
	}
}
