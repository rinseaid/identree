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
	if _, err := s.exec(t.Context(), `UPDATE grace_sessions SET hmac_hex = 'deadbeef' WHERE username = 'alice' AND hostname = 'h'`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if s.WithinGracePeriod("alice", "h") {
		t.Error("WithinGracePeriod after tamper: want false")
	}
	// Verify the tampered row was lazy-deleted on read so the next call
	// doesn't repeat the verify->reject cycle. (Defence-in-depth: prevents
	// the grace_sessions table from accumulating poisoned rows.)
	var count int
	if err := s.queryRow(t.Context(),
		`SELECT COUNT(*) FROM grace_sessions WHERE username = ? AND hostname = ?`,
		"alice", "h").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("expected tampered grace row to be lazy-deleted, found %d remaining", count)
	}

	// And re-creating a fresh session on top of the wiped row works
	// (proves we can recover from a tamper detection without manual cleanup).
	s.CreateGraceSession("alice", "h", 10*time.Minute)
	if !s.WithinGracePeriod("alice", "h") {
		t.Error("WithinGracePeriod after recreate: want true")
	}
}

func TestSQLStore_SetRequestedGrace(t *testing.T) {
	s := newTestSQLStore(t)
	c, err := s.Create("alice", "h", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got, _ := s.Get(c.ID); got.RequestedGrace != 0 {
		t.Errorf("RequestedGrace initial: got %v, want 0", got.RequestedGrace)
	}

	s.SetRequestedGrace(c.ID, 45*time.Minute)
	got, ok := s.Get(c.ID)
	if !ok {
		t.Fatal("Get: not found")
	}
	if got.RequestedGrace != 45*time.Minute {
		t.Errorf("RequestedGrace: got %v, want 45m", got.RequestedGrace)
	}
}

func TestSQLStore_SetBreakglassOverride(t *testing.T) {
	s := newTestSQLStore(t)
	c, err := s.Create("alice", "h", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got, _ := s.Get(c.ID); got.BreakglassOverride {
		t.Error("BreakglassOverride initial: got true, want false")
	}

	s.SetBreakglassOverride(c.ID)
	got, _ := s.Get(c.ID)
	if !got.BreakglassOverride {
		t.Error("BreakglassOverride after set: got false, want true")
	}
}

func TestSQLStore_SetChallengePolicy(t *testing.T) {
	s := newTestSQLStore(t)
	c, err := s.Create("alice", "h", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	s.SetChallengePolicy(c.ID, "two-admin", 2, true, true)
	got, _ := s.Get(c.ID)
	if got.PolicyName != "two-admin" {
		t.Errorf("PolicyName: got %q, want two-admin", got.PolicyName)
	}
	if got.RequiredApprovals != 2 {
		t.Errorf("RequiredApprovals: got %d, want 2", got.RequiredApprovals)
	}
	if !got.RequireAdmin {
		t.Error("RequireAdmin: got false, want true")
	}
	if !got.BreakglassBypassAllowed {
		t.Error("BreakglassBypassAllowed: got false, want true")
	}

	// Re-apply with false booleans — verifies boolToInt(false)=0 round-trips
	// and the UPDATE genuinely overwrites rather than only OR-ing flags.
	s.SetChallengePolicy(c.ID, "solo", 1, false, false)
	got, _ = s.Get(c.ID)
	if got.PolicyName != "solo" || got.RequiredApprovals != 1 {
		t.Errorf("policy re-apply: got name=%q approvals=%d", got.PolicyName, got.RequiredApprovals)
	}
	if got.RequireAdmin || got.BreakglassBypassAllowed {
		t.Errorf("policy re-apply flags: got require_admin=%v bypass=%v, want both false",
			got.RequireAdmin, got.BreakglassBypassAllowed)
	}
}

// TestSQLStore_ConcurrentApprove fires N goroutines all attempting to
// Approve the same pending challenge. Exactly one must succeed; the rest
// must see ErrAlreadyResolved (the row-level lock turned the race into
// an ordered one). Catches regressions in the RMW transaction body.
func TestSQLStore_ConcurrentApprove(t *testing.T) {
	s := newTestSQLStore(t)
	c, err := s.Create("alice", "h", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const N = 20
	results := make(chan error, N)
	var start sync.WaitGroup
	start.Add(1)
	for i := 0; i < N; i++ {
		go func() {
			start.Wait()
			results <- s.Approve(c.ID, "approver")
		}()
	}
	start.Done()

	successes := 0
	conflicts := 0
	for i := 0; i < N; i++ {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrAlreadyResolved):
			conflicts++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if successes != 1 {
		t.Errorf("Approve successes: got %d, want exactly 1 (the rest should be ErrAlreadyResolved)", successes)
	}
	if conflicts != N-1 {
		t.Errorf("ErrAlreadyResolved count: got %d, want %d", conflicts, N-1)
	}
}

// TestSQLStore_ConcurrentOneTap covers the same race for ConsumeOneTap +
// ConsumeAndApprove. The one_tap_used flag flip must be atomic under
// concurrent contention.
func TestSQLStore_ConcurrentOneTap(t *testing.T) {
	s := newTestSQLStore(t)
	c, err := s.Create("alice", "h", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const N = 15
	results := make(chan error, N)
	var start sync.WaitGroup
	start.Add(1)
	for i := 0; i < N; i++ {
		go func() {
			start.Wait()
			results <- s.ConsumeAndApprove(c.ID, "approver")
		}()
	}
	start.Done()

	successes := 0
	other := 0
	for i := 0; i < N; i++ {
		if err := <-results; err == nil {
			successes++
		} else {
			other++
		}
	}
	if successes != 1 {
		t.Errorf("ConsumeAndApprove successes: got %d, want 1", successes)
	}
	if other != N-1 {
		t.Errorf("rejected count: got %d, want %d", other, N-1)
	}
}

func TestSQLStore_ReapExpiredChallenges(t *testing.T) {
	// Use an artificially short TTL so the reap goroutine has work.
	s := openTestStore(t, 100*time.Millisecond, time.Hour)

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
	// Use s.exec() so the placeholder is rewritten for whichever dialect is active.
	if _, err := s.exec(t.Context(), `UPDATE challenges SET expires_at = ? WHERE id = ?`, time.Now().Add(-time.Second).Unix(), c.ID); err != nil {
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
