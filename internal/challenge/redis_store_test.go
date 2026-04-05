package challenge

import (
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestRedisStore(t *testing.T) (*RedisStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewRedisStore(client, "test:", 30*time.Second, 5*time.Minute)
	t.Cleanup(func() {
		store.Stop()
	})
	return store, mr
}

func TestRedisStore_CreateAndGet(t *testing.T) {
	store, _ := newTestRedisStore(t)

	c, err := store.Create("alice", "web1", "", "debugging")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if c.Username != "alice" || c.Hostname != "web1" || c.Reason != "debugging" {
		t.Fatalf("unexpected challenge fields: %+v", c)
	}
	if c.Status != StatusPending {
		t.Fatalf("expected pending, got %s", c.Status)
	}

	// Get by ID.
	got, ok := store.Get(c.ID)
	if !ok {
		t.Fatal("Get returned not found")
	}
	if got.ID != c.ID || got.Username != "alice" {
		t.Fatalf("Get returned wrong challenge: %+v", got)
	}

	// Get by code.
	got2, ok := store.GetByCode(c.UserCode)
	if !ok {
		t.Fatal("GetByCode returned not found")
	}
	if got2.ID != c.ID {
		t.Fatalf("GetByCode returned wrong challenge: %+v", got2)
	}
}

func TestRedisStore_Approve(t *testing.T) {
	store, _ := newTestRedisStore(t)

	c, err := store.Create("bob", "host1", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.Approve(c.ID, "bob"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	got, ok := store.Get(c.ID)
	if !ok {
		t.Fatal("Get after Approve returned not found")
	}
	if got.Status != StatusApproved {
		t.Fatalf("expected approved, got %s", got.Status)
	}
	if got.ApprovedBy != "bob" {
		t.Fatalf("expected approvedBy bob, got %s", got.ApprovedBy)
	}

	// Double approve should fail.
	if err := store.Approve(c.ID, "bob"); err == nil {
		t.Fatal("expected error on double approve")
	}
}

func TestRedisStore_Deny(t *testing.T) {
	store, _ := newTestRedisStore(t)

	c, err := store.Create("carol", "host1", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.Deny(c.ID, "policy violation"); err != nil {
		t.Fatalf("Deny: %v", err)
	}

	got, ok := store.Get(c.ID)
	if !ok {
		t.Fatal("Get after Deny returned not found")
	}
	if got.Status != StatusDenied {
		t.Fatalf("expected denied, got %s", got.Status)
	}
	if got.DenyReason != "policy violation" {
		t.Fatalf("expected deny reason 'policy violation', got %q", got.DenyReason)
	}
}

func TestRedisStore_SetNonce(t *testing.T) {
	store, _ := newTestRedisStore(t)

	c, err := store.Create("dave", "host1", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.SetNonce(c.ID, "testnonce123"); err != nil {
		t.Fatalf("SetNonce: %v", err)
	}

	// Second call should fail (nonce already set).
	if err := store.SetNonce(c.ID, "anothernonce"); err == nil {
		t.Fatal("expected error on second SetNonce")
	}
}

func TestRedisStore_GraceSessions(t *testing.T) {
	store, _ := newTestRedisStore(t)

	// Create a grace session.
	store.CreateGraceSession("alice", "web1", 5*time.Minute)

	if !store.WithinGracePeriod("alice", "web1") {
		t.Fatal("expected within grace period")
	}

	remaining := store.GraceRemaining("alice", "web1")
	if remaining <= 0 || remaining > 5*time.Minute {
		t.Fatalf("unexpected grace remaining: %v", remaining)
	}

	sessions := store.ActiveSessions("alice")
	if len(sessions) != 1 {
		t.Fatalf("expected 1 active session, got %d", len(sessions))
	}
	if sessions[0].Hostname != "web1" {
		t.Fatalf("expected hostname web1, got %s", sessions[0].Hostname)
	}

	// Revoke.
	store.RevokeSession("alice", "web1")
	if store.WithinGracePeriod("alice", "web1") {
		t.Fatal("expected not within grace period after revoke")
	}
}

func TestRedisStore_GraceExtend(t *testing.T) {
	store, _ := newTestRedisStore(t)

	store.CreateGraceSession("alice", "web1", 1*time.Minute)

	// Extend should work (less than 75% remaining of 5min grace).
	dur, err := store.ExtendGraceSession("alice", "web1")
	if err != nil {
		t.Fatalf("ExtendGraceSession: %v", err)
	}
	if dur <= 0 {
		t.Fatal("expected positive duration from extend")
	}

	// ForceExtend should always work.
	dur2 := store.ForceExtendGraceSession("alice", "web1")
	if dur2 <= 0 {
		t.Fatal("expected positive duration from force extend")
	}
}

func TestRedisStore_ConsumeOneTap(t *testing.T) {
	store, _ := newTestRedisStore(t)

	c, err := store.Create("eve", "host1", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.ConsumeOneTap(c.ID); err != nil {
		t.Fatalf("ConsumeOneTap: %v", err)
	}

	// Second consume should fail.
	if err := store.ConsumeOneTap(c.ID); err == nil {
		t.Fatal("expected error on second ConsumeOneTap")
	}
}

func TestRedisStore_ConsumeAndApprove(t *testing.T) {
	store, _ := newTestRedisStore(t)

	c, err := store.Create("frank", "host1", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.ConsumeAndApprove(c.ID, "frank"); err != nil {
		t.Fatalf("ConsumeAndApprove: %v", err)
	}

	got, ok := store.Get(c.ID)
	if !ok {
		t.Fatal("Get after ConsumeAndApprove returned not found")
	}
	if got.Status != StatusApproved {
		t.Fatalf("expected approved, got %s", got.Status)
	}

	// Second ConsumeAndApprove should fail.
	c2, err := store.Create("frank", "host2", "", "")
	if err != nil {
		t.Fatalf("Create 2: %v", err)
	}
	// Set the one-tap for c.ID, then try ConsumeAndApprove on c2.
	// c2 should still be consumable.
	if err := store.ConsumeAndApprove(c2.ID, "frank"); err != nil {
		t.Fatalf("ConsumeAndApprove on c2: %v", err)
	}
}

func TestRedisStore_ActionLog(t *testing.T) {
	store, _ := newTestRedisStore(t)

	store.LogAction("alice", ActionApproved, "web1", "CODE1", "")
	store.LogActionWithReason("alice", ActionRejected, "web2", "CODE2", "admin", "testing")
	store.LogActionAt("alice", ActionAutoApproved, "web1", "CODE3", "", time.Now().Add(-time.Hour))

	history := store.ActionHistory("alice", 0)
	if len(history) != 3 {
		t.Fatalf("expected 3 action log entries, got %d", len(history))
	}
	// Most recent first (LPUSH ordering).
	if history[0].Action != ActionAutoApproved {
		t.Fatalf("expected first entry to be auto_approved, got %s", history[0].Action)
	}

	// With limit.
	limited := store.ActionHistory("alice", 2)
	if len(limited) != 2 {
		t.Fatalf("expected 2 limited entries, got %d", len(limited))
	}

	// AllActionHistory.
	all := store.AllActionHistory()
	if len(all) != 3 {
		t.Fatalf("expected 3 total entries, got %d", len(all))
	}

	// AllActionHistoryWithUsers.
	allWithUsers := store.AllActionHistoryWithUsers()
	if len(allWithUsers) != 3 {
		t.Fatalf("expected 3 total entries with users, got %d", len(allWithUsers))
	}
}

func TestRedisStore_PendingCounterAccuracy(t *testing.T) {
	store, _ := newTestRedisStore(t)

	// Create 3 challenges.
	c1, _ := store.Create("alice", "h1", "", "")
	c2, _ := store.Create("alice", "h2", "", "")
	_, _ = store.Create("alice", "h3", "", "")

	// Approve one, deny one.
	store.Approve(c1.ID, "alice")
	store.Deny(c2.ID, "")

	// Should have 1 pending.
	pending := store.PendingChallenges("alice")
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}
}

func TestRedisStore_EscrowOperations(t *testing.T) {
	store, _ := newTestRedisStore(t)

	store.RecordEscrow("web1", "item-123", "vault-456")

	escrowed := store.EscrowedHosts()
	if len(escrowed) != 1 {
		t.Fatalf("expected 1 escrowed host, got %d", len(escrowed))
	}
	if escrowed["web1"].ItemID != "item-123" {
		t.Fatalf("unexpected escrow record: %+v", escrowed["web1"])
	}

	// Ciphertext.
	store.StoreEscrowCiphertext("web1", "encrypted-data")
	ct, ok := store.GetEscrowCiphertext("web1")
	if !ok || ct != "encrypted-data" {
		t.Fatalf("unexpected ciphertext: %s, found: %v", ct, ok)
	}
}

func TestRedisStore_SessionNonces(t *testing.T) {
	store, _ := newTestRedisStore(t)

	data := SessionNonceData{
		IssuedAt:     time.Now(),
		CodeVerifier: "verifier123",
		ClientIP:     "1.2.3.4",
	}

	if err := store.StoreSessionNonce("nonce1", data, 5*time.Minute); err != nil {
		t.Fatalf("StoreSessionNonce: %v", err)
	}

	got, ok := store.GetSessionNonce("nonce1")
	if !ok {
		t.Fatal("GetSessionNonce returned not found")
	}
	if got.CodeVerifier != "verifier123" || got.ClientIP != "1.2.3.4" {
		t.Fatalf("unexpected session nonce data: %+v", got)
	}

	store.DeleteSessionNonce("nonce1")
	_, ok = store.GetSessionNonce("nonce1")
	if ok {
		t.Fatal("expected nonce to be deleted")
	}
}

func TestRedisStore_HealthCheck(t *testing.T) {
	store, _ := newTestRedisStore(t)

	if err := store.HealthCheck(); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
}

func TestRedisStore_Stop(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewRedisStore(client, "test:", 30*time.Second, 5*time.Minute)

	// Stop should not panic and should be idempotent.
	store.Stop()
}

func TestRedisStore_ConcurrentApproveDeny(t *testing.T) {
	store, _ := newTestRedisStore(t)

	c, err := store.Create("alice", "host1", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var wg sync.WaitGroup
	var approveErr, denyErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		approveErr = store.Approve(c.ID, "alice")
	}()
	go func() {
		defer wg.Done()
		denyErr = store.Deny(c.ID, "")
	}()
	wg.Wait()

	// Exactly one should succeed.
	if approveErr == nil && denyErr == nil {
		t.Fatal("both approve and deny succeeded — atomicity violation")
	}
	if approveErr != nil && denyErr != nil {
		t.Fatal("both approve and deny failed")
	}
}

func TestRedisStore_TTLExpiry(t *testing.T) {
	store, mr := newTestRedisStore(t)

	c, err := store.Create("alice", "host1", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Verify challenge exists.
	_, ok := store.Get(c.ID)
	if !ok {
		t.Fatal("expected challenge to exist before fast-forward")
	}

	// Fast-forward past TTL.
	mr.FastForward(2 * time.Minute) // TTL is 30s + 60s buffer = 90s

	// Challenge should be gone from Redis.
	_, ok = store.Get(c.ID)
	if ok {
		t.Fatal("expected challenge to be expired after fast-forward")
	}
}

func TestRedisStore_PendingCounterReconciliation(t *testing.T) {
	store, _ := newTestRedisStore(t)

	// Create some challenges.
	store.Create("alice", "h1", "", "")
	store.Create("alice", "h2", "", "")

	// Manually corrupt the counter.
	store.client.Set(store.ctx(), store.pendingTotalKey(), 999, 0)

	// Run reconciliation.
	store.reconcilePendingCounters()

	// Counter should be corrected.
	val, _ := store.client.Get(store.ctx(), store.pendingTotalKey()).Int()
	if val != 2 {
		t.Fatalf("expected pending total 2 after reconciliation, got %d", val)
	}
}

func TestRedisStore_AutoApproveIfWithinGracePeriod(t *testing.T) {
	store, _ := newTestRedisStore(t)

	// Create grace session first.
	store.CreateGraceSession("alice", "web1", 5*time.Minute)

	// Create a challenge.
	c, err := store.Create("alice", "web1", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Should auto-approve.
	if !store.AutoApproveIfWithinGracePeriod("alice", "web1", c.ID) {
		t.Fatal("expected auto-approve within grace period")
	}

	got, ok := store.Get(c.ID)
	if !ok {
		t.Fatal("Get after auto-approve returned not found")
	}
	if got.Status != StatusApproved {
		t.Fatalf("expected approved, got %s", got.Status)
	}
}

func TestRedisStore_AllUsers(t *testing.T) {
	store, _ := newTestRedisStore(t)

	store.LogAction("alice", ActionApproved, "h1", "", "")
	store.LogAction("bob", ActionApproved, "h2", "", "")

	users := store.AllUsers()
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
}

func TestRedisStore_RemoveUser(t *testing.T) {
	store, _ := newTestRedisStore(t)

	store.LogAction("alice", ActionApproved, "h1", "", "")
	store.CreateGraceSession("alice", "h1", 5*time.Minute)
	c, _ := store.Create("alice", "h1", "", "")

	store.RemoveUser("alice")

	// Challenge should be gone.
	_, ok := store.Get(c.ID)
	if ok {
		t.Fatal("expected challenge to be removed")
	}

	// Grace session should be gone.
	if store.WithinGracePeriod("alice", "h1") {
		t.Fatal("expected grace session to be removed")
	}

	// User should be removed from all users.
	users := store.AllUsers()
	for _, u := range users {
		if u == "alice" {
			t.Fatal("expected alice to be removed from all users")
		}
	}
}

func TestRedisStore_RemoveHost(t *testing.T) {
	store, _ := newTestRedisStore(t)

	store.LogAction("alice", ActionApproved, "web1", "", "")
	store.RecordEscrow("web1", "item1", "vault1")
	store.CreateGraceSession("alice", "web1", 5*time.Minute)

	store.RemoveHost("web1")

	escrowed := store.EscrowedHosts()
	if len(escrowed) != 0 {
		t.Fatalf("expected 0 escrowed hosts after remove, got %d", len(escrowed))
	}
}

func TestRedisStore_EscrowTokenReplay(t *testing.T) {
	store, _ := newTestRedisStore(t)

	seen := store.CheckAndRecordEscrowToken("host1:12345")
	if seen {
		t.Fatal("expected token not seen on first check")
	}

	seen = store.CheckAndRecordEscrowToken("host1:12345")
	if !seen {
		t.Fatal("expected token seen on second check")
	}

	count := store.UsedEscrowTokenCount()
	if count != 1 {
		t.Fatalf("expected 1 used escrow token, got %d", count)
	}
}

func TestRedisStore_RevokedNonces(t *testing.T) {
	store, _ := newTestRedisStore(t)

	now := time.Now()
	store.PersistRevokedNonce("nonce1", now)
	store.PersistRevokedNonce("nonce2", now.Add(-time.Minute))

	nonces := store.LoadRevokedNonces()
	if len(nonces) != 2 {
		t.Fatalf("expected 2 revoked nonces, got %d", len(nonces))
	}
}

func TestRedisStore_RevokedAdminSessions(t *testing.T) {
	store, _ := newTestRedisStore(t)

	now := time.Now()
	store.PersistRevokedAdminSession("admin1", now)

	sessions := store.LoadRevokedAdminSessions()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 revoked admin session, got %d", len(sessions))
	}
}

func TestRedisStore_HostRotation(t *testing.T) {
	store, _ := newTestRedisStore(t)

	store.SetHostRotateBefore("web1")
	ts := store.HostRotateBefore("web1")
	if ts.IsZero() {
		t.Fatal("expected non-zero HostRotateBefore")
	}

	store.SetAllHostsRotateBefore([]string{"web2", "web3"})
	if store.HostRotateBefore("web2").IsZero() {
		t.Fatal("expected non-zero HostRotateBefore for web2")
	}
	if store.HostRotateBefore("web3").IsZero() {
		t.Fatal("expected non-zero HostRotateBefore for web3")
	}
}

func TestRedisStore_OIDCAuth(t *testing.T) {
	store, _ := newTestRedisStore(t)

	store.RecordOIDCAuth("alice")
	ts := store.LastOIDCAuth("alice")
	if ts.IsZero() {
		t.Fatal("expected non-zero LastOIDCAuth")
	}

	// Unknown user.
	ts2 := store.LastOIDCAuth("nobody")
	if !ts2.IsZero() {
		t.Fatal("expected zero LastOIDCAuth for unknown user")
	}
}
