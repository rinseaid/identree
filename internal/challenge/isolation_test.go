package challenge

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newIsolatedStores creates two RedisStore instances on the same miniredis server
// with different key prefixes.
func newIsolatedStores(t *testing.T, prefixA, prefixB string) (storeA, storeB *RedisStore, mr *miniredis.Miniredis) {
	t.Helper()
	mr = miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	storeA = NewRedisStore(client, prefixA, 30*time.Second, 5*time.Minute)
	storeB = NewRedisStore(client, prefixB, 30*time.Second, 5*time.Minute)
	t.Cleanup(func() {
		storeA.Stop()
		storeB.Stop()
	})
	return
}

func TestIsolation_ChallengeNotVisibleAcrossStores(t *testing.T) {
	storeA, storeB, _ := newIsolatedStores(t, "deploy-a:", "deploy-b:")

	// Create a challenge in store A.
	c, err := storeA.Create("alice", "web1", "", "debugging")
	if err != nil {
		t.Fatalf("storeA.Create: %v", err)
	}

	// Store A can see it.
	got, ok := storeA.Get(c.ID)
	if !ok {
		t.Fatal("storeA.Get returned not found for its own challenge")
	}
	if got.Username != "alice" {
		t.Fatalf("unexpected username: %s", got.Username)
	}

	// Store B cannot see it by ID.
	_, ok = storeB.Get(c.ID)
	if ok {
		t.Fatal("storeB.Get should not find storeA's challenge")
	}

	// Store B cannot see it by code.
	_, ok = storeB.GetByCode(c.UserCode)
	if ok {
		t.Fatal("storeB.GetByCode should not find storeA's challenge")
	}
}

func TestIsolation_ApproveDoesNotAffectOtherStorePendingCounter(t *testing.T) {
	storeA, storeB, _ := newIsolatedStores(t, "deploy-a:", "deploy-b:")

	// Create challenges in both stores.
	cA, err := storeA.Create("alice", "web1", "", "")
	if err != nil {
		t.Fatalf("storeA.Create: %v", err)
	}
	_, err = storeB.Create("alice", "web1", "", "")
	if err != nil {
		t.Fatalf("storeB.Create: %v", err)
	}

	// Both should have 1 pending each.
	if len(storeA.AllPendingChallenges()) != 1 {
		t.Fatalf("storeA expected 1 pending, got %d", len(storeA.AllPendingChallenges()))
	}
	if len(storeB.AllPendingChallenges()) != 1 {
		t.Fatalf("storeB expected 1 pending, got %d", len(storeB.AllPendingChallenges()))
	}

	// Approve in store A.
	if err := storeA.Approve(cA.ID, "admin"); err != nil {
		t.Fatalf("storeA.Approve: %v", err)
	}

	// Store A should have 0 pending.
	if len(storeA.AllPendingChallenges()) != 0 {
		t.Fatalf("storeA expected 0 pending after approve, got %d", len(storeA.AllPendingChallenges()))
	}

	// Store B should still have 1 pending (unaffected).
	if len(storeB.AllPendingChallenges()) != 1 {
		t.Fatalf("storeB expected 1 pending (unaffected), got %d", len(storeB.AllPendingChallenges()))
	}
}

func TestIsolation_GraceSessionRevokeDoesNotAffectOtherStore(t *testing.T) {
	storeA, storeB, _ := newIsolatedStores(t, "deploy-a:", "deploy-b:")

	// Create grace sessions in both stores for the same username+hostname.
	storeA.CreateGraceSession("alice", "web1", 5*time.Minute)
	storeB.CreateGraceSession("alice", "web1", 5*time.Minute)

	// Both should be within grace period.
	if !storeA.WithinGracePeriod("alice", "web1") {
		t.Fatal("storeA: expected within grace period")
	}
	if !storeB.WithinGracePeriod("alice", "web1") {
		t.Fatal("storeB: expected within grace period")
	}

	// Revoke in store A.
	storeA.RevokeSession("alice", "web1")

	// Store A should no longer be within grace period.
	if storeA.WithinGracePeriod("alice", "web1") {
		t.Fatal("storeA: expected NOT within grace period after revoke")
	}

	// Store B should be unaffected — still within grace period.
	if !storeB.WithinGracePeriod("alice", "web1") {
		t.Fatal("storeB: expected still within grace period (unaffected by storeA revoke)")
	}
}

func TestIsolation_ActionLogReturnsOnlyOwnEntries(t *testing.T) {
	storeA, storeB, _ := newIsolatedStores(t, "deploy-a:", "deploy-b:")

	// Log actions in each store.
	storeA.LogAction("alice", ActionApproved, "web1", "CODE-A1", "admin")
	storeA.LogAction("alice", ActionRejected, "web2", "CODE-A2", "admin")

	storeB.LogAction("alice", ActionApproved, "web1", "CODE-B1", "admin")

	// Store A should see 2 entries.
	histA := storeA.AllActionHistory()
	if len(histA) != 2 {
		t.Fatalf("storeA expected 2 action log entries, got %d", len(histA))
	}

	// Store B should see 1 entry.
	histB := storeB.AllActionHistory()
	if len(histB) != 1 {
		t.Fatalf("storeB expected 1 action log entry, got %d", len(histB))
	}

	// Verify the codes are correct for each store.
	for _, e := range histA {
		if e.Code != "CODE-A1" && e.Code != "CODE-A2" {
			t.Fatalf("storeA: unexpected code in action log: %s", e.Code)
		}
	}
	if histB[0].Code != "CODE-B1" {
		t.Fatalf("storeB: unexpected code in action log: %s", histB[0].Code)
	}
}

func TestIsolation_EmptyPrefixCollision(t *testing.T) {
	storeEmpty, storeNamed, _ := newIsolatedStores(t, "", "deploy-b:")

	// Create challenges.
	cEmpty, err := storeEmpty.Create("alice", "web1", "", "empty-prefix")
	if err != nil {
		t.Fatalf("storeEmpty.Create: %v", err)
	}
	cNamed, err := storeNamed.Create("alice", "web1", "", "named-prefix")
	if err != nil {
		t.Fatalf("storeNamed.Create: %v", err)
	}

	// Each store should only see its own challenge.
	_, ok := storeEmpty.Get(cEmpty.ID)
	if !ok {
		t.Fatal("storeEmpty cannot find its own challenge")
	}
	_, ok = storeNamed.Get(cNamed.ID)
	if !ok {
		t.Fatal("storeNamed cannot find its own challenge")
	}

	// Cross-check: neither store sees the other's challenge.
	_, ok = storeEmpty.Get(cNamed.ID)
	if ok {
		t.Fatal("storeEmpty should not see storeNamed's challenge")
	}
	_, ok = storeNamed.Get(cEmpty.ID)
	if ok {
		t.Fatal("storeNamed should not see storeEmpty's challenge")
	}

	// Grace sessions should also be isolated.
	storeEmpty.CreateGraceSession("bob", "host1", 5*time.Minute)
	storeNamed.CreateGraceSession("bob", "host1", 5*time.Minute)

	storeEmpty.RevokeSession("bob", "host1")
	if storeEmpty.WithinGracePeriod("bob", "host1") {
		t.Fatal("storeEmpty: should not be within grace after revoke")
	}
	if !storeNamed.WithinGracePeriod("bob", "host1") {
		t.Fatal("storeNamed: should still be within grace (unaffected)")
	}

	// Action logs should be isolated.
	storeEmpty.LogAction("bob", ActionApproved, "host1", "E1", "")
	storeNamed.LogAction("bob", ActionApproved, "host1", "N1", "")
	storeNamed.LogAction("bob", ActionRejected, "host1", "N2", "")

	emptyHist := storeEmpty.AllActionHistory()
	namedHist := storeNamed.AllActionHistory()
	if len(emptyHist) != 1 {
		t.Fatalf("storeEmpty expected 1 action log entry, got %d", len(emptyHist))
	}
	if len(namedHist) != 2 {
		t.Fatalf("storeNamed expected 2 action log entries, got %d", len(namedHist))
	}

	// Pending counters should be isolated.
	if len(storeEmpty.AllPendingChallenges()) != 1 {
		t.Fatalf("storeEmpty expected 1 pending, got %d", len(storeEmpty.AllPendingChallenges()))
	}
	if len(storeNamed.AllPendingChallenges()) != 1 {
		t.Fatalf("storeNamed expected 1 pending, got %d", len(storeNamed.AllPendingChallenges()))
	}
}
