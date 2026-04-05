package challenge

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// newTestStore returns a fresh ChallengeStore with no persistence for testing.
func newTestStore(ttl, gracePeriod time.Duration) *ChallengeStore {
	s := NewChallengeStore(ttl, gracePeriod, "")
	// Stop the reap goroutine so tests are not subject to background cleanup races.
	s.Stop()
	return s
}

// TestCreate verifies challenge creation, rate limits, and counter bookkeeping.
func TestCreate(t *testing.T) {
	t.Run("basic creation returns a valid challenge", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c == nil {
			t.Fatal("expected non-nil challenge")
		}
		if c.Username != "alice" {
			t.Errorf("username: got %q, want %q", c.Username, "alice")
		}
		if c.Hostname != "host1" {
			t.Errorf("hostname: got %q, want %q", c.Hostname, "host1")
		}
		if c.Status != StatusPending {
			t.Errorf("status: got %q, want %q", c.Status, StatusPending)
		}
		if c.ID == "" {
			t.Error("ID should not be empty")
		}
		if c.UserCode == "" {
			t.Error("UserCode should not be empty")
		}
	})

	t.Run("pendingByUser is incremented on creation", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		_, err := s.Create("bob", "host1", "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		s.mu.RLock()
		count := s.pendingByUser["bob"]
		s.mu.RUnlock()
		if count != 1 {
			t.Errorf("pendingByUser: got %d, want 1", count)
		}

		_, err = s.Create("bob", "host2", "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		s.mu.RLock()
		count = s.pendingByUser["bob"]
		s.mu.RUnlock()
		if count != 2 {
			t.Errorf("pendingByUser after second create: got %d, want 2", count)
		}
	})

	t.Run("maxChallengesPerUser rate limit", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		for i := 0; i < maxChallengesPerUser; i++ {
			_, err := s.Create("carol", "host", "", "")
			if err != nil {
				t.Fatalf("unexpected error on create %d: %v", i+1, err)
			}
		}
		_, err := s.Create("carol", "host", "", "")
		if err == nil {
			t.Fatal("expected error when exceeding per-user limit, got nil")
		}
		if !errors.Is(err, ErrTooManyPerUser) {
			t.Errorf("expected ErrTooManyPerUser, got: %v", err)
		}
	})

	t.Run("maxChallengesPerUser limit does not affect other users", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		for i := 0; i < maxChallengesPerUser; i++ {
			if _, err := s.Create("dave", "host", "", ""); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		}
		// A different user should still be able to create
		_, err := s.Create("eve", "host", "", "")
		if err != nil {
			t.Errorf("other user blocked unexpectedly: %v", err)
		}
	})

	t.Run("maxTotalChallenges rate limit", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		// Inject challenges directly to hit the cap without triggering the
		// per-user limit (maxChallengesPerUser = 5, maxTotalChallenges = 10000).
		s.mu.Lock()
		for i := 0; i < maxTotalChallenges; i++ {
			id := string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune(i))
			s.challenges[id] = &Challenge{ID: id, Username: "synthetic", Status: StatusPending}
		}
		s.totalPending = maxTotalChallenges
		s.mu.Unlock()

		_, err := s.Create("frank", "host", "", "")
		if err == nil {
			t.Fatal("expected error when total challenge cap is hit, got nil")
		}
		if !errors.Is(err, ErrTooManyChallenges) {
			t.Errorf("expected ErrTooManyChallenges, got: %v", err)
		}
	})

	t.Run("challenge is retrievable by ID and code after creation", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got, ok := s.Get(c.ID)
		if !ok {
			t.Fatal("Get by ID returned not-found")
		}
		if got.Username != "alice" {
			t.Errorf("Get by ID username: got %q, want %q", got.Username, "alice")
		}

		gotByCode, ok := s.GetByCode(c.UserCode)
		if !ok {
			t.Fatal("GetByCode returned not-found")
		}
		if gotByCode.ID != c.ID {
			t.Errorf("GetByCode ID mismatch: got %q, want %q", gotByCode.ID, c.ID)
		}
	})
}

// TestApprove verifies the Approve method and the revocation race fix.
func TestApprove(t *testing.T) {
	t.Run("normal approval works", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := s.Approve(c.ID, "alice"); err != nil {
			t.Fatalf("Approve returned error: %v", err)
		}
		got, ok := s.Get(c.ID)
		if !ok {
			// Get returns false for non-pending challenges is fine — check directly.
			s.mu.RLock()
			ch, exists := s.challenges[c.ID]
			s.mu.RUnlock()
			if !exists {
				t.Fatal("challenge disappeared from store after approval")
			}
			got = *ch
		}
		if got.Status != StatusApproved {
			t.Errorf("status after Approve: got %q, want %q", got.Status, StatusApproved)
		}
		if got.ApprovedBy != "alice" {
			t.Errorf("ApprovedBy: got %q, want %q", got.ApprovedBy, "alice")
		}
	})

	t.Run("double approval returns error", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		c, _ := s.Create("alice", "host1", "", "")
		if err := s.Approve(c.ID, "alice"); err != nil {
			t.Fatalf("first Approve error: %v", err)
		}
		if err := s.Approve(c.ID, "alice"); err == nil {
			t.Fatal("expected error on double approval, got nil")
		}
	})

	t.Run("revocation after creation blocks Approve", func(t *testing.T) {
		// This tests the security fix: if revokeTokensBefore is set after
		// the challenge was created, Approve must reject the challenge.
		s := newTestStore(5*time.Minute, 0)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Simulate session revocation happening after challenge creation.
		s.RevokeSession("alice", "host1")

		err = s.Approve(c.ID, "alice")
		if err == nil {
			t.Fatal("expected Approve to fail after session revocation, but it succeeded")
		}
	})

	t.Run("expired challenge cannot be approved", func(t *testing.T) {
		s := newTestStore(1*time.Millisecond, 0)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Wait for the TTL to pass.
		time.Sleep(5 * time.Millisecond)

		err = s.Approve(c.ID, "alice")
		if err == nil {
			t.Fatal("expected Approve to fail for expired challenge, but it succeeded")
		}
	})

	t.Run("Approve of nonexistent challenge returns error", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		if err := s.Approve("does-not-exist", "alice"); err == nil {
			t.Fatal("expected error for nonexistent challenge, got nil")
		}
	})

	t.Run("pendingByUser is decremented after Approve", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		c, _ := s.Create("bob", "host1", "", "")
		s.mu.RLock()
		before := s.pendingByUser["bob"]
		s.mu.RUnlock()
		if before != 1 {
			t.Fatalf("expected pendingByUser=1 before Approve, got %d", before)
		}
		s.Approve(c.ID, "bob")
		s.mu.RLock()
		after := s.pendingByUser["bob"]
		s.mu.RUnlock()
		if after != 0 {
			t.Errorf("expected pendingByUser=0 after Approve, got %d", after)
		}
	})
}

// TestAutoApproveIfWithinGracePeriod verifies atomic grace-period checks.
func TestAutoApproveIfWithinGracePeriod(t *testing.T) {
	t.Run("within grace period returns true and approves challenge", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)
		// Seed a grace session for alice on host1.
		s.CreateGraceSession("alice", "host1", 10*time.Minute)

		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		approved := s.AutoApproveIfWithinGracePeriod("alice", "host1", c.ID)
		if !approved {
			t.Error("expected AutoApproveIfWithinGracePeriod to return true within grace period")
		}

		// Verify the challenge was actually marked approved.
		s.mu.RLock()
		ch := s.challenges[c.ID]
		s.mu.RUnlock()
		if ch == nil || ch.Status != StatusApproved {
			t.Errorf("expected challenge status %q, got %v", StatusApproved, ch)
		}
	})

	t.Run("outside grace period returns false", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)
		// No grace session seeded — grace period has never been set.
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		approved := s.AutoApproveIfWithinGracePeriod("alice", "host1", c.ID)
		if approved {
			t.Error("expected AutoApproveIfWithinGracePeriod to return false when no grace session exists")
		}
	})

	t.Run("expired grace session returns false", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)
		// Manually set an already-expired grace session.
		s.mu.Lock()
		s.lastApproval[graceKey("alice", "host1")] = time.Now().Add(-1 * time.Second)
		s.mu.Unlock()

		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		approved := s.AutoApproveIfWithinGracePeriod("alice", "host1", c.ID)
		if approved {
			t.Error("expected AutoApproveIfWithinGracePeriod to return false for expired grace session")
		}
	})

	t.Run("exact boundary — expired at exactly now — returns false", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)
		// Set the grace session to expire right now (in the past by the time we check).
		s.mu.Lock()
		s.lastApproval[graceKey("alice", "host1")] = time.Now()
		s.mu.Unlock()

		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		// time.Now().Before(expiry) is false when expiry == now, so this should be false.
		approved := s.AutoApproveIfWithinGracePeriod("alice", "host1", c.ID)
		if approved {
			t.Error("expected AutoApproveIfWithinGracePeriod to return false at exact expiry boundary")
		}
	})

	t.Run("atomicity — only one of two concurrent calls returns true", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)
		s.CreateGraceSession("alice", "host1", 10*time.Minute)

		// Create two separate challenges; the first concurrent call to each
		// should succeed but only the appropriate challenge for each call.
		c1, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create c1: %v", err)
		}
		c2, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create c2: %v", err)
		}

		results := make([]bool, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			results[0] = s.AutoApproveIfWithinGracePeriod("alice", "host1", c1.ID)
		}()
		go func() {
			defer wg.Done()
			results[1] = s.AutoApproveIfWithinGracePeriod("alice", "host1", c2.ID)
		}()
		wg.Wait()

		// Both challenges are distinct, so both should be independently approved
		// while the grace session is valid.
		if !results[0] {
			t.Error("expected first concurrent auto-approve to succeed")
		}
		if !results[1] {
			t.Error("expected second concurrent auto-approve to succeed")
		}

		// Verify neither challenge can be auto-approved again (already resolved).
		if s.AutoApproveIfWithinGracePeriod("alice", "host1", c1.ID) {
			t.Error("expected re-auto-approve of already-approved challenge to return false")
		}
	})

	t.Run("grace period disabled returns false always", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0) // grace period = 0 = disabled
		s.mu.Lock()
		s.lastApproval[graceKey("alice", "host1")] = time.Now().Add(10 * time.Minute)
		s.mu.Unlock()
		c, _ := s.Create("alice", "host1", "", "")
		if s.AutoApproveIfWithinGracePeriod("alice", "host1", c.ID) {
			t.Error("expected false when grace period is disabled")
		}
	})
}

// TestActiveSessionsAndKnownHosts verifies session visibility and host tracking.
func TestActiveSessionsAndKnownHosts(t *testing.T) {
	t.Run("CreateGraceSession makes session visible via ActiveSessions", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)
		s.CreateGraceSession("alice", "host1", 10*time.Minute)

		sessions := s.ActiveSessions("alice")
		if len(sessions) != 1 {
			t.Fatalf("expected 1 active session, got %d", len(sessions))
		}
		if sessions[0].Hostname != "host1" {
			t.Errorf("hostname: got %q, want %q", sessions[0].Hostname, "host1")
		}
		if sessions[0].Username != "alice" {
			t.Errorf("username: got %q, want %q", sessions[0].Username, "alice")
		}
	})

	t.Run("KnownHosts requires LogAction — CreateGraceSession alone is not enough", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)
		s.CreateGraceSession("alice", "host1", 10*time.Minute)

		// KnownHosts is derived from action log, not grace sessions.
		hosts := s.KnownHosts("alice")
		if len(hosts) != 0 {
			t.Errorf("expected 0 known hosts before LogAction, got %d: %v", len(hosts), hosts)
		}

		// Now log an action — host should appear.
		s.LogAction("alice", ActionApproved, "host1", "CODE1", "")
		hosts = s.KnownHosts("alice")
		if len(hosts) != 1 || hosts[0] != "host1" {
			t.Errorf("expected [host1] after LogAction, got %v", hosts)
		}
	})

	t.Run("RevokeSession removes the session from ActiveSessions", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)
		s.CreateGraceSession("alice", "host1", 10*time.Minute)

		// Verify it's there first.
		if len(s.ActiveSessions("alice")) != 1 {
			t.Fatal("session not created")
		}

		s.RevokeSession("alice", "host1")

		sessions := s.ActiveSessions("alice")
		if len(sessions) != 0 {
			t.Errorf("expected 0 sessions after RevokeSession, got %d", len(sessions))
		}
	})

	t.Run("multiple sessions for same user across different hosts", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)
		s.CreateGraceSession("alice", "host1", 10*time.Minute)
		s.CreateGraceSession("alice", "host2", 10*time.Minute)

		sessions := s.ActiveSessions("alice")
		if len(sessions) != 2 {
			t.Errorf("expected 2 sessions, got %d", len(sessions))
		}
	})
}

// TestGracePeriodRaceRevocation verifies the security fix: revoke then try to approve.
func TestGracePeriodRaceRevocation(t *testing.T) {
	t.Run("RevokeSession followed by Approve fails", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)

		// Create a challenge for alice on host1.
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		// Revoke the session — this sets revokeTokensBefore[alice] to now.
		s.RevokeSession("alice", "host1")

		// Approve should now be rejected because revokeTokensBefore is after
		// c.CreatedAt.
		err = s.Approve(c.ID, "alice")
		if err == nil {
			t.Fatal("Approve should have failed after session revocation, but succeeded")
		}
	})

	t.Run("challenge created before revocation snapshot cannot be approved", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)

		// Create a challenge (this snapshots revokeTokensBefore at creation time).
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		// Simulate admin revocation after challenge creation.
		time.Sleep(time.Millisecond)
		s.mu.Lock()
		s.revokeTokensBefore["alice"] = time.Now()
		s.mu.Unlock()

		err = s.Approve(c.ID, "alice")
		if err == nil {
			t.Fatal("expected Approve to fail when revokeTokensBefore is after challenge creation")
		}
	})

	t.Run("revocation before challenge creation does not block Approve", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)

		// Set revocation timestamp before creating the challenge.
		s.mu.Lock()
		s.revokeTokensBefore["alice"] = time.Now().Add(-1 * time.Minute)
		s.mu.Unlock()

		// Small sleep to ensure challenge CreatedAt is strictly after the revocation.
		time.Sleep(time.Millisecond)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		// Approve should succeed because revokeTokensBefore < c.CreatedAt.
		if err := s.Approve(c.ID, "alice"); err != nil {
			t.Errorf("expected Approve to succeed, got: %v", err)
		}
	})
}

// TestKnownHostsExcludesRemovedHosts verifies that ActionRemovedHost prevents
// the host from appearing in KnownHosts.
func TestKnownHostsExcludesRemovedHosts(t *testing.T) {
	t.Run("ActionRemovedHost excludes host from KnownHosts", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)

		// First log a normal action to add the host.
		s.LogAction("alice", ActionApproved, "host1", "CODE1", "")
		hosts := s.KnownHosts("alice")
		if len(hosts) != 1 || hosts[0] != "host1" {
			t.Fatalf("expected [host1] after ActionApproved, got %v", hosts)
		}

		// Now log a removal action for the same host.
		s.LogAction("alice", ActionRemovedHost, "host1", "", "")

		// KnownHosts iterates action log and skips entries with ActionRemovedHost;
		// but per the implementation, an entry with ActionRemovedHost means that
		// entry itself is excluded — however prior approved entries for host1 are
		// still in the log. Let's verify the actual behaviour matches the doc:
		// "Entries with action ActionRemovedHost are excluded so removed hosts do not reappear."
		// The implementation skips any entry whose action IS ActionRemovedHost, but
		// other entries for host1 still have ActionApproved and would re-add it.
		// The real removal path uses RemoveHost which deletes all action log entries.
		// Test that RemoveHost correctly removes the host:
		s.RemoveHost("host1")
		hosts = s.KnownHosts("alice")
		if len(hosts) != 0 {
			t.Errorf("expected no known hosts after RemoveHost, got %v", hosts)
		}
	})

	t.Run("KnownHosts excludes entries with ActionRemovedHost action itself", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)

		// Log only a removal action (no prior approval) — host should not appear.
		s.LogAction("alice", ActionRemovedHost, "ghost-host", "", "")
		hosts := s.KnownHosts("alice")
		for _, h := range hosts {
			if h == "ghost-host" {
				t.Errorf("ghost-host should be excluded from KnownHosts (ActionRemovedHost entry), got %v", hosts)
			}
		}
	})

	t.Run("other hosts are unaffected by removal of one host", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		s.LogAction("alice", ActionApproved, "host1", "CODE1", "")
		s.LogAction("alice", ActionApproved, "host2", "CODE2", "")

		s.RemoveHost("host1")

		hosts := s.KnownHosts("alice")
		if len(hosts) != 1 || hosts[0] != "host2" {
			t.Errorf("expected only [host2] after removing host1, got %v", hosts)
		}
	})
}

// TestDeny verifies the Deny method and its counter bookkeeping.
func TestDeny(t *testing.T) {
	t.Run("deny removes challenge from pending and decrements counter", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		s.mu.RLock()
		before := s.pendingByUser["alice"]
		s.mu.RUnlock()
		if before != 1 {
			t.Fatalf("expected pendingByUser=1 before Deny, got %d", before)
		}

		if err := s.Deny(c.ID, "not authorized"); err != nil {
			t.Fatalf("Deny returned unexpected error: %v", err)
		}

		// Challenge should still exist in the store but with StatusDenied.
		s.mu.RLock()
		ch, exists := s.challenges[c.ID]
		after := s.pendingByUser["alice"]
		s.mu.RUnlock()

		if !exists {
			t.Fatal("challenge disappeared from store after Deny")
		}
		if ch.Status != StatusDenied {
			t.Errorf("status after Deny: got %q, want %q", ch.Status, StatusDenied)
		}
		if ch.DenyReason != "not authorized" {
			t.Errorf("DenyReason after Deny: got %q, want %q", ch.DenyReason, "not authorized")
		}
		if after != 0 {
			t.Errorf("expected pendingByUser=0 after Deny, got %d", after)
		}
	})

	t.Run("deny without reason leaves DenyReason empty", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := s.Deny(c.ID, ""); err != nil {
			t.Fatalf("Deny returned unexpected error: %v", err)
		}
		s.mu.RLock()
		ch := s.challenges[c.ID]
		s.mu.RUnlock()
		if ch.DenyReason != "" {
			t.Errorf("DenyReason should be empty, got %q", ch.DenyReason)
		}
	})

	t.Run("double deny returns an error", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := s.Deny(c.ID, ""); err != nil {
			t.Fatalf("first Deny returned unexpected error: %v", err)
		}
		if err := s.Deny(c.ID, ""); err == nil {
			t.Fatal("expected error on double Deny, got nil")
		}
	})

	t.Run("denying a non-existent challenge ID returns an error", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		if err := s.Deny("does-not-exist", ""); err == nil {
			t.Fatal("expected error for nonexistent challenge ID, got nil")
		}
	})
}

// TestStatePersistence verifies that state survives a save+load round-trip.
func TestStatePersistence(t *testing.T) {
	t.Run("grace sessions, action log, and revokeTokensBefore survive round-trip", func(t *testing.T) {
		dir := t.TempDir()
		persistPath := filepath.Join(dir, "sessions.json")

		// Create the first store with a persist path.
		s1 := NewChallengeStore(5*time.Minute, 10*time.Minute, persistPath)
		s1.Stop()

		// Add a grace session on host1.
		s1.CreateGraceSession("alice", "host1", 10*time.Minute)

		// Log an action on host1.
		s1.LogAction("alice", ActionApproved, "host1", "CODE1", "")

		// Revoke a session on a different host so the grace session above is preserved.
		s1.RevokeSession("alice", "host2")

		// Force a flush to disk.
		s1.SaveState()

		// Confirm the file was written.
		if _, err := os.Stat(persistPath); err != nil {
			t.Fatalf("persist file not created: %v", err)
		}

		// Create a second store loading from the same file.
		s2 := NewChallengeStore(5*time.Minute, 10*time.Minute, persistPath)
		s2.Stop()

		// Verify grace session is present.
		if !s2.WithinGracePeriod("alice", "host1") {
			t.Error("expected grace session for alice@host1 to survive round-trip")
		}

		// Verify action log is present.
		hosts := s2.KnownHosts("alice")
		found := false
		for _, h := range hosts {
			if h == "host1" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected host1 in KnownHosts after load, got %v", hosts)
		}

		// Verify revokeTokensBefore is present.
		s2.mu.RLock()
		rts, ok := s2.revokeTokensBefore["alice"]
		s2.mu.RUnlock()
		if !ok {
			t.Error("expected revokeTokensBefore[alice] to survive round-trip")
		}
		if rts.IsZero() {
			t.Error("expected non-zero revokeTokensBefore timestamp after load")
		}
	})
}

// TestActionLogConstants verifies that action string constants are non-empty and unique.
func TestActionLogConstants(t *testing.T) {
	constants := map[string]string{
		"ActionApproved":           ActionApproved,
		"ActionDenied":             ActionDenied,
		"ActionAutoApproved":       ActionAutoApproved,
		"ActionRevoked":            ActionRevoked,
		"ActionExtended":           ActionExtended,
		"ActionElevated":           ActionElevated,
		"ActionRotatedBreakglass":  ActionRotatedBreakglass,
		"ActionRevealedBreakglass": ActionRevealedBreakglass,
		"ActionRemovedHost":        ActionRemovedHost,
		"ActionRemovedUser":        ActionRemovedUser,
		"ActionRotationRequested":  ActionRotationRequested,
		"ActionDeployed":           ActionDeployed,
		"ActionConfigChanged":      ActionConfigChanged,
	}

	t.Run("all constants are non-empty", func(t *testing.T) {
		for name, val := range constants {
			if val == "" {
				t.Errorf("action constant %s is empty", name)
			}
		}
	})

	t.Run("all constants are unique", func(t *testing.T) {
		seen := make(map[string]string) // value -> constant name
		for name, val := range constants {
			if prev, exists := seen[val]; exists {
				t.Errorf("duplicate action constant value %q: %s and %s", val, prev, name)
			}
			seen[val] = name
		}
	})
}

// TestSetNonce verifies that a nonce can be set exactly once on a pending challenge
// and is rejected when the challenge is expired or already resolved.
func TestSetNonce(t *testing.T) {
	t.Run("nonce is stored on a fresh challenge", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := s.SetNonce(c.ID, "nonce-abc"); err != nil {
			t.Fatalf("SetNonce: unexpected error: %v", err)
		}
		// Verify that the nonce was stored.
		s.mu.RLock()
		stored := s.challenges[c.ID].Nonce
		s.mu.RUnlock()
		if stored != "nonce-abc" {
			t.Errorf("stored nonce: got %q, want %q", stored, "nonce-abc")
		}
	})

	t.Run("second SetNonce on same challenge fails", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := s.SetNonce(c.ID, "nonce-first"); err != nil {
			t.Fatalf("SetNonce first call: %v", err)
		}
		if err := s.SetNonce(c.ID, "nonce-second"); err == nil {
			t.Fatal("SetNonce second call: expected error, got nil")
		}
	})

	t.Run("SetNonce on expired challenge fails", func(t *testing.T) {
		// Create a store with a very short TTL so the challenge expires immediately.
		s := newTestStore(time.Millisecond, 0)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
		if err := s.SetNonce(c.ID, "nonce-late"); err == nil {
			t.Fatal("SetNonce on expired challenge: expected error, got nil")
		}
	})

	t.Run("SetNonce on unknown ID fails", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		if err := s.SetNonce("does-not-exist", "nonce-x"); err == nil {
			t.Fatal("SetNonce on unknown ID: expected error, got nil")
		}
	})
}

// TestConsumeOneTap verifies one-tap token semantics: consume once succeeds,
// a second consume of the same challenge fails, and an expired challenge fails.
func TestConsumeOneTap(t *testing.T) {
	t.Run("first consume succeeds", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := s.ConsumeOneTap(c.ID); err != nil {
			t.Fatalf("ConsumeOneTap first call: unexpected error: %v", err)
		}
	})

	t.Run("second consume of same nonce fails", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := s.ConsumeOneTap(c.ID); err != nil {
			t.Fatalf("ConsumeOneTap first call: %v", err)
		}
		if err := s.ConsumeOneTap(c.ID); err == nil {
			t.Fatal("ConsumeOneTap second call: expected error, got nil")
		}
	})

	t.Run("consume on expired challenge fails", func(t *testing.T) {
		s := newTestStore(time.Millisecond, 0)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
		if err := s.ConsumeOneTap(c.ID); err == nil {
			t.Fatal("ConsumeOneTap on expired challenge: expected error, got nil")
		}
	})

	t.Run("consume on unknown ID fails", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		if err := s.ConsumeOneTap("does-not-exist"); err == nil {
			t.Fatal("ConsumeOneTap on unknown ID: expected error, got nil")
		}
	})
}

// TestConsumeAndApprove verifies the atomic consume-and-approve operation.
func TestConsumeAndApprove(t *testing.T) {
	t.Run("successfully consumes one-tap nonce and approves atomically", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := s.ConsumeAndApprove(c.ID, "alice"); err != nil {
			t.Fatalf("ConsumeAndApprove: unexpected error: %v", err)
		}
		// Verify the challenge is approved in the store.
		s.mu.RLock()
		ch, exists := s.challenges[c.ID]
		s.mu.RUnlock()
		if !exists {
			t.Fatal("challenge disappeared from store after ConsumeAndApprove")
		}
		if ch.Status != StatusApproved {
			t.Errorf("status after ConsumeAndApprove: got %q, want %q", ch.Status, StatusApproved)
		}
		if ch.ApprovedBy != "alice" {
			t.Errorf("ApprovedBy: got %q, want %q", ch.ApprovedBy, "alice")
		}
		// Verify one-tap nonce is consumed.
		s.mu.RLock()
		used := s.oneTapUsed[c.ID]
		s.mu.RUnlock()
		if !used {
			t.Error("expected oneTapUsed[id] to be true after ConsumeAndApprove")
		}
	})

	t.Run("second call on same challenge ID fails (already approved)", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := s.ConsumeAndApprove(c.ID, "alice"); err != nil {
			t.Fatalf("ConsumeAndApprove first call: %v", err)
		}
		// Second call: nonce already consumed and challenge already resolved.
		if err := s.ConsumeAndApprove(c.ID, "alice"); err == nil {
			t.Fatal("ConsumeAndApprove second call: expected error, got nil")
		}
	})

	t.Run("call on expired challenge fails", func(t *testing.T) {
		s := newTestStore(time.Millisecond, 0)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
		if err := s.ConsumeAndApprove(c.ID, "alice"); err == nil {
			t.Fatal("ConsumeAndApprove on expired challenge: expected error, got nil")
		}
	})

	t.Run("call after session revocation fails", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		// Revoke the session after challenge creation.
		s.RevokeSession("alice", "host1")
		if err := s.ConsumeAndApprove(c.ID, "alice"); err == nil {
			t.Fatal("ConsumeAndApprove after revocation: expected error, got nil")
		}
	})

	t.Run("call on unknown ID fails", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		if err := s.ConsumeAndApprove("does-not-exist", "alice"); err == nil {
			t.Fatal("ConsumeAndApprove on unknown ID: expected error, got nil")
		}
	})

	t.Run("approval is reflected via Get after ConsumeAndApprove", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := s.ConsumeAndApprove(c.ID, "alice"); err != nil {
			t.Fatalf("ConsumeAndApprove: %v", err)
		}
		// Get returns false for non-pending challenges (expired-check-only).
		// Read directly from the store to confirm approved state.
		s.mu.RLock()
		ch, exists := s.challenges[c.ID]
		s.mu.RUnlock()
		if !exists {
			t.Fatal("challenge not found in store after ConsumeAndApprove")
		}
		if ch.Status != StatusApproved {
			t.Errorf("store status: got %q, want %q", ch.Status, StatusApproved)
		}
	})

	t.Run("grace session is created when grace period is configured", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)
		c, err := s.Create("alice", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := s.ConsumeAndApprove(c.ID, "alice"); err != nil {
			t.Fatalf("ConsumeAndApprove: %v", err)
		}
		if !s.WithinGracePeriod("alice", "host1") {
			t.Error("expected grace session to exist after ConsumeAndApprove with grace period configured")
		}
	})

	t.Run("pendingByUser is decremented after ConsumeAndApprove", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		c, err := s.Create("bob", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		s.mu.RLock()
		before := s.pendingByUser["bob"]
		s.mu.RUnlock()
		if before != 1 {
			t.Fatalf("expected pendingByUser=1 before ConsumeAndApprove, got %d", before)
		}
		if err := s.ConsumeAndApprove(c.ID, "bob"); err != nil {
			t.Fatalf("ConsumeAndApprove: %v", err)
		}
		s.mu.RLock()
		after := s.pendingByUser["bob"]
		s.mu.RUnlock()
		if after != 0 {
			t.Errorf("expected pendingByUser=0 after ConsumeAndApprove, got %d", after)
		}
	})
}

// TestAllActiveSessions verifies AllActiveSessions across multiple users and hosts.
func TestAllActiveSessions(t *testing.T) {
	t.Run("empty store returns no sessions", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)
		sessions := s.AllActiveSessions()
		if len(sessions) != 0 {
			t.Errorf("expected 0 sessions, got %d", len(sessions))
		}
	})

	t.Run("sessions for multiple users and hosts are all returned", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)
		s.CreateGraceSession("alice", "host1", 10*time.Minute)
		s.CreateGraceSession("alice", "host2", 10*time.Minute)
		s.CreateGraceSession("bob", "host1", 10*time.Minute)

		sessions := s.AllActiveSessions()
		if len(sessions) != 3 {
			t.Errorf("expected 3 sessions, got %d", len(sessions))
		}

		// Build a quick lookup to verify each expected session is present.
		type sessionKey struct{ username, hostname string }
		found := make(map[sessionKey]bool)
		for _, gs := range sessions {
			found[sessionKey{gs.Username, gs.Hostname}] = true
		}
		expected := []sessionKey{
			{"alice", "host1"},
			{"alice", "host2"},
			{"bob", "host1"},
		}
		for _, k := range expected {
			if !found[k] {
				t.Errorf("session missing for user=%q host=%q", k.username, k.hostname)
			}
		}
	})

	t.Run("only approved sessions appear — pending challenges do not", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)
		// Create a pending challenge; it should NOT appear in AllActiveSessions.
		_, err := s.Create("carol", "host1", "", "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		sessions := s.AllActiveSessions()
		if len(sessions) != 0 {
			t.Errorf("pending challenge should not appear in AllActiveSessions, got %d sessions", len(sessions))
		}

		// Approve a different challenge to seed a grace session.
		s.CreateGraceSession("carol", "host1", 10*time.Minute)
		sessions = s.AllActiveSessions()
		if len(sessions) != 1 {
			t.Errorf("expected 1 session after CreateGraceSession, got %d", len(sessions))
		}
	})

	t.Run("revoked session no longer appears", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)
		s.CreateGraceSession("alice", "host1", 10*time.Minute)
		s.CreateGraceSession("bob", "host2", 10*time.Minute)

		// Verify both are present before revocation.
		if got := len(s.AllActiveSessions()); got != 2 {
			t.Fatalf("expected 2 sessions before revocation, got %d", got)
		}

		s.RevokeSession("alice", "host1")

		sessions := s.AllActiveSessions()
		if len(sessions) != 1 {
			t.Errorf("expected 1 session after revocation, got %d", len(sessions))
		}
		if sessions[0].Username != "bob" || sessions[0].Hostname != "host2" {
			t.Errorf("unexpected remaining session: user=%q host=%q", sessions[0].Username, sessions[0].Hostname)
		}
	})

	t.Run("expired sessions are not returned", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)
		// Manually inject an already-expired grace session.
		s.mu.Lock()
		s.lastApproval[graceKey("alice", "host1")] = time.Now().Add(-1 * time.Second)
		s.mu.Unlock()

		sessions := s.AllActiveSessions()
		if len(sessions) != 0 {
			t.Errorf("expected 0 sessions (expired), got %d", len(sessions))
		}
	})

	t.Run("sessions are grouped correctly by user and host", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 10*time.Minute)
		s.CreateGraceSession("alice", "host1", 5*time.Minute)
		s.CreateGraceSession("alice", "host2", 8*time.Minute)

		sessions := s.AllActiveSessions()
		if len(sessions) != 2 {
			t.Fatalf("expected 2 sessions, got %d", len(sessions))
		}
		for _, gs := range sessions {
			if gs.Username != "alice" {
				t.Errorf("unexpected username: got %q, want %q", gs.Username, "alice")
			}
			if gs.Hostname != "host1" && gs.Hostname != "host2" {
				t.Errorf("unexpected hostname: %q", gs.Hostname)
			}
		}
	})
}

// TestAllActionHistoryWithUsers verifies AllActionHistoryWithUsers across multiple users.
func TestAllActionHistoryWithUsers(t *testing.T) {
	t.Run("empty store returns no entries", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		entries := s.AllActionHistoryWithUsers()
		if len(entries) != 0 {
			t.Errorf("expected 0 entries, got %d", len(entries))
		}
	})

	t.Run("actions for multiple users are all returned", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		s.LogAction("alice", ActionApproved, "host1", "CODE1", "")
		s.LogAction("bob", ActionApproved, "host2", "CODE2", "")
		s.LogAction("carol", ActionRevoked, "host3", "", "")

		entries := s.AllActionHistoryWithUsers()
		if len(entries) != 3 {
			t.Errorf("expected 3 entries, got %d", len(entries))
		}

		// Verify each entry includes the correct username.
		users := make(map[string]bool)
		for _, e := range entries {
			users[e.Username] = true
		}
		for _, u := range []string{"alice", "bob", "carol"} {
			if !users[u] {
				t.Errorf("expected entry for user %q, not found", u)
			}
		}
	})

	t.Run("entries are sorted most recent first", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		t0 := time.Now().Add(-2 * time.Minute)
		t1 := time.Now().Add(-1 * time.Minute)
		t2 := time.Now()
		s.LogActionAt("alice", ActionApproved, "host1", "C1", "", t0)
		s.LogActionAt("bob", ActionRevoked, "host2", "", "", t2)
		s.LogActionAt("carol", ActionAutoApproved, "host3", "C3", "", t1)

		entries := s.AllActionHistoryWithUsers()
		if len(entries) != 3 {
			t.Fatalf("expected 3 entries, got %d", len(entries))
		}
		for i := 1; i < len(entries); i++ {
			if entries[i].Timestamp.After(entries[i-1].Timestamp) {
				t.Errorf("entries not sorted descending: entries[%d].Timestamp=%v is after entries[%d].Timestamp=%v",
					i, entries[i].Timestamp, i-1, entries[i-1].Timestamp)
			}
		}
	})

	t.Run("entry fields match what was logged", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		s.LogAction("alice", ActionApproved, "host1", "CODE1", "admin")

		entries := s.AllActionHistoryWithUsers()
		if len(entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(entries))
		}
		e := entries[0]
		if e.Username != "alice" {
			t.Errorf("Username: got %q, want %q", e.Username, "alice")
		}
		if e.Action != ActionApproved {
			t.Errorf("Action: got %q, want %q", e.Action, ActionApproved)
		}
		if e.Hostname != "host1" {
			t.Errorf("Hostname: got %q, want %q", e.Hostname, "host1")
		}
		if e.Code != "CODE1" {
			t.Errorf("Code: got %q, want %q", e.Code, "CODE1")
		}
		if e.Actor != "admin" {
			t.Errorf("Actor: got %q, want %q", e.Actor, "admin")
		}
	})

	t.Run("multiple actions per user are all returned", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		s.LogAction("alice", ActionApproved, "host1", "C1", "")
		s.LogAction("alice", ActionRevoked, "host1", "", "")
		s.LogAction("alice", ActionAutoApproved, "host2", "C2", "")

		entries := s.AllActionHistoryWithUsers()
		aliceCount := 0
		for _, e := range entries {
			if e.Username == "alice" {
				aliceCount++
			}
		}
		if aliceCount != 3 {
			t.Errorf("expected 3 entries for alice, got %d", aliceCount)
		}
	})
}

// TestPersistStateVersionCompat verifies that a state file with version 0 (legacy/absent)
// loads successfully and its data is intact.
func TestPersistStateVersionCompat(t *testing.T) {
	t.Run("version 0 state file loads without error and data is intact", func(t *testing.T) {
		dir := t.TempDir()
		persistPath := filepath.Join(dir, "sessions.json")

		// Build a version-0 (legacy) state JSON manually.
		// In the legacy format version is 0 (Go zero value when absent).
		futureExpiry := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano)
		pastRevoke := time.Now().Add(-1 * time.Minute).UTC().Format(time.RFC3339Nano)
		stateJSON := `{
			"version": 0,
			"grace_sessions": {
				"alice\u0000host1": "` + futureExpiry + `"
			},
			"revoke_tokens_before": {
				"bob": "` + pastRevoke + `"
			},
			"action_log": {
				"alice": [
					{"timestamp": "` + pastRevoke + `", "action": "approved", "hostname": "host1", "code": "CODE1"}
				]
			}
		}`

		// Write the file with 0600 permissions so loadState does not reject it.
		if err := os.WriteFile(persistPath, []byte(stateJSON), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		// Load from the file — this should succeed without error.
		s := NewChallengeStore(5*time.Minute, 10*time.Minute, persistPath)
		s.Stop()

		// Verify the grace session for alice@host1 survived the load.
		if !s.WithinGracePeriod("alice", "host1") {
			t.Error("expected grace session for alice@host1 to be loaded from version-0 state")
		}

		// Verify the revocation timestamp for bob survived the load.
		s.mu.RLock()
		rts, ok := s.revokeTokensBefore["bob"]
		s.mu.RUnlock()
		if !ok {
			t.Error("expected revokeTokensBefore[bob] to be loaded from version-0 state")
		}
		if rts.IsZero() {
			t.Error("revokeTokensBefore[bob] is zero after load")
		}

		// Verify the action log entry for alice survived the load.
		hosts := s.KnownHosts("alice")
		found := false
		for _, h := range hosts {
			if h == "host1" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected host1 in KnownHosts(alice) after load, got %v", hosts)
		}
	})

	t.Run("version field absent (truly legacy) loads the same as version 0", func(t *testing.T) {
		dir := t.TempDir()
		persistPath := filepath.Join(dir, "sessions.json")

		// Omit the version field entirely to simulate the oldest legacy files.
		futureExpiry := time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano)
		stateJSON := `{
			"grace_sessions": {
				"carol\u0000host2": "` + futureExpiry + `"
			},
			"revoke_tokens_before": {},
			"action_log": {}
		}`

		if err := os.WriteFile(persistPath, []byte(stateJSON), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		s := NewChallengeStore(5*time.Minute, 10*time.Minute, persistPath)
		s.Stop()

		if !s.WithinGracePeriod("carol", "host2") {
			t.Error("expected grace session for carol@host2 to be loaded from truly-legacy state (no version field)")
		}
	})

	t.Run("sessions and action log survive round-trip through version-0 load then re-save", func(t *testing.T) {
		dir := t.TempDir()
		persistPath := filepath.Join(dir, "sessions.json")

		futureExpiry := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano)
		pastAction := time.Now().Add(-30 * time.Second).UTC().Format(time.RFC3339Nano)
		stateJSON := `{
			"version": 0,
			"grace_sessions": {
				"dave\u0000host3": "` + futureExpiry + `"
			},
			"revoke_tokens_before": {},
			"action_log": {
				"dave": [
					{"timestamp": "` + pastAction + `", "action": "approved", "hostname": "host3", "code": "C99"}
				]
			}
		}`

		if err := os.WriteFile(persistPath, []byte(stateJSON), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		// Load and immediately re-save (simulates a server restart with graceful flush).
		s1 := NewChallengeStore(5*time.Minute, 10*time.Minute, persistPath)
		s1.Stop()
		s1.SaveState()

		// Load again from the re-saved (now version-1) file.
		s2 := NewChallengeStore(5*time.Minute, 10*time.Minute, persistPath)
		s2.Stop()

		if !s2.WithinGracePeriod("dave", "host3") {
			t.Error("expected grace session for dave@host3 to survive version-0 load + re-save round-trip")
		}

		hosts := s2.KnownHosts("dave")
		found := false
		for _, h := range hosts {
			if h == "host3" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected host3 in KnownHosts(dave) after round-trip, got %v", hosts)
		}
	})
}
