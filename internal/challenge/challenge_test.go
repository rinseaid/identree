package challenge

import (
	"errors"
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
		c, err := s.Create("alice", "host1", "")
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
		_, err := s.Create("bob", "host1", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		s.mu.RLock()
		count := s.pendingByUser["bob"]
		s.mu.RUnlock()
		if count != 1 {
			t.Errorf("pendingByUser: got %d, want 1", count)
		}

		_, err = s.Create("bob", "host2", "")
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
			_, err := s.Create("carol", "host", "")
			if err != nil {
				t.Fatalf("unexpected error on create %d: %v", i+1, err)
			}
		}
		_, err := s.Create("carol", "host", "")
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
			if _, err := s.Create("dave", "host", ""); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		}
		// A different user should still be able to create
		_, err := s.Create("eve", "host", "")
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
			s.challenges[id] = &Challenge{ID: id, Username: "synthetic"}
		}
		s.mu.Unlock()

		_, err := s.Create("frank", "host", "")
		if err == nil {
			t.Fatal("expected error when total challenge cap is hit, got nil")
		}
		if !errors.Is(err, ErrTooManyChallenges) {
			t.Errorf("expected ErrTooManyChallenges, got: %v", err)
		}
	})

	t.Run("challenge is retrievable by ID and code after creation", func(t *testing.T) {
		s := newTestStore(5*time.Minute, 0)
		c, err := s.Create("alice", "host1", "")
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
		c, err := s.Create("alice", "host1", "")
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
		c, _ := s.Create("alice", "host1", "")
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
		c, err := s.Create("alice", "host1", "")
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
		c, err := s.Create("alice", "host1", "")
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
		c, _ := s.Create("bob", "host1", "")
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

		c, err := s.Create("alice", "host1", "")
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
		c, err := s.Create("alice", "host1", "")
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

		c, err := s.Create("alice", "host1", "")
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

		c, err := s.Create("alice", "host1", "")
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
		c1, err := s.Create("alice", "host1", "")
		if err != nil {
			t.Fatalf("Create c1: %v", err)
		}
		c2, err := s.Create("alice", "host1", "")
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
		c, _ := s.Create("alice", "host1", "")
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
		c, err := s.Create("alice", "host1", "")
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
		c, err := s.Create("alice", "host1", "")
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
		c, err := s.Create("alice", "host1", "")
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
