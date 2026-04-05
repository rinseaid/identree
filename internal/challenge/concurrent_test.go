package challenge

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// TestConcurrentApprove_Local verifies that the local ChallengeStore correctly
// serializes concurrent approvals: exactly one succeeds, the rest fail.
func TestConcurrentApprove_Local(t *testing.T) {
	s := newTestStore(30*time.Second, 5*time.Minute)

	c, err := s.Create("alice", "host1", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const N = 100
	var (
		wg       sync.WaitGroup
		successes atomic.Int32
		failures  atomic.Int32
		barrier   = make(chan struct{})
	)

	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			<-barrier // wait for all goroutines to be ready
			err := s.Approve(c.ID, "admin")
			if err == nil {
				successes.Add(1)
			} else if strings.Contains(err.Error(), "already resolved") {
				failures.Add(1)
			} else {
				// Unexpected error — still count as failure but log it.
				t.Errorf("unexpected error: %v", err)
				failures.Add(1)
			}
		}()
	}

	close(barrier)
	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Errorf("expected exactly 1 success, got %d", got)
	}
	if got := failures.Load(); got != N-1 {
		t.Errorf("expected exactly %d failures, got %d", N-1, got)
	}

	// Verify pending counter is exactly 0.
	pending := s.AllPendingChallenges()
	if len(pending) != 0 {
		t.Errorf("expected 0 pending challenges, got %d", len(pending))
	}

	s.mu.RLock()
	pendingCount := s.pendingByUser["alice"]
	totalPending := s.totalPending
	s.mu.RUnlock()
	if pendingCount != 0 {
		t.Errorf("pendingByUser[alice]: got %d, want 0", pendingCount)
	}
	if totalPending != 0 {
		t.Errorf("totalPending: got %d, want 0", totalPending)
	}

	// Verify grace session was created exactly once.
	sessions := s.ActiveSessions("alice")
	if len(sessions) != 1 {
		t.Fatalf("expected exactly 1 grace session, got %d", len(sessions))
	}
	if sessions[0].Hostname != "host1" {
		t.Errorf("grace session hostname: got %q, want %q", sessions[0].Hostname, "host1")
	}
}

// TestConcurrentApproveDeny_Redis verifies that the RedisStore correctly
// serializes concurrent mixed approve/deny operations: exactly one succeeds.
func TestConcurrentApproveDeny_Redis(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewRedisStore(client, "test:", 30*time.Second, 5*time.Minute)
	t.Cleanup(func() {
		store.Stop()
	})

	c, err := store.Create("bob", "host2", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const N = 100
	var (
		wg        sync.WaitGroup
		approveOK atomic.Int32
		denyOK    atomic.Int32
		failures  atomic.Int32
		barrier   = make(chan struct{})
	)

	wg.Add(N)
	for i := 0; i < N; i++ {
		isApprove := i < N/2
		go func(approve bool) {
			defer wg.Done()
			<-barrier
			if approve {
				err := store.Approve(c.ID, "admin")
				if err == nil {
					approveOK.Add(1)
				} else if strings.Contains(err.Error(), "already_resolved") || strings.Contains(err.Error(), "already resolved") {
					failures.Add(1)
				} else {
					t.Errorf("unexpected approve error: %v", err)
					failures.Add(1)
				}
			} else {
				err := store.Deny(c.ID)
				if err == nil {
					denyOK.Add(1)
				} else if strings.Contains(err.Error(), "already_resolved") || strings.Contains(err.Error(), "already resolved") {
					failures.Add(1)
				} else {
					t.Errorf("unexpected deny error: %v", err)
					failures.Add(1)
				}
			}
		}(isApprove)
	}

	close(barrier)
	wg.Wait()

	totalOK := approveOK.Load() + denyOK.Load()
	if totalOK != 1 {
		t.Errorf("expected exactly 1 total success (approve=%d + deny=%d = %d), want 1",
			approveOK.Load(), denyOK.Load(), totalOK)
	}
	if got := failures.Load(); got != N-1 {
		t.Errorf("expected exactly %d failures, got %d", N-1, got)
	}

	// Verify pending counter is exactly 0.
	pending := store.AllPendingChallenges()
	if len(pending) != 0 {
		t.Errorf("expected 0 pending challenges, got %d", len(pending))
	}
}
