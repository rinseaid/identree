package server

import (
	"testing"
	"time"
)

// TestAuthFailTracker_BlockAfterNFailures verifies that an IP is throttled
// after authFailMax consecutive failures and that different IPs are independent.
func TestAuthFailTracker_BlockAfterNFailures(t *testing.T) {
	const ip1 = "10.0.0.1"
	const ip2 = "10.0.0.2"

	a := newAuthFailTracker()

	// ip1 should not be throttled before it reaches the limit.
	for i := 0; i < authFailMax-1; i++ {
		a.record(ip1)
		if a.throttled(ip1) {
			t.Fatalf("ip1 throttled after only %d failures (limit is %d)", i+1, authFailMax)
		}
	}

	// One more failure pushes ip1 to the limit.
	a.record(ip1)
	if !a.throttled(ip1) {
		t.Fatalf("ip1 not throttled after %d failures", authFailMax)
	}

	// ip2 must remain unaffected by ip1's failures.
	if a.throttled(ip2) {
		t.Fatal("ip2 throttled despite having no failures")
	}
}

// TestAuthFailTracker_IndependentIPs verifies that two IPs accumulate separate
// failure counters and each reaches the limit independently.
func TestAuthFailTracker_IndependentIPs(t *testing.T) {
	const ip1 = "192.168.1.1"
	const ip2 = "192.168.1.2"

	a := newAuthFailTracker()

	for i := 0; i < authFailMax; i++ {
		a.record(ip1)
	}
	for i := 0; i < authFailMax-1; i++ {
		a.record(ip2)
	}

	if !a.throttled(ip1) {
		t.Errorf("ip1 should be throttled after %d failures", authFailMax)
	}
	if a.throttled(ip2) {
		t.Errorf("ip2 should not be throttled after %d failures", authFailMax-1)
	}
}

// TestAuthFailTracker_ResetsAfterWindow verifies that old failures fall outside
// the sliding window and the IP is no longer throttled.
func TestAuthFailTracker_ResetsAfterWindow(t *testing.T) {
	const ip = "172.16.0.1"

	a := newAuthFailTracker()

	// Directly inject timestamps that are older than authFailWindow so that
	// all stored failures are already stale when throttled/recentCount runs.
	stale := time.Now().Add(-(authFailWindow + time.Second))
	a.mu.Lock()
	times := make([]time.Time, authFailMax)
	for i := range times {
		times[i] = stale
	}
	a.seen[ip] = times
	a.mu.Unlock()

	// All recorded failures are outside the window — IP must not be throttled.
	if a.throttled(ip) {
		t.Fatal("ip should not be throttled after the lockout window has expired")
	}

	// Adding a single fresh failure on top of the stale ones must not trigger
	// throttling (only one recent failure, well below authFailMax).
	a.record(ip)
	if a.throttled(ip) {
		t.Fatal("ip should not be throttled with only one failure in the current window")
	}
}
