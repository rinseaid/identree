package challenge

import (
	"testing"
	"time"
)

func TestSQLStore_AgentHeartbeat(t *testing.T) {
	s := newTestSQLStore(t)

	if got := s.ListAgents(); len(got) != 0 {
		t.Errorf("ListAgents on fresh store: got %d entries, want 0", len(got))
	}

	s.RecordHeartbeat(AgentHeartbeat{
		Hostname: "host1", Version: "1.2.3", OSInfo: "ubuntu 24.04", IP: "10.0.0.1",
	})

	agents := s.ListAgents()
	if len(agents) != 1 {
		t.Fatalf("ListAgents: got %d, want 1", len(agents))
	}
	if agents[0].Hostname != "host1" {
		t.Errorf("Hostname: got %q", agents[0].Hostname)
	}
	if agents[0].Version != "1.2.3" {
		t.Errorf("Version: got %q", agents[0].Version)
	}
	if agents[0].FirstSeen.IsZero() || agents[0].LastSeen.IsZero() {
		t.Errorf("timestamps zero: %+v", agents[0])
	}
	firstSeen := agents[0].FirstSeen

	// Second heartbeat updates last_seen but keeps first_seen.
	time.Sleep(1100 * time.Millisecond)
	s.RecordHeartbeat(AgentHeartbeat{Hostname: "host1", Version: "1.2.4"})

	agents = s.ListAgents()
	if len(agents) != 1 {
		t.Fatalf("ListAgents after re-heartbeat: got %d, want 1", len(agents))
	}
	if agents[0].Version != "1.2.4" {
		t.Errorf("Version after upgrade: got %q, want 1.2.4", agents[0].Version)
	}
	if !agents[0].FirstSeen.Equal(firstSeen) {
		t.Errorf("FirstSeen changed: was %v, now %v", firstSeen, agents[0].FirstSeen)
	}
	if !agents[0].LastSeen.After(firstSeen) {
		t.Errorf("LastSeen not bumped: first=%v last=%v", firstSeen, agents[0].LastSeen)
	}

	// Multiple hosts, ordered by last_seen DESC.
	s.RecordHeartbeat(AgentHeartbeat{Hostname: "host2"})
	agents = s.ListAgents()
	if len(agents) != 2 {
		t.Fatalf("ListAgents: got %d, want 2", len(agents))
	}
	if agents[0].Hostname != "host2" {
		t.Errorf("first entry: got %q, want host2 (most recent)", agents[0].Hostname)
	}

	// Hostname empty is a no-op.
	s.RecordHeartbeat(AgentHeartbeat{})
	if got := s.ListAgents(); len(got) != 2 {
		t.Errorf("ListAgents after empty heartbeat: got %d, want 2", len(got))
	}
}

func TestSQLStore_RemoveHostClearsAgent(t *testing.T) {
	s := newTestSQLStore(t)
	s.RecordHeartbeat(AgentHeartbeat{Hostname: "vanish"})
	if got := s.ListAgents(); len(got) != 1 {
		t.Fatalf("precondition: ListAgents = %d, want 1", len(got))
	}
	s.RemoveHost("vanish")
	if got := s.ListAgents(); len(got) != 0 {
		t.Errorf("ListAgents after RemoveHost: got %d, want 0", len(got))
	}
}
