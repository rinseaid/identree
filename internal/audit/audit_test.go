package audit

import (
	"sync"
	"testing"
	"time"
)

// mockSink records emitted events for assertions.
type mockSink struct {
	mu     sync.Mutex
	events []Event
	closed bool
}

func (m *mockSink) Name() string { return "mock" }

func (m *mockSink) Emit(e Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	return nil
}

func (m *mockSink) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockSink) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]Event, len(m.events))
	copy(cp, m.events)
	return cp
}

func TestStreamer_EmitAndClose(t *testing.T) {
	sink := &mockSink{}
	s := NewStreamer([]Sink{sink}, 100)

	s.Emit(NewEvent("challenge_created", "alice", "web-01", "ABC123", "", "test", "dev"))
	s.Emit(NewEvent("challenge_approved", "alice", "web-01", "ABC123", "bob", "", "dev"))
	s.Close()

	events := sink.Events()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Event != "challenge_created" {
		t.Errorf("event[0] = %q, want challenge_created", events[0].Event)
	}
	if events[1].Actor != "bob" {
		t.Errorf("event[1].Actor = %q, want bob", events[1].Actor)
	}
	if !sink.closed {
		t.Error("sink was not closed")
	}
}

func TestStreamer_NonBlocking(t *testing.T) {
	sink := &mockSink{}
	// Buffer of 2: third event should be dropped without blocking.
	s := NewStreamer([]Sink{sink}, 2)

	// Fill the buffer without consuming.
	// We need to pause the dispatch goroutine — do this by sending events
	// faster than dispatch can process. Since dispatch is fast with mockSink,
	// use a tiny buffer and blast events.
	for i := 0; i < 100; i++ {
		s.Emit(NewEvent("test", "user", "host", "", "", "", "dev"))
	}
	s.Close()

	// Some events should have been delivered, some may have been dropped.
	// The key assertion: we didn't deadlock and Close returned.
	events := sink.Events()
	if len(events) == 0 {
		t.Error("expected at least some events to be delivered")
	}
}

func TestNewEvent_Timestamp(t *testing.T) {
	e := NewEvent("test", "alice", "web-01", "", "", "", "dev")
	if e.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
	if _, err := time.Parse(time.RFC3339, e.Timestamp); err != nil {
		t.Errorf("timestamp %q is not valid RFC3339: %v", e.Timestamp, err)
	}
	if e.Source != "identree" {
		t.Errorf("source = %q, want identree", e.Source)
	}
}
