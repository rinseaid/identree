package server

import (
	"sync"
	"testing"
	"time"

	"github.com/rinseaid/identree/internal/notify"
)

// mockBroadcaster captures published messages so tests can assert without a
// real Postgres LISTEN/NOTIFY round-trip.
type mockBroadcaster struct {
	mu      sync.Mutex
	sse     []ssePayload
	cluster []clusterMessage
}

func (m *mockBroadcaster) Broadcast(username, event string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sse = append(m.sse, ssePayload{User: username, Event: event})
}

func (m *mockBroadcaster) PublishCluster(msg clusterMessage) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cluster = append(m.cluster, msg)
}

func (m *mockBroadcaster) Close() {}

func TestPublishClusterMessage_RoutesThroughBroadcaster(t *testing.T) {
	mock := &mockBroadcaster{}
	s := &Server{sseBroadcaster: mock}

	s.publishClusterMessage(clusterMessage{Type: "revoke_nonce", Nonce: "abc"})
	s.publishClusterMessage(clusterMessage{Type: "revoke_admin", Username: "alice"})

	if len(mock.cluster) != 2 {
		t.Fatalf("PublishCluster called %d times, want 2", len(mock.cluster))
	}
	if mock.cluster[0].Nonce != "abc" {
		t.Errorf("first message nonce: got %q", mock.cluster[0].Nonce)
	}
	if mock.cluster[1].Username != "alice" {
		t.Errorf("second message username: got %q", mock.cluster[1].Username)
	}
}

func TestPublishClusterMessage_NilBroadcasterIsNoop(t *testing.T) {
	s := &Server{} // sseBroadcaster nil
	// Should not panic.
	s.publishClusterMessage(clusterMessage{Type: "revoke_nonce", Nonce: "x"})
}

func TestApplyClusterMessage_RevokeNonce(t *testing.T) {
	s := &Server{
		revokedNonces: make(map[string]time.Time),
	}
	s.applyClusterMessage(`{"type":"revoke_nonce","nonce":"deadbeef"}`)

	s.revokedNoncesMu.Lock()
	defer s.revokedNoncesMu.Unlock()
	if _, ok := s.revokedNonces["deadbeef"]; !ok {
		t.Errorf("expected revokedNonces to contain 'deadbeef', got %+v", s.revokedNonces)
	}
}

func TestApplyClusterMessage_RevokeAdmin(t *testing.T) {
	s := &Server{}
	s.applyClusterMessage(`{"type":"revoke_admin","username":"alice"}`)

	val, loaded := s.revokedAdminSessions.Load("alice")
	if !loaded {
		t.Fatal("expected revokedAdminSessions[alice] to be set")
	}
	if _, ok := val.(time.Time); !ok {
		t.Errorf("expected time.Time, got %T", val)
	}
}

func TestApplyClusterMessage_ReloadDeduplicates(t *testing.T) {
	store := &countingConfigStore{}
	s := &Server{notifyStore: store}

	if s.clusterLastNotifyReload.Load() != 0 {
		t.Fatal("precondition: clusterLastNotifyReload should be zero")
	}

	s.applyClusterMessage(`{"type":"reload_notify_config"}`)
	first := s.clusterLastNotifyReload.Load()
	if first == 0 {
		t.Fatal("first reload didn't bump timestamp")
	}
	if store.loads != 1 {
		t.Errorf("first reload: expected 1 store.Load, got %d", store.loads)
	}

	// Second call within 1s is deduplicated.
	s.applyClusterMessage(`{"type":"reload_notify_config"}`)
	if got := s.clusterLastNotifyReload.Load(); got != first {
		t.Errorf("expected dedup, got first=%d second=%d", first, got)
	}
	if store.loads != 1 {
		t.Errorf("expected dedup to skip store.Load, got %d total loads", store.loads)
	}
}

// countingConfigStore is a notify.ConfigStore for tests that counts loads.
type countingConfigStore struct {
	loads int
}

func (s *countingConfigStore) Load() (*notify.NotificationConfig, error) {
	s.loads++
	return &notify.NotificationConfig{}, nil
}
func (s *countingConfigStore) Save(_ *notify.NotificationConfig) error { return nil }

func TestApplyClusterMessage_MalformedIgnored(t *testing.T) {
	s := &Server{revokedNonces: make(map[string]time.Time)}
	s.applyClusterMessage(`{not valid json`)
	s.applyClusterMessage(`{"type":"unknown"}`)
	s.applyClusterMessage(`{"type":"revoke_nonce"}`) // missing nonce
	if len(s.revokedNonces) != 0 {
		t.Errorf("expected no state changes, got %+v", s.revokedNonces)
	}
}

func TestSSEPayloadRoundTrip(t *testing.T) {
	mock := &mockBroadcaster{}
	mock.Broadcast("alice", "challenge_created")

	if len(mock.sse) != 1 {
		t.Fatalf("got %d SSE payloads, want 1", len(mock.sse))
	}
	if mock.sse[0].User != "alice" || mock.sse[0].Event != "challenge_created" {
		t.Errorf("payload mismatch: %+v", mock.sse[0])
	}
}

// Compile-time interface compliance.
var _ SSEBroadcaster = (*mockBroadcaster)(nil)
var _ SSEBroadcaster = (*pgListenBroadcaster)(nil)
var _ SSEBroadcaster = (*localBroadcaster)(nil)
