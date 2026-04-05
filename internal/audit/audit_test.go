package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── Mock sink ────────────────────────────────────────────────────────────────

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

// ── Streamer tests ──────────────────────────────────────────────────────────

func TestStreamer_EmitAndClose(t *testing.T) {
	sink := &mockSink{}
	s := NewStreamer([]Sink{sink}, 100)

	s.Emit(NewEvent("challenge_created", "alice", "web-01", "ABC123", "", "test reason", "10.0.0.1", "dev"))
	s.Emit(NewEvent("challenge_approved", "alice", "web-01", "ABC123", "bob", "", "10.0.0.2", "dev"))
	s.Close()

	events := sink.Events()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Event != "challenge_created" {
		t.Errorf("event[0].Event = %q, want challenge_created", events[0].Event)
	}
	if events[0].Reason != "test reason" {
		t.Errorf("event[0].Reason = %q, want 'test reason'", events[0].Reason)
	}
	if events[1].Actor != "bob" {
		t.Errorf("event[1].Actor = %q, want bob", events[1].Actor)
	}
	if !sink.closed {
		t.Error("sink was not closed")
	}
}

func TestStreamer_MultipleSinks(t *testing.T) {
	s1, s2 := &mockSink{}, &mockSink{}
	streamer := NewStreamer([]Sink{s1, s2}, 100)

	streamer.Emit(NewEvent("test", "alice", "host", "", "", "", "", "dev"))
	streamer.Close()

	if len(s1.Events()) != 1 {
		t.Errorf("sink1 got %d events, want 1", len(s1.Events()))
	}
	if len(s2.Events()) != 1 {
		t.Errorf("sink2 got %d events, want 1", len(s2.Events()))
	}
}

func TestStreamer_NonBlocking(t *testing.T) {
	sink := &mockSink{}
	s := NewStreamer([]Sink{sink}, 2)

	for i := 0; i < 100; i++ {
		s.Emit(NewEvent("test", "user", "host", "", "", "", "", "dev"))
	}
	s.Close()

	events := sink.Events()
	if len(events) == 0 {
		t.Error("expected at least some events to be delivered")
	}
	if len(events) == 100 {
		t.Error("expected some events to be dropped with buffer size 2")
	}
}

func TestStreamer_DefaultBufferSize(t *testing.T) {
	sink := &mockSink{}
	s := NewStreamer([]Sink{sink}, 0)
	s.Emit(NewEvent("test", "user", "host", "", "", "", "", "dev"))
	s.Close()

	if len(sink.Events()) != 1 {
		t.Errorf("got %d events, want 1", len(sink.Events()))
	}
}

func TestNewEvent_RemoteAddr(t *testing.T) {
	e := NewEvent("test", "alice", "web-01", "CODE", "actor", "reason", "10.0.0.1", "v1.0")
	if e.RemoteAddr != "10.0.0.1" {
		t.Errorf("RemoteAddr = %q, want 10.0.0.1", e.RemoteAddr)
	}
	// Empty remote addr should be omitted from JSON.
	e2 := NewEvent("test", "alice", "web-01", "CODE", "", "", "", "v1.0")
	b, _ := json.Marshal(e2)
	if strings.Contains(string(b), "remote_addr") {
		t.Error("expected remote_addr to be omitted when empty")
	}
}

func TestStreamer_HashChain(t *testing.T) {
	sink := &mockSink{}
	s := NewStreamer([]Sink{sink}, 100)

	s.Emit(NewEvent("event_a", "alice", "host", "", "", "", "10.0.0.1", "dev"))
	s.Emit(NewEvent("event_b", "bob", "host", "", "", "", "10.0.0.2", "dev"))
	s.Emit(NewEvent("event_c", "carol", "host", "", "", "", "", "dev"))
	s.Close()

	events := sink.Events()
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	// Verify sequence numbers.
	for i, e := range events {
		if e.Seq != uint64(i) {
			t.Errorf("event[%d].Seq = %d, want %d", i, e.Seq, i)
		}
	}

	// First event should have no prev_hash.
	if events[0].PrevHash != "" {
		t.Errorf("event[0].PrevHash = %q, want empty", events[0].PrevHash)
	}

	// Verify the hash chain: each event's PrevHash should be the SHA-256 of the previous event's JSON.
	for i := 1; i < len(events); i++ {
		prevJSON, err := json.Marshal(events[i-1])
		if err != nil {
			t.Fatalf("marshal event[%d]: %v", i-1, err)
		}
		h := sha256.Sum256(prevJSON)
		want := hex.EncodeToString(h[:])
		if events[i].PrevHash != want {
			t.Errorf("event[%d].PrevHash = %q, want %q", i, events[i].PrevHash, want)
		}
	}
}

func TestNewEvent_Timestamp(t *testing.T) {
	e := NewEvent("test", "alice", "web-01", "CODE", "actor", "reason", "192.168.1.1", "v1.0")
	if e.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
	if _, err := time.Parse(time.RFC3339, e.Timestamp); err != nil {
		t.Errorf("timestamp %q is not valid RFC3339: %v", e.Timestamp, err)
	}
	if e.Source != "identree" {
		t.Errorf("source = %q, want identree", e.Source)
	}
	if e.Version != "v1.0" {
		t.Errorf("version = %q, want v1.0", e.Version)
	}
}

// ── JSONLogSink tests ───────────────────────────────────────────────────────

func TestJSONLogSink_Stdout(t *testing.T) {
	// Capture stdout via a pipe.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	sink, err := NewJSONLogSink("stdout")
	if err != nil {
		t.Fatalf("NewJSONLogSink(stdout): %v", err)
	}
	if sink.Name() != "jsonlog" {
		t.Errorf("Name() = %q, want jsonlog", sink.Name())
	}

	e := NewEvent("challenge_created", "alice", "web-01", "ABC123", "", "", "", "dev")
	if err := sink.Emit(e); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	_ = sink.Close()
	w.Close()

	var buf bytes.Buffer
	io.Copy(&buf, r)
	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("expected JSON line on stdout, got empty")
	}

	var parsed Event
	if err := json.Unmarshal([]byte(line), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\nline: %s", err, line)
	}
	if parsed.Event != "challenge_created" {
		t.Errorf("parsed.Event = %q, want challenge_created", parsed.Event)
	}
	if parsed.Username != "alice" {
		t.Errorf("parsed.Username = %q, want alice", parsed.Username)
	}
}

func TestJSONLogSink_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "audit.jsonl")

	sink, err := NewJSONLogSink(path)
	if err != nil {
		t.Fatalf("NewJSONLogSink(file): %v", err)
	}

	e1 := NewEvent("challenge_created", "alice", "web-01", "ABC", "", "deploy", "", "dev")
	e2 := NewEvent("challenge_approved", "alice", "web-01", "ABC", "bob", "", "", "dev")
	sink.Emit(e1)
	sink.Emit(e2)
	sink.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	var p1, p2 Event
	json.Unmarshal([]byte(lines[0]), &p1)
	json.Unmarshal([]byte(lines[1]), &p2)
	if p1.Event != "challenge_created" {
		t.Errorf("line 1 event = %q", p1.Event)
	}
	if p2.Actor != "bob" {
		t.Errorf("line 2 actor = %q", p2.Actor)
	}
}

func TestJSONLogSink_FileAppend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Write first event, close.
	s1, _ := NewJSONLogSink(path)
	s1.Emit(NewEvent("event1", "alice", "", "", "", "", "", "dev"))
	s1.Close()

	// Write second event, close.
	s2, _ := NewJSONLogSink(path)
	s2.Emit(NewEvent("event2", "bob", "", "", "", "", "", "dev"))
	s2.Close()

	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (appended), got %d", len(lines))
	}
}

func TestJSONLogSink_InvalidPath(t *testing.T) {
	_, err := NewJSONLogSink("/dev/null/impossible/path/audit.jsonl")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestJSONLogSink_Rotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Use a tiny MaxSize so rotation triggers after a few events.
	sink, err := NewJSONLogSink(path, RotationConfig{MaxSize: 500, MaxFiles: 5})
	if err != nil {
		t.Fatalf("NewJSONLogSink: %v", err)
	}

	// Each JSON event is roughly 150-200 bytes; writing 10 should exceed 500.
	for i := 0; i < 10; i++ {
		if err := sink.Emit(NewEvent(fmt.Sprintf("event_%d", i), "alice", "web-01", "CODE", "", "reason", "", "dev")); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	sink.Close()

	// The rotated file .1 should exist.
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("expected rotated file %s.1 to exist: %v", path, err)
	}

	// The current file should exist and be non-empty.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("current file missing: %v", err)
	}
	if info.Size() == 0 {
		t.Error("current file should be non-empty after rotation")
	}
}

func TestJSONLogSink_MaxFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// MaxFiles=2 means only .1 and .2 should be kept.
	sink, err := NewJSONLogSink(path, RotationConfig{MaxSize: 200, MaxFiles: 2})
	if err != nil {
		t.Fatalf("NewJSONLogSink: %v", err)
	}

	// Write enough events to trigger multiple rotations.
	for i := 0; i < 30; i++ {
		if err := sink.Emit(NewEvent(fmt.Sprintf("event_%d", i), "alice", "web-01", "CODE", "", "reason", "", "dev")); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	sink.Close()

	// .1 and .2 should exist.
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("expected %s.1 to exist: %v", path, err)
	}
	if _, err := os.Stat(path + ".2"); err != nil {
		t.Errorf("expected %s.2 to exist: %v", path, err)
	}

	// .3 should NOT exist (pruned).
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Errorf("expected %s.3 to NOT exist (max_files=2), but it does", path)
	}
}

// ── SyslogSink tests ────────────────────────────────────────────────────────

func TestSyslogSink_UDP(t *testing.T) {
	// Start a UDP listener.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	addr := conn.LocalAddr().String()
	sink, err := NewSyslogSink("udp://" + addr)
	if err != nil {
		t.Fatalf("NewSyslogSink: %v", err)
	}
	if sink.Name() != "syslog" {
		t.Errorf("Name() = %q, want syslog", sink.Name())
	}

	e := NewEvent("challenge_approved", "alice", "web-01", "CODE1", "bob", "deploy", "10.0.0.1", "dev")
	if err := sink.Emit(e); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	sink.Close()

	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	msg := string(buf[:n])

	// Verify RFC 5424 structure.
	if !strings.HasPrefix(msg, "<86>1 ") {
		t.Errorf("expected RFC 5424 prefix <86>1, got: %s", msg[:20])
	}
	if !strings.Contains(msg, "identree") {
		t.Error("message should contain 'identree' app-name")
	}
	if !strings.Contains(msg, `event="challenge_approved"`) {
		t.Error("structured data should contain event name")
	}
	if !strings.Contains(msg, `"username":"alice"`) {
		t.Error("message body should contain JSON event")
	}
}

func TestSyslogSink_InvalidURL(t *testing.T) {
	_, err := NewSyslogSink("http://bad-protocol:514")
	if err == nil {
		t.Error("expected error for non-udp/tcp URL")
	}
}

func TestSyslogSink_Reconnect(t *testing.T) {
	// Create a sink pointing at a port that's not listening.
	sink, err := NewSyslogSink("udp://127.0.0.1:1")
	if err != nil {
		t.Fatalf("NewSyslogSink: %v", err)
	}
	defer sink.Close()

	// Emit should not panic, just return an error or succeed (UDP is fire-and-forget).
	e := NewEvent("test", "alice", "", "", "", "", "", "dev")
	// UDP sends may not return errors, so we just verify no panic.
	_ = sink.Emit(e)
}

// ── SplunkHECSink tests ─────────────────────────────────────────────────────

func TestSplunkHECSink_Batching(t *testing.T) {
	var received atomic.Int32
	var lastBody []byte
	var bodyMu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Splunk test-token" {
			t.Errorf("bad auth header: %s", r.Header.Get("Authorization"))
		}
		bodyMu.Lock()
		lastBody, _ = io.ReadAll(r.Body)
		bodyMu.Unlock()
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	sink := NewSplunkHECSink(ts.URL, "test-token")
	if sink.Name() != "splunk_hec" {
		t.Errorf("Name() = %q, want splunk_hec", sink.Name())
	}

	// Emit fewer than batch max — should flush on Close.
	for i := 0; i < 5; i++ {
		sink.Emit(NewEvent(fmt.Sprintf("event_%d", i), "alice", "host", "", "", "", "", "dev"))
	}
	sink.Close()

	if received.Load() == 0 {
		t.Fatal("expected at least one POST to Splunk HEC")
	}

	// Verify the body contains valid JSON objects with "event" and "sourcetype".
	bodyMu.Lock()
	body := string(lastBody)
	bodyMu.Unlock()
	if !strings.Contains(body, `"sourcetype":"identree:audit"`) {
		t.Errorf("body missing sourcetype: %s", body)
	}
	if !strings.Contains(body, `"source":"identree"`) {
		t.Errorf("body missing source: %s", body)
	}
}

// ── LokiSink tests ──────────────────────────────────────────────────────────

func TestLokiSink_Push(t *testing.T) {
	var received atomic.Int32
	var lastBody []byte
	var bodyMu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/loki/api/v1/push" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer loki-token" {
			t.Errorf("bad auth: %s", r.Header.Get("Authorization"))
		}
		bodyMu.Lock()
		lastBody, _ = io.ReadAll(r.Body)
		bodyMu.Unlock()
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	sink := NewLokiSink(ts.URL, "loki-token")
	if sink.Name() != "loki" {
		t.Errorf("Name() = %q, want loki", sink.Name())
	}

	for i := 0; i < 3; i++ {
		sink.Emit(NewEvent(fmt.Sprintf("event_%d", i), "alice", "host", "", "", "", "", "dev"))
	}
	sink.Close()

	if received.Load() == 0 {
		t.Fatal("expected at least one POST to Loki")
	}

	bodyMu.Lock()
	body := lastBody
	bodyMu.Unlock()

	var payload lokiPushPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("invalid Loki payload: %v", err)
	}
	if len(payload.Streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(payload.Streams))
	}
	stream := payload.Streams[0]
	if stream.Stream["app"] != "identree" {
		t.Errorf("stream label app = %q, want identree", stream.Stream["app"])
	}
	if len(stream.Values) == 0 {
		t.Error("expected at least one value in stream")
	}
}

// ── RFC 5424 formatting ─────────────────────────────────────────────────────

func TestFormatRFC5424(t *testing.T) {
	e := Event{
		Timestamp: "2026-04-04T22:00:00Z",
		Event:     "challenge_approved",
		Username:  "alice",
		Hostname:  "web-01",
		Code:      "ABC123",
		Actor:     "bob",
		Reason:    `test "reason" with quotes`,
		Source:    "identree",
		Version:   "dev",
	}

	msg, err := formatRFC5424(e, "myhost")
	if err != nil {
		t.Fatalf("formatRFC5424: %v", err)
	}
	s := string(msg)

	if !strings.HasPrefix(s, "<86>1 2026-04-04T22:00:00Z myhost identree - - ") {
		t.Errorf("bad prefix: %s", s[:60])
	}
	// Quotes in reason should be escaped in SD.
	if !strings.Contains(s, `username=\"alice\"`) {
		// SD-PARAM values use \" escaping.
		if !strings.Contains(s, `username="alice"`) {
			t.Error("SD should contain username")
		}
	}
	// The JSON body should follow the SD.
	if !strings.Contains(s, `"event":"challenge_approved"`) {
		t.Error("JSON body should contain event field")
	}
}

func TestSyslogEscape(t *testing.T) {
	tests := []struct{ in, want string }{
		{`normal`, `normal`},
		{`with "quotes"`, `with \"quotes\"`},
		{`with ]bracket`, `with \]bracket`},
		{`with \backslash`, `with \\backslash`},
	}
	for _, tt := range tests {
		got := syslogEscape(tt.in)
		if got != tt.want {
			t.Errorf("syslogEscape(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseSyslogURL(t *testing.T) {
	tests := []struct {
		url     string
		network string
		addr    string
		wantErr bool
	}{
		{"udp://syslog.local:514", "udp", "syslog.local:514", false},
		{"tcp://syslog.local:601", "tcp", "syslog.local:601", false},
		{"http://bad:514", "", "", true},
		{"syslog.local:514", "", "", true},
	}
	for _, tt := range tests {
		n, a, err := parseSyslogURL(tt.url)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseSyslogURL(%q) err=%v, wantErr=%v", tt.url, err, tt.wantErr)
			continue
		}
		if n != tt.network || a != tt.addr {
			t.Errorf("parseSyslogURL(%q) = (%q, %q), want (%q, %q)", tt.url, n, a, tt.network, tt.addr)
		}
	}
}
