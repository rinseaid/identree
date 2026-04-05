// Package audit provides a non-blocking, fan-out event streamer for
// delivering structured audit events to external SIEM / log aggregation
// systems (Splunk, Loki, syslog, etc.).
//
// Multiple Sinks can be active simultaneously. Events are dispatched via
// a buffered channel; if the buffer is full the event is dropped and a
// Prometheus counter is incremented.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Event is the canonical structured audit record emitted to all sinks.
type Event struct {
	Seq        uint64 `json:"seq"`                    // monotonically increasing sequence number
	PrevHash   string `json:"prev_hash,omitempty"`    // hex SHA-256 of previous event's JSON
	Timestamp  string `json:"timestamp"`              // RFC 3339
	Event      string `json:"event"`                  // action constant (e.g. "challenge_approved")
	Username   string `json:"username"`
	Hostname   string `json:"hostname,omitempty"`
	Code       string `json:"code,omitempty"`         // user-visible challenge code
	Actor      string `json:"actor,omitempty"`         // who performed the action (empty if self)
	Reason     string `json:"reason,omitempty"`        // justification
	RemoteAddr string `json:"remote_addr,omitempty"`   // client IP
	Source     string `json:"source"`                  // always "identree"
	Version    string `json:"version"`                 // build version
}

// Sink is the interface implemented by each output backend.
type Sink interface {
	// Name returns a short label used in metrics and logs (e.g. "jsonlog", "syslog").
	Name() string
	// Emit delivers a single event. Implementations must be safe for concurrent
	// use and should return quickly (buffer internally if needed).
	Emit(Event) error
	// Close flushes any buffered data and releases resources.
	Close() error
}

// Prometheus metrics.
var (
	eventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "identree",
		Name:      "audit_events_total",
		Help:      "Total audit events by sink and outcome.",
	}, []string{"sink", "status"}) // emitted, dropped, failed
)

func init() {
	// Pre-populate label series so they appear as zero rather than absent.
	for _, status := range []string{"emitted", "dropped", "failed"} {
		eventsTotal.WithLabelValues("_channel", status)
	}
}

const defaultBufferSize = 4096

// Streamer fans out audit events to registered sinks via a buffered channel.
type Streamer struct {
	ch       chan Event
	sinks    []Sink
	wg       sync.WaitGroup
	seq      uint64     // monotonically increasing counter
	prevHash string     // hex SHA-256 of last emitted event
	hashMu   sync.Mutex // protects seq and prevHash
}

// NewStreamer creates a Streamer with the given sinks and buffer size.
// A bufferSize ≤ 0 uses the default (4096).
func NewStreamer(sinks []Sink, bufferSize int) *Streamer {
	if bufferSize <= 0 {
		bufferSize = defaultBufferSize
	}
	s := &Streamer{
		ch:    make(chan Event, bufferSize),
		sinks: sinks,
	}
	// Pre-populate per-sink metric series.
	for _, sink := range sinks {
		for _, status := range []string{"emitted", "dropped", "failed"} {
			eventsTotal.WithLabelValues(sink.Name(), status)
		}
	}
	s.wg.Add(1)
	go s.dispatch()
	return s
}

// Emit enqueues an event. Non-blocking: if the buffer is full the event is
// dropped and the drop counter is incremented.
//
// Before enqueuing, the event is stamped with a monotonically increasing
// sequence number and the SHA-256 hash of the previous event's JSON,
// forming a hash chain for tamper detection (SOC 2 CC7.2).
func (s *Streamer) Emit(e Event) {
	s.hashMu.Lock()
	e.Seq = s.seq
	s.seq++
	e.PrevHash = s.prevHash
	if b, err := json.Marshal(e); err == nil {
		h := sha256.Sum256(b)
		s.prevHash = hex.EncodeToString(h[:])
	}
	s.hashMu.Unlock()

	select {
	case s.ch <- e:
	default:
		eventsTotal.WithLabelValues("_channel", "dropped").Inc()
		slog.Warn("AUDIT event dropped (buffer full)", "event", e.Event, "user", e.Username)
	}
}

// Close signals the dispatch goroutine to drain remaining events and shut down.
// It blocks until all sinks have been closed.
func (s *Streamer) Close() {
	close(s.ch)
	s.wg.Wait()
}

// dispatch reads from the channel and fans out to every sink.
func (s *Streamer) dispatch() {
	defer s.wg.Done()
	for e := range s.ch {
		for _, sink := range s.sinks {
			if err := sink.Emit(e); err != nil {
				eventsTotal.WithLabelValues(sink.Name(), "failed").Inc()
				slog.Error("AUDIT sink error", "sink", sink.Name(), "event", e.Event, "err", err)
			} else {
				eventsTotal.WithLabelValues(sink.Name(), "emitted").Inc()
			}
		}
	}
	// Channel closed — flush all sinks.
	for _, sink := range s.sinks {
		if err := sink.Close(); err != nil {
			slog.Error("AUDIT sink close error", "sink", sink.Name(), "err", err)
		}
	}
}

// NewEvent is a convenience constructor that stamps the current time.
func NewEvent(event, username, hostname, code, actor, reason, remoteAddr, version string) Event {
	return Event{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Event:      event,
		Username:   username,
		Hostname:   hostname,
		Code:       code,
		Actor:      actor,
		Reason:     reason,
		RemoteAddr: remoteAddr,
		Source:     "identree",
		Version:    version,
	}
}
