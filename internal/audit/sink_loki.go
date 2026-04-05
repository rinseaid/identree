package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LokiSink pushes events to a Grafana Loki instance via the HTTP push API.
// Events are batched to reduce HTTP overhead.
type LokiSink struct {
	mu     sync.Mutex
	url    string // base URL, e.g. "http://loki:3100"
	token  string // optional bearer token
	client *http.Client
	buf    []lokiEntry
	stopCh chan struct{}
	wg     sync.WaitGroup
}

type lokiEntry struct {
	ts    time.Time
	line  string
	event string // for labels
}

const (
	lokiBatchMax      = 100
	lokiFlushInterval = 5 * time.Second
)

// NewLokiSink creates a sink that pushes to url (e.g. "http://loki:3100").
// token is an optional bearer token for authentication.
func NewLokiSink(url, token string) *LokiSink {
	s := &LokiSink{
		url:   strings.TrimRight(url, "/"),
		token: token,
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				Proxy:             nil,
				DialContext:       (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
				DisableKeepAlives: false,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		stopCh: make(chan struct{}),
	}
	s.wg.Add(1)
	go s.flushLoop()
	return s
}

func (s *LokiSink) Name() string { return "loki" }

func (s *LokiSink) Emit(e Event) error {
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("loki marshal: %w", err)
	}

	s.mu.Lock()
	s.buf = append(s.buf, lokiEntry{
		ts:    time.Now(),
		line:  string(line),
		event: e.Event,
	})
	shouldFlush := len(s.buf) >= lokiBatchMax
	s.mu.Unlock()

	if shouldFlush {
		s.flush()
	}
	return nil
}

func (s *LokiSink) Close() error {
	close(s.stopCh)
	s.wg.Wait()
	s.flush() // final drain
	return nil
}

func (s *LokiSink) flushLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(lokiFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.flush()
		case <-s.stopCh:
			return
		}
	}
}

// lokiPushPayload matches the Loki push API format.
type lokiPushPayload struct {
	Streams []lokiStream `json:"streams"`
}

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"` // [[nanosecond_timestamp, line], ...]
}

func (s *LokiSink) flush() {
	s.mu.Lock()
	batch := s.buf
	s.buf = nil
	s.mu.Unlock()

	if len(batch) == 0 {
		return
	}

	// Group entries into a single stream with static labels.
	values := make([][]string, len(batch))
	for i, entry := range batch {
		values[i] = []string{
			strconv.FormatInt(entry.ts.UnixNano(), 10),
			entry.line,
		}
	}

	payload := lokiPushPayload{
		Streams: []lokiStream{{
			Stream: map[string]string{
				"app": "identree",
				"job": "identree-audit",
			},
			Values: values,
		}},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("AUDIT loki: marshal payload", "err", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, s.url+"/loki/api/v1/push", bytes.NewReader(body))
	if err != nil {
		slog.Error("AUDIT loki: build request", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		slog.Error("AUDIT loki: POST failed", "err", err, "events", len(batch))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		slog.Error("AUDIT loki: HTTP error", "status", resp.StatusCode, "body", string(respBody), "events", len(batch))
	}
}
