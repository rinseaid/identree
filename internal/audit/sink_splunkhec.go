package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// SplunkHECSink sends events to a Splunk HTTP Event Collector endpoint.
// Events are batched (up to batchMax or flushInterval) to reduce HTTP overhead.
type SplunkHECSink struct {
	mu     sync.Mutex
	url    string
	token  string
	client *http.Client
	buf    []splunkEvent
	stopCh chan struct{}
	wg     sync.WaitGroup
}

type splunkEvent struct {
	Event      Event  `json:"event"`
	Sourcetype string `json:"sourcetype"`
	Source     string `json:"source"`
	Time       string `json:"time,omitempty"` // epoch string; omit to let Splunk use receipt time
}

const (
	splunkBatchMax     = 100
	splunkFlushInterval = 5 * time.Second
)

// NewSplunkHECSink creates a sink that POSTs to url with the given HEC token.
func NewSplunkHECSink(url, token string) *SplunkHECSink {
	s := &SplunkHECSink{
		url:   url,
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

func (s *SplunkHECSink) Name() string { return "splunk_hec" }

func (s *SplunkHECSink) Emit(e Event) error {
	se := splunkEvent{
		Event:      e,
		Sourcetype: "identree:audit",
		Source:     "identree",
	}

	s.mu.Lock()
	s.buf = append(s.buf, se)
	shouldFlush := len(s.buf) >= splunkBatchMax
	s.mu.Unlock()

	if shouldFlush {
		s.flush()
	}
	return nil
}

func (s *SplunkHECSink) Close() error {
	close(s.stopCh)
	s.wg.Wait()
	s.flush() // final drain
	return nil
}

func (s *SplunkHECSink) flushLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(splunkFlushInterval)
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

func (s *SplunkHECSink) flush() {
	s.mu.Lock()
	batch := s.buf
	s.buf = nil
	s.mu.Unlock()

	if len(batch) == 0 {
		return
	}

	// Splunk HEC accepts multiple JSON objects concatenated (no array wrapper).
	var body bytes.Buffer
	var dropped int
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(false)
	for _, e := range batch {
		if err := enc.Encode(e); err != nil {
			dropped++
			slog.Warn("AUDIT splunk_hec: encode event failed, dropping", "err", err, "event", e.Event.Event)
		}
	}
	if dropped > 0 {
		slog.Warn("AUDIT splunk_hec: dropped events in batch", "dropped", dropped, "total", len(batch))
	}

	payload := body.Bytes()

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * 500 * time.Millisecond
			slog.Warn("AUDIT splunk_hec: retrying", "attempt", attempt+1, "backoff", backoff, "events", len(batch))
			time.Sleep(backoff)
		}

		req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(payload))
		if err != nil {
			slog.Error("AUDIT splunk_hec: build request", "err", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Splunk "+s.token)

		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("POST failed: %w", err)
			continue // network error, retry
		}

		if resp.StatusCode < 400 {
			resp.Body.Close()
			return // success
		}

		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()

		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
			continue // transient error, retry
		}

		// 4xx (except 429): permanent error, do not retry
		slog.Error("AUDIT splunk_hec: permanent HTTP error", "status", resp.StatusCode, "body", string(respBody), "events", len(batch))
		return
	}
	if lastErr != nil {
		slog.Error("AUDIT splunk_hec: all retries exhausted", "err", lastErr, "events", len(batch))
	}
}
