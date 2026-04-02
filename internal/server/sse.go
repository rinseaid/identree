package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// sseAdminKey is the SSE channel key for admin subscribers.
// The NUL byte prefix cannot appear in valid usernames, preventing collision.
const sseAdminKey = "\x00admin"

// sseNewlineReplacer strips CR and LF from SSE event strings to prevent
// SSE protocol injection. Defined at package level to avoid allocating a
// new Replacer on every broadcastSSE call.
var sseNewlineReplacer = strings.NewReplacer("\n", "", "\r", "")

// maxSSEPerUser caps the number of concurrent SSE connections per user/key
// to prevent memory exhaustion from a single client opening many connections.
const maxSSEPerUser = 10

// maxSSETotal caps the server-wide number of concurrent SSE connections.
const maxSSETotal = 500

// registerSSE allocates a new SSE channel for the given key (username or sseAdminKey).
// Returns nil if the per-user or server-wide limit is exceeded.
func (s *Server) registerSSE(username string) chan string {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	// Enforce per-user limit.
	if len(s.sseClients[username]) >= maxSSEPerUser {
		return nil
	}
	// Enforce server-wide limit.
	total := 0
	for _, chans := range s.sseClients {
		total += len(chans)
	}
	if total >= maxSSETotal {
		return nil
	}
	ch := make(chan string, 64)
	s.sseClients[username] = append(s.sseClients[username], ch)
	return ch
}

func (s *Server) unregisterSSE(username string, ch chan string) {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	clients := s.sseClients[username]
	for i, c := range clients {
		if c == ch {
			s.sseClients[username] = append(clients[:i], clients[i+1:]...)
			break
		}
	}
	if len(s.sseClients[username]) == 0 {
		delete(s.sseClients, username)
	}
}

// broadcastSSE sends an event to all SSE channels for username and to admin subscribers.
// Newlines are stripped from event to prevent SSE protocol injection.
func (s *Server) broadcastSSE(username, event string) {
	event = sseNewlineReplacer.Replace(event)
	// Copy channel slices under the lock (fast), then release before sending
	// to avoid holding the mutex while blocked on channel sends.
	s.sseMu.RLock()
	userChans := append([]chan string{}, s.sseClients[username]...)
	adminChans := append([]chan string{}, s.sseClients[sseAdminKey]...)
	s.sseMu.RUnlock()

	for _, ch := range userChans {
		select {
		case ch <- event:
		default:
			slog.Debug("SSE: event dropped, channel full", "username", username, "event", event)
		}
	}
	for _, ch := range adminChans {
		select {
		case ch <- event:
		default:
			slog.Debug("SSE: event dropped, admin channel full", "event", event)
		}
	}
}

// handleSSEEvents streams server-sent events for live dashboard updates.
// GET /api/events
func (s *Server) handleSSEEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := s.getSessionUser(r)
	if username == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Clear the server-level WriteTimeout for this streaming connection so it
	// can remain open indefinitely. All other handlers retain the 60s deadline.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	sseKey := username
	if s.getSessionRole(r) == "admin" {
		sseKey = sseAdminKey
	}
	ch := s.registerSSE(sseKey)
	if ch == nil {
		http.Error(w, "too many connections", http.StatusTooManyRequests)
		return
	}
	defer s.unregisterSSE(sseKey, ch)

	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case event := <-ch:
			fmt.Fprintf(w, "event: update\ndata: %s\n\n", event)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
