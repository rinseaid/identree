package server

import (
	"fmt"
	"net/http"
	"time"
)

// sseAdminKey is the SSE channel key for admin subscribers.
// The NUL byte prefix cannot appear in valid usernames, preventing collision.
const sseAdminKey = "\x00admin"

func (s *Server) registerSSE(username string) chan string {
	ch := make(chan string, 16)
	s.sseMu.Lock()
	s.sseClients[username] = append(s.sseClients[username], ch)
	s.sseMu.Unlock()
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
func (s *Server) broadcastSSE(username, event string) {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	for _, ch := range s.sseClients[username] {
		select {
		case ch <- event:
		default:
		}
	}
	for _, ch := range s.sseClients[sseAdminKey] {
		select {
		case ch <- event:
		default:
		}
	}
}

// handleSSEEvents streams server-sent events for live dashboard updates.
// GET /api/events
func (s *Server) handleSSEEvents(w http.ResponseWriter, r *http.Request) {
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

	sseKey := username
	if s.getSessionRole(r) == "admin" {
		sseKey = sseAdminKey
	}
	ch := s.registerSSE(sseKey)
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
