// Package adminnotify manages per-admin notification preferences.
//
// Each admin can subscribe to specific notification channels for events
// matching their configured filters (event types, hostnames). Preferences
// are persisted as a JSON array file with atomic writes.
package adminnotify

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/rinseaid/identree/internal/notify"
)

// Preference describes one admin's notification subscription.
type Preference struct {
	Username string   `json:"username"` // OIDC username
	Channels []string `json:"channels"` // channel names from notification config
	Events   []string `json:"events"`   // event globs; ["*"] = everything
	Hosts    []string `json:"hosts"`    // hostname globs; empty = all
	Enabled  bool     `json:"enabled"`  // toggle without deleting
}

// maxPreferences prevents unbounded growth.
const maxPreferences = 500

// Store persists admin notification preferences to a JSON file.
// Safe for concurrent use.
type Store struct {
	mu    sync.RWMutex
	path  string
	prefs []Preference
}

// NewStore loads (or creates) a store at path.
// Returns an empty store without error if the file does not exist.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path, prefs: []Preference{}}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("adminnotify: open %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("adminnotify: stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("adminnotify: %s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("adminnotify: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &s.prefs); err != nil {
		return nil, fmt.Errorf("adminnotify: parse %s: %w", path, err)
	}
	if s.prefs == nil {
		s.prefs = []Preference{}
	}
	return s, nil
}

// All returns a copy of all preferences.
func (s *Store) All() []Preference {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Preference, len(s.prefs))
	copy(out, s.prefs)
	return out
}

// Get returns the preference for a specific admin, or nil if not found.
func (s *Store) Get(username string) *Preference {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.prefs {
		if p.Username == username {
			cp := p
			return &cp
		}
	}
	return nil
}

// Set creates or updates the preference for an admin.
func (s *Store) Set(pref Preference) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	for i, p := range s.prefs {
		if p.Username == pref.Username {
			s.prefs[i] = pref
			found = true
			break
		}
	}
	if !found {
		if len(s.prefs) >= maxPreferences {
			return fmt.Errorf("adminnotify: maximum preferences (%d) reached", maxPreferences)
		}
		s.prefs = append(s.prefs, pref)
	}
	return s.saveLocked()
}

// Delete removes the preference for an admin.
func (s *Store) Delete(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, p := range s.prefs {
		if p.Username == username {
			s.prefs = append(s.prefs[:i], s.prefs[i+1:]...)
			return s.saveLocked()
		}
	}
	return nil // not found = no-op
}

// MatchingChannels returns the set of channel names that should receive a
// notification based on all enabled admin preferences.
func (s *Store) MatchingChannels(event, hostname, username string) map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	channels := make(map[string]bool)
	for _, p := range s.prefs {
		if !p.Enabled {
			continue
		}
		if !notify.MatchesGlob(event, p.Events) {
			continue
		}
		if !notify.MatchesGlob(hostname, p.Hosts) {
			continue
		}
		// Admin preferences match all users (the admin is subscribing to
		// notifications about other users' activity).
		for _, ch := range p.Channels {
			channels[ch] = true
		}
	}
	return channels
}

func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s.prefs, "", "  ")
	if err != nil {
		return fmt.Errorf("adminnotify: marshal: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("adminnotify: create dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".admin-notify-*.json")
	if err != nil {
		return fmt.Errorf("adminnotify: create temp: %w", err)
	}
	tmpName := tmp.Name()
	if err := func() error {
		defer tmp.Close()
		if err := tmp.Chmod(0600); err != nil {
			return err
		}
		if _, err := tmp.Write(data); err != nil {
			return err
		}
		return tmp.Sync()
	}(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
